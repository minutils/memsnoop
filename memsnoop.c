// based on https://github.com/jtolds/malloc_instrumentation

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdarg.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

typedef void* (*malloc_t)(size_t size);
typedef void* (*calloc_t)(size_t nmemb, size_t size);
typedef void* (*realloc_t)(void *ptr, size_t size);
typedef void* (*memalign_t)(size_t blocksize, size_t bytes);
typedef void* (*valloc_t)(size_t size);
typedef int   (*posix_memalign_t)(void** memptr, size_t alignment, size_t size);
typedef void  (*free_t)(void *ptr);

typedef enum {
    NATIVE,
    MMAP
} type;

typedef struct allocation {
    void*  ptr;
    size_t size;
    size_t fullsize;
    type   type;
} allocation;

static malloc_t         temp_malloc, real_malloc;
static calloc_t         temp_calloc, real_calloc;
static realloc_t        temp_realloc, real_realloc;
static memalign_t       temp_memalign, real_memalign;
static valloc_t         temp_valloc, real_valloc;
static posix_memalign_t temp_posix_memalign, real_posix_memalign;
static free_t           temp_free, real_free;

static char tmpbuf[1024];
static unsigned long tmppos = 0;

#define MAX_ALLOCS 1024*1024

static allocation allocations[MAX_ALLOCS];

static unsigned long total_size = 0;
static unsigned long total_allocs = 0;

static int config_print = 1;
static int config_abort = 1;
static int config_track = 1;
static int config_mmap = 0;

static int initialized = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void lock() {
    pthread_mutex_lock(&mutex);
}

void unlock() {
    pthread_mutex_unlock(&mutex);
}

void* early_malloc(size_t size) {
    if (tmppos + size >= sizeof(tmpbuf)) exit(1);
    void *retptr = tmpbuf + tmppos;
    tmppos += size;
    return retptr;
}

void* early_calloc(size_t nmemb, size_t size) {
    void *ptr = early_malloc(nmemb * size);
    unsigned int i = 0;
    for (; i < nmemb * size; ++i)
        *((char*)(ptr + i)) = '\0';
    return ptr;
}

void early_free(void *ptr) {
    (void)ptr;
}

void error(char* format, ...) {
    va_list(args);
    va_start(args, format);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    if(config_abort) abort();
}

unsigned hash(void* ptr)
{
    //http://web.archive.org/web/20050215204412/http://www.concentric.net/~ttwang/tech/inthash.htm

    uintptr_t hash = (uintptr_t)ptr;

#if UINTPTR_MAX == UINT64_MAX
    hash += ~(hash << 32);
    hash ^=  (hash >> 22);
    hash += ~(hash << 13);
    hash ^=  (hash >> 8);
    hash +=  (hash << 3);
    hash ^=  (hash >> 15);
    hash += ~(hash << 27);
    hash ^=  (hash >> 31);
#else
    hash += ~(hash << 15);
    hash ^=  (hash >> 10);
    hash +=  (hash << 3);
    hash ^=  (hash >> 6);
    hash += ~(hash << 11);
    hash ^=  (hash >> 16);
#endif

    return hash % MAX_ALLOCS;
}

int lookup(void* ptr)
{
    int i = hash(ptr);

    for(int j=0; j<MAX_ALLOCS; j++)
    {
        if(allocations[i].ptr == ptr) return i;
        if(!allocations[i].ptr) return -1;

        i++;
        i %= MAX_ALLOCS;
    }

    return -1;
}

int slot(void* ptr)
{
    int i = hash(ptr);

    for(int j=0; j<MAX_ALLOCS; j++)
    {
        if(!allocations[i].ptr) return i;

        i++;
        i %= MAX_ALLOCS;
    }

    return -1;
}

void save_allocation(void* ptr, size_t size, size_t fullsize, type type) {
    if(!config_track) return;

    if(!ptr) {
        error("asked to save a null pointer!");
        abort();
    }

    int i = slot(ptr);

    if(i == -1)
    {
        error("too many allocs, increase MAX_ALLOCS");
        return;
    }

    allocations[i].ptr = ptr;
    allocations[i].size = size;
    allocations[i].fullsize = fullsize;
    allocations[i].type = type;

    total_size += size;
    total_allocs++;
}

void clear_allocation(void* ptr) {
    if(!config_track) return;
    int i = lookup(ptr);

    if(i == -1)
    {
        error("bad free %p", ptr);
        return;
    }

    int j = i;
    for(;;)
    {
        j++;
        j %= MAX_ALLOCS;
        if(!allocations[j].ptr) break;
        int k = hash(allocations[j].ptr);
        if((j > i && (k <= i || k > j)) || (j < i && (k <= i && k > j)))
        {
            allocations[i] = allocations[j];
            i = j;
        }
    }

    total_size -= allocations[i].size;
    total_allocs--;

    allocations[i].ptr = NULL;
}

void clear_allocations() {
    for(int i=0; i<MAX_ALLOCS; i++)
    {
        allocations[i].ptr = NULL;
    }
}

void initialize() {
    initialized = 1;

    if(getenv("MEMSNOOP_NO_PRINT")) config_print = 0;
    if(getenv("MEMSNOOP_NO_TRACK")) config_track = 0;
    if(getenv("MEMSNOOP_NO_ABORT")) config_abort = 0;
    if(getenv("MEMSNOOP_MMAP"))     config_mmap  = 1;

    real_malloc         = early_malloc;
    real_calloc         = early_calloc;
    real_realloc        = NULL;
    real_free           = early_free;
    real_memalign       = NULL;
    real_valloc         = NULL;
    real_posix_memalign = NULL;

    temp_malloc         = dlsym(RTLD_NEXT, "malloc");
    temp_calloc         = dlsym(RTLD_NEXT, "calloc");
    temp_realloc        = dlsym(RTLD_NEXT, "realloc");
    temp_free           = dlsym(RTLD_NEXT, "free");
    temp_memalign       = dlsym(RTLD_NEXT, "memalign");
    temp_valloc         = dlsym(RTLD_NEXT, "valloc");
    temp_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");

    if (!temp_malloc || !temp_calloc || !temp_realloc || !temp_memalign ||
        !temp_valloc || !temp_posix_memalign || !temp_free)
    {
        fprintf(stderr, "Error in `dlsym`: %s", dlerror());
        abort();
    }

    real_malloc         = temp_malloc;
    real_calloc         = temp_calloc;
    real_realloc        = temp_realloc;
    real_free           = temp_free;
    real_memalign       = temp_memalign;
    real_valloc         = temp_valloc;
    real_posix_memalign = temp_posix_memalign;
}

allocation map_pages(size_t size, size_t alignment)
{
    int pagesize = getpagesize();
    int pages = size / pagesize;
    if(pages*pagesize < size) pages++;
    pages++;

    // some apps need alignment greater that pagesize.  there's no way to ask mmap for this!
    // so we allocate more than we need, and then find within the larger space a properly aligned
    // subsection.  we then munmap the unneeded parts.

    int pagealign = 0;
    if(alignment > pagesize) {
        pagealign = alignment / pagesize;
        pages += pagealign;
    }

    void* ptr = mmap(0, pagesize*(pages + pagealign), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if(ptr == MAP_FAILED) {
        error("map failed! %s", strerror(errno));
    }

    if(pagealign) {
        int adjust = 0;
        while(((uintptr_t)ptr / pagesize) % pagealign != 0) {
            munmap(ptr, pagesize);
            ptr += pagesize;
            adjust++;
        }

        pagealign -= adjust;

        if(pagealign) {
            munmap(ptr + pagesize*(pages-pagealign), pagesize*pagealign);
        }
    }

    mprotect(ptr+(pagesize*(pages-1)), pagesize, PROT_NONE);

    allocation result;
    result.ptr = ptr;
    result.size = size;
    result.fullsize = pagesize*pages;
    result.type = MMAP;

    return result;
}

void* malloc(size_t size) {
    if(!initialized) initialize();

    lock();

    void* result;

    if(config_mmap) {
        allocation a = map_pages(size, 0);
        result = a.ptr;
        save_allocation(a.ptr, size, a.fullsize, MMAP);
    } else {
        result = real_malloc(size);
        save_allocation(result, size, 0, NATIVE);
    }

    if(config_print) fprintf(stderr, "malloc(%zu) = %p [%lu/%lu]\n", size, result, total_size, total_allocs);

    unlock();

    return result;
}

void free(void *ptr) {
    if(!initialized) initialize();

    if(!ptr) return;

    lock();

    if(lookup(ptr) == -1) {
        error("bad free %p", ptr);
    }

    if(allocations[lookup(ptr)].type == NATIVE)
        real_free(ptr);
    else
        munmap(ptr, allocations[lookup(ptr)].fullsize);

    clear_allocation(ptr);

    if(config_print) fprintf(stderr, "free(%p) [%lu/%lu]\n", ptr, total_size, total_allocs);

    unlock();
}

void* calloc(size_t n, size_t size) {
    if(!initialized) initialize();

    lock();

    void* result;

    if(config_mmap) {
        allocation a = map_pages(n*size, 0);
        result = a.ptr;
        save_allocation(a.ptr, n*size, a.fullsize, MMAP);
    } else {
        result = real_calloc(n, size);
        save_allocation(result, n*size, 0, NATIVE);
    }

    if(config_print) fprintf(stderr, "calloc(%zu) = %p [%lu/%lu]\n", n*size, result, total_size, total_allocs);

    unlock();

    return result;
}

void* realloc(void *ptr, size_t size) {
    if(!initialized) initialize();

    lock();

    void* result;
    int location = ptr ? lookup(ptr) : -1;
    type type = location == -1 ? NATIVE : allocations[location].type;
    int fullsize = 0;

    if(type == MMAP)
    {
        allocation a = map_pages(size, 0);
        result = a.ptr;
        fullsize = a.fullsize;

        int oldsize = allocations[lookup(ptr)].fullsize - getpagesize();
        int newsize = fullsize - getpagesize();
        int minsize = oldsize < newsize ? oldsize : newsize;
        memcpy(result, ptr, minsize);
        munmap(ptr, allocations[lookup(ptr)].fullsize);
    }
    else
    {
        result = real_realloc(ptr, size);
    }

    if(ptr) {
        clear_allocation(ptr);

        if(config_print) fprintf(stderr, "realloc_free(%p) [%lu/%lu]\n", ptr, total_size, total_allocs);
    }

    save_allocation(result, size, fullsize, type);

    if(config_print) fprintf(stderr, "realloc_malloc(%p, %zu) = %p [%lu/%lu]\n", ptr, size, result, total_size, total_allocs);

    unlock();

    return result;
}

void* valloc(size_t size) {
    if(!initialized) initialize();

    lock();

    void* result;

    if(config_mmap) {
        allocation a = map_pages(size, 0);
        result = a.ptr;
        save_allocation(a.ptr, size, a.fullsize, MMAP);
    } else {
        result = real_valloc(size);
        save_allocation(result, size, 0, NATIVE);
    }

    if(config_print) fprintf(stderr, "valloc(%zu) = %p [%lu/%lu]\n", size, result, total_size, total_allocs);

    unlock();

    return result;
}

void* memalign(size_t alignment, size_t size) {
    if(!initialized) initialize();

    lock();

    void* result;

    if(config_mmap) {
        allocation a = map_pages(size, alignment);
        result = a.ptr;
        save_allocation(a.ptr, size, a.fullsize, MMAP);
    } else {
        result = real_memalign(alignment, size);
        save_allocation(result, size, 0, NATIVE);
    }

    if(config_print) fprintf(stderr, "memalign(%zu) = %p [%lu/%lu]\n", size, result, total_size, total_allocs);

    unlock();

    return result;
}

int posix_memalign(void** memptr, size_t alignment, size_t size) {
    if(!initialized) initialize();

    lock();

    int result = 0;

    if(config_mmap) {
        allocation a = map_pages(size, alignment);
        *memptr = a.ptr;
        save_allocation(a.ptr, size, a.fullsize, MMAP);
    } else {
        result = real_posix_memalign(memptr, alignment, size);
        save_allocation(*memptr, size, 0, NATIVE);
    }

    if(config_print) fprintf(stderr, "posix_memalign(%zu) = %p [%lu/%lu]\n", size, *memptr, total_size, total_allocs);

    unlock();

    return result;
}
