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

typedef enum {
    NOT_INITIALIZED,
    INITIALIZING,
    INITIALIZED
} status;

static status initialized = NOT_INITIALIZED;

typedef struct allocation {
    void*  ptr;
    size_t size;
    size_t fullsize;
    type   type;
} allocation;

static malloc_t         real_malloc;
static calloc_t         real_calloc;
static realloc_t        real_realloc;
static memalign_t       real_memalign;
static valloc_t         real_valloc;
static posix_memalign_t real_posix_memalign;
static free_t           real_free;

#define MAX_ALLOCS 1024*1024

static allocation allocations[MAX_ALLOCS];

static unsigned long total_size = 0;
static unsigned long total_allocs = 0;

static int config_print = 1;
static int config_abort = 1;
static int config_track = 1;
static int config_mmap = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void lock()
{
    pthread_mutex_lock(&mutex);
}

void unlock()
{
    pthread_mutex_unlock(&mutex);
}

void info(char* format, ...)  __attribute__((format(printf, 1, 2)));
void warn(char* format, ...)  __attribute__((format(printf, 1, 2)));
void error(char* format, ...) __attribute__((format(printf, 1, 2)));
void fatal(char* format, ...) __attribute__((format(printf, 1, 2)));

void vprint(char* format, va_list args)
{
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}

#define CALL_VPRINT \
    do { \
        va_list(args); \
        va_start(args, format); \
        vprint(format, args); \
        va_end(args); \
    } while(0);

void info(char* format, ...)
{
    if(config_print) CALL_VPRINT
}

void warn(char* format, ...)
{
    CALL_VPRINT
}

void error(char* format, ...)
{
    CALL_VPRINT
    if(config_abort) abort();
}

void fatal(char* format, ...)
{
    CALL_VPRINT
    abort();
}

#undef CALL_VPRINT

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

    for(int j=0; j<MAX_ALLOCS; j++) {
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

    for(int j=0; j<MAX_ALLOCS; j++) {
        if(!allocations[i].ptr) return i;

        i++;
        i %= MAX_ALLOCS;
    }

    return -1;
}

void save_allocation(void* ptr, size_t size, size_t fullsize, type type)
{
    if(!config_track) return;

    if(!ptr) {
        fatal("asked to save a null pointer!");
    }

    int i = slot(ptr);

    if(i == -1) {
        fatal("too many allocs, increase MAX_ALLOCS");
    }

    allocations[i].ptr = ptr;
    allocations[i].size = size;
    allocations[i].fullsize = fullsize;
    allocations[i].type = type;

    total_size += size;
    total_allocs++;
}

void clear_allocation(void* ptr)
{
    if(!config_track) return;
    int i = lookup(ptr);

    if(i == -1) {
        error("bad free %p", ptr);
        return;
    }

    int j = i;
    for(;;) {
        j++;
        j %= MAX_ALLOCS;
        if(!allocations[j].ptr) break;
        int k = hash(allocations[j].ptr);
        if((j > i && (k <= i || k > j)) || (j < i && (k <= i && k > j))) {
            allocations[i] = allocations[j];
            i = j;
        }
    }

    total_size -= allocations[i].size;
    total_allocs--;

    allocations[i].ptr = NULL;
}

void clear_allocations()
{
    for(int i=0; i<MAX_ALLOCS; i++) {
        allocations[i].ptr = NULL;
    }
}

void initialize()
{
    initialized = INITIALIZING;

    if(getenv("MEMSNOOP_NO_PRINT")) config_print = 0;
    if(getenv("MEMSNOOP_NO_TRACK")) config_track = 0;
    if(getenv("MEMSNOOP_NO_ABORT")) config_abort = 0;
    if(getenv("MEMSNOOP_MMAP"))     config_mmap  = 1;

    if(!config_track && config_mmap) {
        fatal("MEMSNOOP_MMAP and MEMSNOOP_NO_TRACK cannot both be set");
    }

    real_malloc         = dlsym(RTLD_NEXT, "malloc");
    real_calloc         = dlsym(RTLD_NEXT, "calloc");
    real_realloc        = dlsym(RTLD_NEXT, "realloc");
    real_free           = dlsym(RTLD_NEXT, "free");
    real_memalign       = dlsym(RTLD_NEXT, "memalign");
    real_valloc         = dlsym(RTLD_NEXT, "valloc");
    real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");

    if (!real_malloc || !real_calloc || !real_realloc || !real_memalign ||
        !real_valloc || !real_posix_memalign || !real_free) {
        fatal("Error in `dlsym`: %s", dlerror());
    }

    initialized = INITIALIZED;
}

void safe_munmap(void* addr, size_t len)
{
    if(munmap(addr, len) == -1) {
        fatal("munmap(%p, %zu) failed: %s", addr, len, strerror(errno));
    }
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
        fatal("mmap failed! %s", strerror(errno));
    }

    if(pagealign) {
        int adjust = 0;
        while(((uintptr_t)ptr / pagesize) % pagealign != 0) {
            safe_munmap(ptr, pagesize);
            ptr += pagesize;
            adjust++;
        }

        pagealign -= adjust;

        if(pagealign) {
            safe_munmap(ptr + pagesize*(pages-pagealign), pagesize*pagealign);
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

void* malloc(size_t size)
{
    if(!initialized) initialize();

    lock();

    void* result;

    if(config_mmap || initialized == INITIALIZING) {
        allocation a = map_pages(size, 0);
        result = a.ptr;
        save_allocation(a.ptr, size, a.fullsize, MMAP);
    } else {
        result = real_malloc(size);
        save_allocation(result, size, 0, NATIVE);
    }

    info("malloc(%zu) = %p [%lu/%lu]", size, result, total_size, total_allocs);

    unlock();

    return result;
}

void free(void *ptr)
{
    if(!initialized) initialize();

    if(!ptr) return;

    lock();

    if(config_track && lookup(ptr) == -1) {
        error("bad free %p", ptr);
    }

    if(config_mmap || (config_track && allocations[lookup(ptr)].type == MMAP) || initialized == INITIALIZING)
        safe_munmap(ptr, allocations[lookup(ptr)].fullsize);
    else
        real_free(ptr);

    clear_allocation(ptr);

    info("free(%p) [%lu/%lu]", ptr, total_size, total_allocs);

    unlock();
}

void* calloc(size_t n, size_t size)
{
    if(!initialized) initialize();

    lock();

    void* result;

    if(config_mmap || initialized == INITIALIZING) {
        allocation a = map_pages(n*size, 0);
        result = a.ptr;
        save_allocation(a.ptr, n*size, a.fullsize, MMAP);
    } else {
        result = real_calloc(n, size);
        save_allocation(result, n*size, 0, NATIVE);
    }

    info("calloc(%zu) = %p [%lu/%lu]", n*size, result, total_size, total_allocs);

    unlock();

    return result;
}

void* realloc(void *ptr, size_t size)
{
    if(!initialized) initialize();

    if(initialized == INITIALIZING) {
        fatal("realloc not supported while initializing");
    }

    lock();

    void* result;
    int fullsize = 0;

    if(config_mmap) {
        allocation a = map_pages(size, 0);
        result = a.ptr;
        fullsize = a.fullsize;

        if(ptr) {
            int oldsize = allocations[lookup(ptr)].fullsize - getpagesize();
            int newsize = fullsize - getpagesize();
            int minsize = oldsize < newsize ? oldsize : newsize;
            memcpy(result, ptr, minsize);
            safe_munmap(ptr, allocations[lookup(ptr)].fullsize);
        }
    } else {
        result = real_realloc(ptr, size);
    }

    if(ptr) {
        clear_allocation(ptr);

        info("realloc_free(%p) [%lu/%lu]", ptr, total_size, total_allocs);
    }

    save_allocation(result, size, fullsize, config_mmap ? MMAP : NATIVE);

    info("realloc_malloc(%p, %zu) = %p [%lu/%lu]", ptr, size, result, total_size, total_allocs);

    unlock();

    return result;
}

void* valloc(size_t size)
{
    if(!initialized) initialize();

    lock();

    void* result;

    if(config_mmap || initialized == INITIALIZING) {
        allocation a = map_pages(size, 0);
        result = a.ptr;
        save_allocation(a.ptr, size, a.fullsize, MMAP);
    } else {
        result = real_valloc(size);
        save_allocation(result, size, 0, NATIVE);
    }

    info("valloc(%zu) = %p [%lu/%lu]", size, result, total_size, total_allocs);

    unlock();

    return result;
}

void* memalign(size_t alignment, size_t size)
{
    if(!initialized) initialize();

    lock();

    void* result;

    if(config_mmap || initialized == INITIALIZING) {
        allocation a = map_pages(size, alignment);
        result = a.ptr;
        save_allocation(a.ptr, size, a.fullsize, MMAP);
    } else {
        result = real_memalign(alignment, size);
        save_allocation(result, size, 0, NATIVE);
    }

    info("memalign(%zu) = %p [%lu/%lu]", size, result, total_size, total_allocs);

    unlock();

    return result;
}

int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    if(!initialized) initialize();

    lock();

    int result = 0;

    if(config_mmap || initialized == INITIALIZING) {
        allocation a = map_pages(size, alignment);
        *memptr = a.ptr;
        save_allocation(a.ptr, size, a.fullsize, MMAP);
    } else {
        result = real_posix_memalign(memptr, alignment, size);
        save_allocation(*memptr, size, 0, NATIVE);
    }

    info("posix_memalign(%zu) = %p [%lu/%lu]", size, *memptr, total_size, total_allocs);

    unlock();

    return result;
}
