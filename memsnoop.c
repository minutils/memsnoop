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

//=============================================================================
// increase this to track more allocations
//=============================================================================

#define MAX_ALLOCS 1024*1024


//=============================================================================
// typedefs
//=============================================================================

typedef void* (*malloc_t)(size_t size);
typedef void* (*calloc_t)(size_t nmemb, size_t size);
typedef void* (*realloc_t)(void *ptr, size_t size);
typedef void* (*memalign_t)(size_t blocksize, size_t bytes);
typedef void* (*valloc_t)(size_t size);
typedef int   (*posix_memalign_t)(void** memptr, size_t alignment, size_t size);
typedef void  (*free_t)(void *ptr);

typedef enum {
    NOT_INITIALIZED,
    INITIALIZING,
    INITIALIZED
} status;

typedef struct allocation {
    void*  ptr;
    size_t size;
} allocation;


//=============================================================================
// static variables
//=============================================================================

static status initialized = NOT_INITIALIZED;

static malloc_t         real_malloc;
static calloc_t         real_calloc;
static realloc_t        real_realloc;
static memalign_t       real_memalign;
static valloc_t         real_valloc;
static posix_memalign_t real_posix_memalign;
static free_t           real_free;

static allocation allocations[MAX_ALLOCS];

static uint8_t* a1_page;

static unsigned long total_size = 0;
static unsigned long total_allocs = 0;

static int config_print = 1;
static int config_abort = 1;
static int config_track = 1;
static int config_check = 0;
static int config_mmap = 0;

static int pagesize = 0;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


//=============================================================================
// static prototypes
//=============================================================================

static void lock();
static void unlock();

static void info(char* format, ...)  __attribute__((format(printf, 1, 2)));
static void warn(char* format, ...)  __attribute__((format(printf, 1, 2))) __attribute__ ((unused));
static void error(char* format, ...) __attribute__((format(printf, 1, 2)));
static void fatal(char* format, ...) __attribute__((format(printf, 1, 2)));
static void vprint(char* format, va_list args);

static unsigned hash(void* ptr);
static int lookup(void* ptr);
static int slot(void* ptr);

static void save_allocation(void* ptr, size_t size);
static void clear_allocation(void* ptr);
static void clear_allocations();

static void initialize();

static size_t fullsize(size_t size);
static allocation map_pages(size_t size, size_t alignment);
static void safe_munmap(void* addr, size_t len);
static void unmap_allocation(int a);


//=============================================================================
// prototypes of functions to be wrapped
//=============================================================================

void* malloc(size_t size);
void free(void *ptr);
void* calloc(size_t n, size_t size);
void* realloc(void *ptr, size_t size);
void* valloc(size_t size);
void* memalign(size_t alignment, size_t size);
int posix_memalign(void** memptr, size_t alignment, size_t size);


//=============================================================================
// locking system
//=============================================================================

void lock()
{
    pthread_mutex_lock(&mutex);
}

void unlock()
{
    pthread_mutex_unlock(&mutex);
}


//=============================================================================
// logging system
//=============================================================================

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


//=============================================================================
// hashtable
//=============================================================================

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


//=============================================================================
// tracking
//=============================================================================

void save_allocation(void* ptr, size_t size)
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


//=============================================================================
// initialization
//=============================================================================

void initialize()
{
    initialized = INITIALIZING;

    pagesize = getpagesize();

    clear_allocations();

    if(getenv("MEMSNOOP_NO_PRINT")) config_print = 0;
    if(getenv("MEMSNOOP_NO_TRACK")) config_track = 0;
    if(getenv("MEMSNOOP_NO_ABORT")) config_abort = 0;
    if(getenv("MEMSNOOP_MMAP"))     config_mmap  = 1;
    if(getenv("MEMSNOOP_CHECK"))    config_check = 1;

    if(!config_track && config_mmap) {
        fatal("MEMSNOOP_MMAP and MEMSNOOP_NO_TRACK cannot both be set");
    }

    if(config_check && !config_mmap) {
        fatal("MEMSNOOP_CHECK requires MEMSNOOP_MMAP");
    }

    if(config_check) {
        a1_page = mmap(0, pagesize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if(!a1_page) fatal("mmap failed: %s", strerror(errno));
        memset(a1_page, 0xA1, pagesize);
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


//=============================================================================
// mmap
//=============================================================================

size_t fullsize(size_t size)
{
    int pages = size / pagesize;
    if(pages*pagesize < size) pages++;
    pages++;
    return pages*pagesize;
}

void safe_munmap(void* addr, size_t len)
{
    if(munmap(addr, len) == -1) {
        fatal("munmap(%p, %zu) failed: %s", addr, len, strerror(errno));
    }
}

void unmap_allocation(int a)
{
    uint8_t* ptr = allocations[a].ptr;
    int size = allocations[a].size;

    if(config_check) {
        if(memcmp(ptr+size, a1_page, fullsize(size) - size - pagesize) != 0) {
            for(int i=size; i<fullsize(size) - pagesize; i++) {
                uint8_t* p = ptr;
                p += i;
                if(*p != 0xA1) {
                    error("overrun detected in %p at position %d (size was %d)", ptr, i, size);
                }
            }
        }
    }

    safe_munmap(ptr, fullsize(size));
}

allocation map_pages(size_t size, size_t alignment)
{
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

    if(config_check) {
        memset(ptr+size, 0xA1, fullsize(size) - pagesize - size);
    }

    allocation result;
    result.ptr = ptr;
    result.size = size;

    return result;
}


//=============================================================================
// wrappers
//=============================================================================

void* malloc(size_t size)
{
    if(!initialized) initialize();

    lock();

    void* result;

    if(config_mmap || initialized == INITIALIZING) {
        allocation a = map_pages(size, 0);
        result = a.ptr;
        save_allocation(a.ptr, size);
    } else {
        result = real_malloc(size);
        save_allocation(result, size);
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

    if(config_mmap || initialized == INITIALIZING)
        unmap_allocation(lookup(ptr));
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
        save_allocation(a.ptr, n*size);
    } else {
        result = real_calloc(n, size);
        save_allocation(result, n*size);
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

    if(config_mmap) {
        allocation a = map_pages(size, 0);
        result = a.ptr;

        if(ptr) {
            int oldsize = allocations[lookup(ptr)].size;
            int newsize = size;
            int minsize = oldsize < newsize ? oldsize : newsize;
            memcpy(result, ptr, minsize);
            unmap_allocation(lookup(ptr));
        }
    } else {
        result = real_realloc(ptr, size);
    }

    if(ptr) {
        clear_allocation(ptr);

        info("realloc_free(%p) [%lu/%lu]", ptr, total_size, total_allocs);
    }

    save_allocation(result, size);

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
        save_allocation(a.ptr, size);
    } else {
        result = real_valloc(size);
        save_allocation(result, size);
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
        save_allocation(a.ptr, size);
    } else {
        result = real_memalign(alignment, size);
        save_allocation(result, size);
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
        save_allocation(a.ptr, size);
    } else {
        result = real_posix_memalign(memptr, alignment, size);
        save_allocation(*memptr, size);
    }

    info("posix_memalign(%zu) = %p [%lu/%lu]", size, *memptr, total_size, total_allocs);

    unlock();

    return result;
}
