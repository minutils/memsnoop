# memsnoop

[![Build Status](https://travis-ci.org/minutils/memsnoop.svg?branch=master)](https://travis-ci.org/minutils/memsnoop)

LD_PRELOADable library for snooping on malloc and friends

## Wrapped functions

- `malloc`
- `free`
- `realloc`
- `calloc`
- `valloc`
- `memalign`
- `posix_memalign`

## Building and Basic Usage
```
cmake .
make
LD_PRELOAD=./libmemsnoop.so ls
```

## Output sample
```
malloc(568) = 0x2257010 [568/1]
```
`malloc(568)` was called, returning a pointer to `0x2257010`, there are currently 568 total bytes allocated in 1 allocation.
```
free(0x2257010) [0/0]
```
`free(0x2257010)` was called, freeing that chunk.  Now there are no outstanding allocations.

## Options

export  | result
------------- | -------------
`MEMSNOOP_NO_PRINT`  | Don't print out all allocations.
`MEMSNOOP_NO_TRACK`  | Don't track allocations.  Tracking allocations is expensive but will catch errors like double free or calling realloc with a pointer that was not previously allocated.
`MEMSNOOP_NO_ABORT`  | Don't abort program when memory errors are detected.  Full speed ahead!
`MEMSNOOP_MMAP`      | Use `mmap` instead of native memory allocator.  All allocations will be followed by an extra page that is `mprotect(PROT_NONE)`, so buffer overruns (at least to the next page boundary) and underruns will immediately segfault.  Cannot be used with `MEMSNOOP_NO_TRACK`.

Based on https://github.com/jtolds/malloc_instrumentation
