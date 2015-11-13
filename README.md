# memsnoop

LD_PRELOADable library for snooping on malloc and friends.

[![Build Status](https://travis-ci.org/minutils/memsnoop.svg?branch=master)](https://travis-ci.org/minutils/memsnoop)

```
cmake .
make
LD_PRELOAD=./libmemsnoop.so ls
```

Based on https://github.com/jtolds/malloc_instrumentation
