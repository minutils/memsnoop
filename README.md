# memsnoop

A LD_PRELOADable library for snooping on malloc and friends.

```
cmake .
make
LD_PRELOAD=./libmemsnoop.so ls
```

Based on https://github.com/jtolds/malloc_instrumentation
