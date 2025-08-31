TL;DR

Vulnerability

When reading a string from input, getline is given a buffer on the stack. If the provided size is insufficient for the string being read, that buffer is also passed into realloc.

Possible Exploit

1. We control 8 bytes right before the buffer (where the result of eval is stored). Since buffer is passed into realloc, we can control the chunk size that realloc will operate on.
2. If realloc cannot extend the buffer (by merging with the following chunk), it performs malloc + memcpy + free → this allows us to free our stack buffer with a chosen chunk size.
3. If we free a small-sized buffer (e.g., 0x20), it goes into tcache → stack buffer address leak.
4. We can’t directly free our buffer into unsortedbin, because there’s a fatal check that ensures the chunk address lies within the heap (but we’re freeing from the stack). However, glibc has a second path where chunks land in unsortedbin: during malloc_consolidate. We can place our chunk in fastbin and then trigger consolidation by requesting a large string. After consolidation, our chunk ends up in unsortedbin, then immediately in smallbin → libc leak.
5. The first thing __libc_realloc checks is whether the current chunk can simply be reused without any actual reallocation. We can abuse this to force getline to write past the bounds of our stack buffer → stack OOB.
6. Since the buffer lies at the edge of the stack frame, and there’s no real return from main, this stack OOB initially seems useless.
7. With the OOB write, we can overwrite data pointed to by rbp in main. This means that upon entering another function (e.g., readline), the saved rbp on the stack points to our controlled data. We can overwrite that pointer to controlled data using unsafe unlink (a well-known glibc malloc attack). We need to perform unsafe unlink on fake chunk main rbp points to. As a result, after reading a string and performing unsafe unlink, when returning from readline, the corrupted value gets loaded into rbp. This points far below the original stack frame. Since the buffer address for getline is computed relative to rbp, we now get write below main and readline stack frames → ROP via libc.
