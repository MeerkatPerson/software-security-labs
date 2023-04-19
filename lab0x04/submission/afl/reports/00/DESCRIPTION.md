
# BUG 00

### Name

Invalid free due to not setting pointer(s) to `NULL` after freeing

### Description

`current_chunk->chunk_data` is not initialized to zero, but also, `pngparser.c` does not follow the good practice of setting pointer to `NULL` after freeing.

Note: this bug is not just the bug described in the `libfuzzer` section of the `README` as fixing that one doesn't resolve this one - we also have to set `current_chunk->chunk_data` to `NULL` after freeing, in particular in the `error` case of `read_png_chunk`.

### Expected vs Observed

We expect that `free` is not called on `NULL` pointers. However, apparently such `free` calls on `NULL` pointers do occur in the original program.

### Affected Lines

`pngparser.c:701`, `pngparser.c:266`

### Suggested Fix Description

Suggested fix: initialize `current_chunk->chunk_data` to `NULL`, and set ALL pointers to `NULL` after freeing (in particular `current_chunk->chunk_data` in the `error` case of `read_png_chunk` to fix this specific bug), because OCD.

Also, after fixing this bug, `poc.bin` still produces some memory leaks. Those can partly be fixed by also freeing `plte_chunk->chunk_data` and `ihdr_chunk->chunk_data` in the `success` and `error` cases of `load_png`.

### Steps to Reproduce

##### Command

```
./size poc.bin
```
##### Proof-of-Concept Input (if needed)
(attached: poc.png)
