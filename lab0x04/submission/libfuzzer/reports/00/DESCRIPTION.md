
# BUG 00

### Name

Double free of `current_chunk->chunk_data`

### Description

After fixing the bug described in the `README` by initializing `current_chunk->chunk_data` to `NULL` in `load_png`, we still get an invalid free of `current_chunk->chunk_data` in `load_png`'s error handling.

This is because in `pngparser.c`, pointers are never (? ... or at least almost never)  set to `NULL` after freeing.

### Expected vs Observed

Expected: temporal memory safety is ensured in the program. Observed: program terminates because of temporal memory safety violation!

### Affected Lines

`pngparser.c:701`, `pngparser.c:266`

### Suggested Fix Description

Suggested fix: initialize `current_chunk->chunk_data` to `NULL`, and set ALL pointers to `NULL` after freeing (in particular `current_chunk->chunk_data` in the `error` case of `read_png_chunk` to fix this specific bug), because OCD.

Also, after fixing this bug, `poc.bin` still produces some memory leaks. Those can partly be fixed by also freeing `plte_chunk->chunk_data` and `ihdr_chunk->chunk_data` in the `success` and `error` cases of `load_png`.

### Steps to Reproduce

#### Command

```
./fuzzer_load_png poc.bin
```

#### Proof-of-Concept Input (if needed)
(attached: poc.png)