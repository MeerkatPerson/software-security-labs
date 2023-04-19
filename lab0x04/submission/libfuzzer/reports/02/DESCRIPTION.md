
# BUG 02

NOTE: this assumes bugs 0, 1, and 2 have already been fixed.

### Name

Memory leaks: `inflated_buf`, `plte_chunk->chunk_data`, `ihdr_chunk->chunk_data``

### Description:

Lots of memory leaks. 

Firstly, `inflated_buf` is never freed. Fix: free `inflated_buf` in the `success` and `error` cases of `load_png`.

Further, in the `success` and `error` cases of `load_png`, the field `chunk_data` is only freed for `current_chunk`, not `plte_chunk` and `ihdr_chunk`. 

Also, in `compress_png_data`, in the error case, we need to free `decompressed_data`, which was allocated in the calling function.

### Expected vs Observed

Memory safety is ensured: all memory that was dynamically allocated is freed in the respective locations. Observed: memory leaks due to missing calls to `free`.

### Affected Lines

No lines are affected as these bugs refer to missing rather than incorrect statements. These missing statements need to be inserted in the locations described above.

### Suggested Fix Description

Fix: add the corresponding additional frees in the spots named above.

### Steps to reproduce

#### Command

```
./fuzzer_load_png poc.bin
```

#### Proof-of-Concept Input (if needed)
(attached: poc.png)

