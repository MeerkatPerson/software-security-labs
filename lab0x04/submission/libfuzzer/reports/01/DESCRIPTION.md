
# BUG 01

NOTE: this bug was found when fuzzing after having already fixed the bug described in the `README` as well as bug 00.

### Name

Invalid read of `NULL` pointer in `convert_color_palette_to_image`.

### Description

Invalid read in `convert_color_palette_to_image`: when `plte_chunk` is `NULL`, we get an invalid read upon trying to access `plte_chunk->chunk_data`.

### Expected vs Observed

Expected: `convert_color_palette_to_image` combines image metadata, palette and a decompressed image data buffer (with palette entries) into an image. Observed: program aborts with a segfault.

### Affected Lines

`pngparser.c:385`

### Suggested Fix Description

Suggested fix: let `convert_color_palette_to_image` return `NULL` when `plte_chunk` is `NULL` (this case is handled in the calling function).

### Steps to Reproduce

#### Command

```
./fuzzer_load_png poc.bin
```

#### Proof-of-Concept Input (if needed)
(attached: poc.png)


