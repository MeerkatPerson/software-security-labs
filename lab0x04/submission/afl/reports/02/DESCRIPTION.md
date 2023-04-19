
# BUG 02

### Name

Invalid read of `NULL` value

### Description

In `convert_color_palette_to_image`, we get a segmentation fault when trying to access the field `chunk_data` of `plte_entry` when `plte_entry` is `NULL`.

### Expected vs Observed

Expected: `convert_color_palette_to_image` combines image metadata, palette and a decompressed image data buffer (with palette entries) into an image. Observed: program aborts with a segfault.

### Affected Lines

`pngparser.c:385`

### Suggested Fix Description

Fix: check if `plte_entry` is `NULL` and return `NULL` if it is before trying to access its field `chunk_data`. A `NULL` return value is handled in the calling function.

### Steps to Reproduce

#### Command

```
./size poc.bin
```

#### Proof-of-Concept Input (if needed)

(attached: poc.png)