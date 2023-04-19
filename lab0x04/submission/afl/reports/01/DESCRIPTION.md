
# BUG 01

### Name

Out-of-bounds read from buffer

### Description

Invalid read in `convert_color_palette_to_image`: when reading from `inflated_buf`, there is no check ensuring that we do not read past its limit, which is given by `inflated_size`.

### Expected vs Observed

Expected: `convert_color_palette_to_image` combines image metadata, palette and a decompressed image data buffer (with palette entries) into an image. Observed: program aborts with a segfault.

### Affected Lines

`pngparser.c:394`, `pngparser.c:400`

### Suggested Fix Description

Fix: insert bound checks to ensure we don't read past index `inflated_size-1`. Return `NULL` if the index at which we're trying to read from `inflated_buf` is out-of-bounds (`NULL` return value is handled in the calling function).

### Steps to Reproduce

#### Command

```
./size poc.bin
```

#### Proof-of-Concept Input (if needed)

(attached: poc.png)