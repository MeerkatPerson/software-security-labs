
# BUG 04

NOTE: assuming bugs 0-3 have already been fixed here!!

### Name

Invalid call to `fopen` on `NULL` value.

### Description

When `fopen` fails in `load_png`, `input` is `NULL` and we `goto error`.
However, in `error` handling, an attempt is made to `fclose` `input` without checking if `input` is `NULL`, causing an invalid read.

### Expected vs Observed

Expected: there is nothing to `fclose` when `fopen` failed. Observed: nevertheless, an attempt is made to `fopen` `NULL`value.

### Affected Lines in the Original Program

`pngparser.c:694`.

### Suggested Fix Description

Fix: check if `input` is `NULL` and only call `fclose` on it if it isn't.

### Steps to Reproduce

#### Command

```
./fuzzer_load_png_name poc.bin
```

#### Proof-of-Concept Input (if needed)
(attached: poc.png)






