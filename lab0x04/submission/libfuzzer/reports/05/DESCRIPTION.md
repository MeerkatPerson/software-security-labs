
# BUG 05

NOTE: as always, assuming all the other bugs (0-4) have been fixed previously.

### Name

Invalid call of `store_filesig` on `NULL` value.

### Description

In `store_png`, there is no `NULL`-check for `output` before calling `store_filesig` on it. This results in an invalid read in `fwrite` when `output` is in fact `NULL`.

### Expected vs Observed

Expected: if the `fopen` call on in `store_png` fails, the program should exit safely. Instead, the program continues and invalidly calls library functions on a `NULL` pointer.

### Affected Lines in the Original Program

`pngparser.c:1009`

### Suggested Fix Description

Suggested fix: check if `output` is `NULL` and return 1 if it is (before attempting to call `store_filesig` on it)

### Steps to Reproduce

#### Command

```
./store_png_name poc.bin
```

#### Proof-of-Concept Input (if needed)
(attached: poc.png)
