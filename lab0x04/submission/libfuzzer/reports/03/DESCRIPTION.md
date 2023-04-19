
# BUG 03

NOTE: assuming bugs 00-02 are already fixed.

### Name

Invalid `free` of non-initialized pointer in `error` case of `store_idat_palette`.
 
### Description

In the `error` case of `store_idat_palette`, there is a `NULL` check for `compressed_data_buf`. However, `compressed_data_buf` is declared & initialized after the line containing the `goto error` statement, causing an invalid read. This is an example of how `goto`-statements can trick the compiler!

### Expected vs Observed

`goto`-statements are tricky - the programmer has to be sure what they're doing in these. Apparently here, this wasn't the case: the `error` case incorrectly handles data that wasn't yet declared or initialized at the time of the `goto`-statement!
 
### Affected Lines in the Original Program

`pngparser.c:939`

### Suggested Fix Description

Fix: move the declaration & initialization of `compressed_data_buf` to the start of `store_idat_palette`.

### Steps to Reproduce

#### Command

```
./fuzzer_store_png_palette poc.bin
```

#### Proof-of-Concept Input (if needed)
(attached: poc.png)



