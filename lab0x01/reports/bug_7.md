# BUG-7
## Category
Temporal safety violation

## Description
There exist paths through the program in which a struct for which memory has been allocated (`struct pixel *ptr`) is never freed.

## Affected Lines in the original program
`solid.c:16`, `solid.c:138 - 144`

## Expected vs Observed
The expected functionality of the program (draw a solid rectangle of the specified size and color and save it in the given output location) is not affected by this bug; however, its expected *properties* (i.e., memory safety) are in fact affected.

## Steps to Reproduce
If an error occurs while attempting to allocate memory for `img` (line 71), `img->px` (line 76), or attempting to store the png (line 103).

We can e.g. trigger the bug by picking the `width` and `height` parameters als large as possible, i.e. `USHRT_MAX - 1` (= maximum possible value to still pass the checks in lines 48 and 53), to cause the attempt to allocate memory for `img->px` to fail.

### Command

```
./solid solid_test.png 65534 65534 c0d6e4
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Add a `free(palette)` in the three error cases `error_img`, `error_px`, and `error_mem`.
