# BUG-13
## Category
Wrong operators/variables

## Description
Due to a typo (using `+` instead of `*`), not enough memory is allocated for the `new_img->px` array, leading to a segmentation fault.

## Affected Lines in the original program
Typo: `resize.c:49`, segmentation fault resulting from typo: `resize.c:70` 

## Expected vs Observed
Expected: the provided image is resized according to the given resize factor, and the result is saved in the speficied output location.

## Steps to Reproduce
Run the original file with any (reasonable) input, such as in the example given in the command below.

### Command

```
./resize test_imgs/summer.png resize_test.png 2.5
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Change `+` to `*` in line 49.