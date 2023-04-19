# BUG-16
## Category
Iteration error

## Description
`<=` is incorrectly utilized instead of `<` in the blur- as well as the negative filters' loop.  

For the blur filter, if an out-of-bounds check is performed before reading from the `image_data`-array in line 77, this only leads to a segmentation fault in line 94, when it is attempted to write into the `new_data` array in an invalid location.

For the negative filter, a segmentation fault occurs in line 121 when attempting to read from `image_data` at an out-of-bounds index.

## Affected Lines in the original program
`filter.c:64`, `filter.c:65`, `filter.c:118`, `filter.c:119`

## Expected vs Observed
Expected: the given image is passed to the blur/negative filter, and the output is saved in the specified location. Observed: the program aborts with a segmentation fault.

## Steps to Reproduce
Execute the blur/negative filter with any (valid) input, such as in the example command below.

### Command
````
./filter test_imgs/summer.png blur_test.png blur 50
./filter test_imgs/summer.png negative_test.png negative
````

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Replace `<=` with `<`.