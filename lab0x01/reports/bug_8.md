# BUG-8
## Category
Arithmetic error/overflow

## Description
In `resize.c`, the width and height of the image (both of datatype `uint16_t`) are multiplied by a factor, and the result is assigned to `unsigned short height` resp. `unsigned short width`. We thus need to make sure that the result of the multiplication does not exceed the maximum size of an unsigned short.

## Affected Lines in the original program
`resize.c:34-35`

## Expected vs Observed
Expected: the results of `height * factor`/`width * factor` are computed and stored. Observed: if the computation result exceeds the maximum value that can be stored in an `unsigned short`, the resulting unsigned integer type is reduced modulo the number that is one greater than the largest value that can be represented by the resulting type according to the C standard.

## Steps to Reproduce
Call the program with a very large resize factor to trigger the overflow, such as in the command below.

### Command
````
./resize test_imgs/desert.png resize_test.png 65535
````

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Check that `height < 65535 * factor` and `width < 65535 * factor`.