# BUG-12
## Category
Local persisting pointers

## Description
Address of stack memory associated with local variable `px` returned. This leads to undefined behavior. 

## Affected Lines in the original program
`filter.c:109`

## Expected vs Observed
Expected: compute the negative of a given image. Observed: the program aborts with message `segmentation fault`.

## Steps to Reproduce
Call the program with standard input values, such as in the example command below.

### Command

```
./filter test_imgs/summer.png summer_negative.png negative
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Get rid of the `get_pixel()` function and *statically* allocate memory for `struct pixel` where the function is called.