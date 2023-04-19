# BUG-4
## Category
Usage of deprecated function

## Description
`atoi` is used rather than `strtol`. 

## Affected Lines in the original program
In `circle.c:21`, `circle.c:22`, `circle.c:28`  

## Expected vs Observed
When a negative input, a numerical value exceeding the maximum size of an `int` or even some string like `foo` is provided as argument, we expect the program to inform us of the invalidity of the input.
Instead, atoi will just convert the input to the number 0 and thus make this scenario indistinguishable from one in which the actual input is 0.

Providing such an argument leads to `undefined behavior`: `if the value of the result cannot be represented, the behavior is undefined`.

## Steps to Reproduce
Call the program with invalid inputs as outlined above for one or multiple of `center_x`, `center_y`, and `radius`.

### Command

```
./circle test_imgs/summer.png circle_test.png 777777777 777777777 "foo" fa7645
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Replace all instances of `atoi` with `strtol`.