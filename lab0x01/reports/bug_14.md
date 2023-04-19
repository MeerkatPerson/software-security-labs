# BUG-14
## Category
Iteration errors

## Description
Due to setting incorrect bounds for loop iterators, the program does not deliver its intended functionality. In particular, in the current configuration, the condition for drawing onto the image is never true.

## Affected Lines in the original program
`rect.c:67`, `rect.c:68` 

## Expected vs Observed
Expected: a rectangle is drawn onto the provided image, at the specified location and in the given color, and saved at the output location.

## Steps to Reproduce

Run the original file with any (reasonable) input, such as in the example given in the command below.

### Command

```
./rect test_imgs/summer.png rect_test.png 50 100 100 50 ffe100
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Adjust the loop(s) in which the rectangle is colored so that the case where the condition is true (i.e., the respective coordinate is inside the rectangle) actually result in the corresponding pixel being colored.