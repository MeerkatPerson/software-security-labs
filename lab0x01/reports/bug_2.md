# BUG-2
## Category
Heap overflow

## Description
In order to be able to segment the image using the `square_width`, both width and height must divisible by square_width. However, this isn't checked.

## Affected Lines in the original program
Bug location: `checkerboard.c:99`; invalid writes resulting from bug: `checkerboard.c:115`, `checkerboard.c:117`, `checkerboard.c:119`, `checkerboard.c:121`

## Expected vs Observed
In the presence of this bug, the program simply doesn't run. Expected: execution of the program. Observed: program crashes (message: `segmentation fault`).  

## Steps to Reproduce
This crash will occur as long as `square_width` does not divide `width` and/or `height`.

### Command

```
./checkerboard checkerboard_test.png 10 10 3 d7a6b7 c0d6e4
```

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Add an additional check to ensure the described requirement is fulfilled.

