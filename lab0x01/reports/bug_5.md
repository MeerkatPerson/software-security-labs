# BUG-5
## Category
Stack buffer overflow/underflow

## Description
The program accepts 6 input arguments: `input_file`, `output_file`, `center_x`, `center_y`, `radius`, `hex_color`. Thus, the maximum index of `argv` is 6 (`argv[0]` stores the program's name as per convention). An attempt to read `argv[7]` thus constitutes an invalid read. 

## Affected Lines in the original program
`circle.c:33`, `circle.c:34`

## Expected vs Observed
Expected: program draws a circle onto the specified image. Observed: the program crashes upon an attempt to execute it (message: `segmentation fault`).

## Steps to Reproduce

Running the program with any (valid) input will result in this behaviour.

### Command

```
./circle test_imgs/desert.png circle_test.png 5 5 1 fa7645
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
The `hex_color` argument is stored in `argv[6]`, not `argv[7]`. Make the according changes in lines 33 and 34.
