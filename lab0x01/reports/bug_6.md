# BUG-6
## Category
Type errors

## Description
Incompatible pointer types passing `char *` to parameter of type `char **`

## Affected Lines in the original program
In `rect.c:34` 

## Expected vs Observed
Expected: a rectangle is drawn onto the specified image, with its location and color as specified.
Observed: the program crashes (message: `segmentation fault`).

## Steps to Reproduce

Run the original program with any reasonable input, such as in the example outlined in the next section.

### Command

```
./rect test_imgs/desert.png rect_test.png 10 10 20 5 ffffff
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Change `end_ptr` to `&end_ptr` in line 34.
