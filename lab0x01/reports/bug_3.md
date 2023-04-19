# BUG-3 
Wrong operators/variables

## Description
Equality comparisons (`==`) are used in places where variable assignments (`=`) are required.

## Affected Lines in the original program
In `circle.c:65` and `circle.c:88`

## Expected vs Observed
Expected: a solid circle is drawn onto the specified picture, with the result being saved at the specified output location. Observed: the resulting circle drawn on the given image is imperfect (has some gaps).

## Steps to Reproduce

Run the program with any (valid) input, such as in the example given in the next section.

### Command

```
./circle test_imgs/desert.png circle_test.png 10 10 5 33adff
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description

Replace `==` with `=` in the affected lines.