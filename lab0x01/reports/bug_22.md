# BUG-22
## Category
Iteration errors

## Description
Iterating from `i - radius` to `i + radius` and `j - radius` to `j + radius` for computing the average colors of neighbouring pixels is not efficient: it results in a lot of unnecessary out-of-bounds checks for pixels for which the circle around them defined by radius does not entirely lie inside the image.

## Affected Lines in the original program
`filter.c:69-70`

## Expected vs Observed
Expected: the image is blurred in a fairly efficient manner. Observed: the program takes a long time to pass the image through the filter.

## Steps to Reproduce
Calling the program with any valid values for the input parameters will do (after having fixed the non-graded bug resulting in reads from invalid memory).

### Command
````
./filter test_imgs/desert.png blur_output.png blur 50
````

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Compute the area of neighbouring pixels that are not out of bounds to decide which intervals to loop over to avoid unnecessary checks.