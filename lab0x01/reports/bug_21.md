# BUG-21
## Category
Arithmetic error/overflow

## Description
When calculating the average values of red, green, blue, and alpha of neighbouring pixels, the formula `(2 * radius + 1) * (2 * radius + 1)` is not necessarily correct (what if a pixel is located at the edge of the image?).

## Affected Lines in the original program
`filter.c:86`

## Expected vs Observed
We expect the blur filter to replace each pixel's color values with the average color values of the pixels located in the respective pixel's proximity. However, the program computes this average using the formula `(2 * radius + 1) * (2 * radius + 1)` for every pixel; for pixels at the edge of the image however, this formula is incorrect as the circe defining the 'pixels in the proximity' is truncated so as to stay within the boundaries of the image.

## Steps to Reproduce
Call the program with any valid input, such as in the sample command below.

### Command
````
./filter test_imgs/desert.png blur_output.png blur 50
````

### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Calculate `num_pixels` by incrementing a counter everytime the condition for reading neighbouring pixels from valid memory is true (instead of using the same formula every time).