# BUG-15
## Category
Stack buffer overflow

## Description
It is not checked if the position and size of the circle fit into the boundaries of the image. Thus, if values are provided such that `center_x - radius < 0`,  `center_x + radius > img->size_x`, `center_y - radius < 0`, or `center_y + radius > img->size_y`, a `segmentation fault` occurs when attempting to draw onto the image.    

## Affected Lines in the original program
`circle.c:60-63`, `circle.c:68-71`, `circe.c:83-86`, `circe.c:91-94` 

## Expected vs Observed
Expected: if the given position and radius of the circle cause the drawing to overflow the boundaries of the image, we expect the program to only draw in valid locations. Observed: the program crashes (message: `segmentation fault`).

## Steps to Reproduce

Run the original file with an input that causes the circle drawing to overflow the boundaries of the image as outlined in the description above.

### Command

```
./circe test_imgs/summer.png circle_test.png 250 250 1000 ffe100
```
### Proof-of-Concept Input (if needed)


## Suggested Fix Description
Check if the boundaries have been violated before writing to the `image_data` array.