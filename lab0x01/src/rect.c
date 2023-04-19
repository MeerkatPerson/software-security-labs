#include "pngparser.h"
#include <string.h>

int main(int argc, char *argv[]) {
  struct image *img;

  /* There isn't any complex error handling in this function, so we use a simple
   * if */
  if (argc != 8) {
    printf("Usage: %s input_image output_image top_left_x top_left_y "
           "bottom_right_x bottom_right_y hex_color\n",
           argv[0]);
    return 1;
  }

  /* Parse the points. Invalid input will just set the coordinate to 0.
   * The program will still work.
   */

  char *input = argv[1];
  char *output = argv[2];

  unsigned top_left_x = atoi(argv[3]);
  unsigned top_left_y = atoi(argv[4]);

  unsigned bottom_right_x = atoi(argv[5]);
  unsigned bottom_right_y = atoi(argv[6]);

  /* Invalid color code will set the color to black.
   * If it worked for Henry Ford, it will work for us.
   */

  char *end_ptr;
  long hex_color = strtol(argv[7], &end_ptr, 16); // TYPE ERROR
  if (*end_ptr || strlen(argv[7]) != 6 || hex_color < 0) {
    hex_color = 0;
  }

  if (load_png(input, &img)) {
    return 1;
  }

  unsigned height = img->size_y;
  unsigned width = img->size_x;

  struct pixel(*image_data)[width] = (struct pixel(*)[width])img->px;

  /* We iterate over all pixel in the image and check whether they are in the
   * rectangle
   *
   * The rectangle is defined by the two points:
   * - top-left (TL)
   * - bottom-right (BR)
   *
   * A pixel is inside the rectangle if it is:
   * - to the right of TL
   * - to the left of BR
   * - below TL
   * - above BR
   */

  for (unsigned i = bottom_right_y; i < top_left_y; i++) {

    for (unsigned j = top_left_x; j < bottom_right_x; j++) {

      image_data[i][j].red = (hex_color & 0xff0000) >> 16;
      image_data[i][j].green = (hex_color & 0x00ff00) >> 8;
      image_data[i][j].blue = (hex_color & 0x0000ff);
      image_data[i][j].alpha = 0xff;

      // test actual rectangle
    }
  }

  if (store_png(output, img, NULL, 0)) {
    free(img->px);
    free(img);
    return 1;
  }

  free(img->px);
  free(img);
  return 0;
}
