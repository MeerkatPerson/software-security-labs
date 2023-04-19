#include "pngparser.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define OUTPUT_NAME_SIZE 255

// This function is from
// https://www.geeksforgeeks.org/c-program-find-size-file/
// could have also used stat

long int findSize(char file_name[]) {
  // opening the file in read mode
  FILE *fp = fopen(file_name, "r");

  // checking if the file exist or not
  if (fp == NULL) {
    printf("File Not Found!\n");
    return -1;
  }

  fseek(fp, 0L, SEEK_END);

  // calculating the size of the file
  long int res = ftell(fp);

  // closing the file
  fclose(fp);

  return res;
}

int main(int argc, char *argv[]) {

  struct image *img = NULL;

  struct pixel *palette = malloc(sizeof(struct pixel));

  if (!palette) {
    goto error_palette;
  }

  /*
   * goto statements should be used only in two cases:
   *
   * 1) Cleanup at the end of the function (HERE)
   * 2) To jump out of multiple for loops without using flags
   *
   */

  // The user needs to provide all arguments
  // >= or > ????
  if (argc != 5 || strlen(argv[1]) > OUTPUT_NAME_SIZE) {
    goto error;
  }

  /* Assign names to arguments for better abstraction */
  char output_name[OUTPUT_NAME_SIZE];

  strncpy(output_name, argv[1],
          OUTPUT_NAME_SIZE); // BUG ???!!! Size of argv[1] not checked
  const char *height_arg = argv[2];
  const char *width_arg = argv[3];
  const char *hex_color_arg = argv[4];
  char *end_ptr;

  if (strlen(hex_color_arg) != 6) {
    goto error;
  }

  unsigned long height = strtol(height_arg, &end_ptr, 10);

  /* If the user provides negative height or the height is 0 and the end_ptr
   * hasn't moved we issue an error and free palette
   */
  if (height >= (32767 * 2 + 1) || *end_ptr)
    goto error;

  unsigned long width = strtol(width_arg, &end_ptr, 10);

  if (width >= USHRT_MAX || *end_ptr) {
    goto error;
  }

  unsigned n_pixels = height * width;

  long color = strtol(hex_color_arg, &end_ptr, 16);

  if (*end_ptr) {
    goto error;
  }

  palette[0].red = (color & 0xff0000) >> 16;
  palette[0].green = (color & 0x00ff00) >> 8;
  palette[0].blue = (color & 0x0000ff);
  palette[0].alpha = 0xff;

  /* After calling malloc we must check if it was successful */
  img = malloc(sizeof(struct image));
  if (!img) {
    goto error_mem;
  }

  img->px = malloc(sizeof(struct pixel) * n_pixels);
  if (!img->px) {
    goto error_img;
  }

  img->size_x = width;
  img->size_y = height;

  {
    /* Cast a pixel array into a 2D array.
     * We need extra brackets to prevent goto from jumping into the scope of the
     * new variable
     */
    struct pixel(*image_data)[img->size_x] =
        (struct pixel(*)[img->size_x])img->px;

    /* Iterate over a new image and fill it with color */
    for (int i = 0; i < img->size_y; i++) {
      for (int j = 0; j < img->size_x; j++) {
        image_data[i][j].red = palette[0].red;
        image_data[i][j].green = palette[0].green;
        image_data[i][j].blue = palette[0].blue;
        image_data[i][j].alpha = 0xff;
      }
    }
  }

  if (store_png(output_name, img, palette, 1)) {
    goto error_px;
  }

  free(img->px);
  img->px = NULL;
  free(img);
  img = NULL;
  free(palette);
  palette = NULL;

  /* We want to inform user how big the new image is.
   * "stat -c %s filename" prints the size of the file
   *
   * To prevent buffer overflows we use strncat.
   */
  // char command[512] = {0};

  printf("Size: ");

  long int res = findSize(output_name);
  if (res != -1)
    // printf("Size of the file is %ld bytes \n", res);
    printf("%ld\n", res);

  return 0;

  /* We use goto to jump to the corresponding error handling code.
   * This gets rid of repetitive if chunks we'd use otherwise
   */

error_px:
  if (palette) {
    free(palette);
    palette = NULL;
  }
  if (img) {
    free(img);
    img = NULL;
  }
  if (img->px) {
    free(img->px);
    img->px = NULL;
  }
  return 1;
error_img:
  if (palette) {
    free(palette);
    palette = NULL;
  }
  if (img) {
    free(img);
    img = NULL;
  }
  return 1;
error_mem:
  if (palette) {
    free(palette);
    palette = NULL;
  }
  printf("Couldn't allocate memory\n");
  return 1;
error:
  if (palette) {
    free(palette);
    palette = NULL;
  }
  printf("Usage: %s output_name height width hex_color\n", argv[0]);
  return 1;
error_palette:
  printf("Couldn't allocate memory for palette\n");
  return 1;
}
