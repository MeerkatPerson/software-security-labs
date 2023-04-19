#include "pngparser.h"
#include <stdio.h>

// LibFuzzer stub
//
// ERROR CASE: put 10 random colors into the palette (fixed palette as demanded by Makefile),
// but it is pretty unlikely that all the pixels in the image will have colors corresponding to these.

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  struct image *test_img;

  FILE *input = fopen("testfile.png","w");
  fwrite(Data, Size, 1, input);
  fclose(input);

  if (load_png("testfile.png", &test_img) == 0) {
  	
    // Stolen from checkerboard.c .... however doesn't make any sense - 
    // the lookup in 'find_color' will always (?) fail this way

    struct pixel palette[10];

    /* We assign colors to the palette */
    palette[0].red = (0xf6a192 & 0xff0000) >> 16;
    palette[0].green = (0xf6a192 & 0x00ff00) >> 8;
    palette[0].blue = (0xf6a192 & 0x0000ff);
    palette[0].alpha = 0xff;

    palette[1].red = (0x39a78e & 0xff0000) >> 16;
    palette[1].green = (0x39a78e & 0x00ff00) >> 8;
    palette[1].blue = (0x39a78e & 0x0000ff);
    palette[1].alpha = 0xff;

    palette[2].red = (0x14a4f4 & 0xff0000) >> 16;
    palette[2].green = (0x14a4f4 & 0x00ff00) >> 8;
    palette[2].blue = (0x14a4f4 & 0x0000ff);
    palette[2].alpha = 0xff;

    palette[3].red = (0xa80ebe & 0xff0000) >> 16;
    palette[3].green = (0xa80ebe & 0x00ff00) >> 8;
    palette[3].blue = (0xa80ebe & 0x0000ff);
    palette[3].alpha = 0xff;

    palette[4].red = (0xff7f50 & 0xff0000) >> 16;
    palette[4].green = (0xff7f50 & 0x00ff00) >> 8;
    palette[4].blue = (0xff7f50 & 0x0000ff);
    palette[4].alpha = 0xff;

    palette[5].red = (0x003399 & 0xff0000) >> 16;
    palette[5].green = (0x003399 & 0x00ff00) >> 8;
    palette[5].blue = (0x003399 & 0x0000ff);
    palette[5].alpha = 0xff;

    palette[6].red = (0x00db96 & 0xff0000) >> 16;
    palette[6].green = (0x00db96 & 0x00ff00) >> 8;
    palette[6].blue = (0x00db96 & 0x0000ff);
    palette[6].alpha = 0xff;

    palette[7].red = (0x49297e & 0xff0000) >> 16;
    palette[7].green = (0x49297e & 0x00ff00) >> 8;
    palette[7].blue = (0x49297e & 0x0000ff);
    palette[7].alpha = 0xff;

    palette[8].red = (0x2f4f4f & 0xff0000) >> 16;
    palette[8].green = (0x2f4f4f & 0x00ff00) >> 8;
    palette[8].blue = (0x2f4f4f & 0x0000ff);
    palette[8].alpha = 0xff;

    palette[9].red = (0xff00db & 0xff0000) >> 16;
    palette[9].green = (0xff00db & 0x00ff00) >> 8;
    palette[9].blue = (0xff00db & 0x0000ff);
    palette[9].alpha = 0xff;

    int res = store_png("testfile_restored.png", test_img, palette, 10);

    free(test_img->px);

    free(test_img);

  }

  // Always return 0
  return 0;
}
