#include "pngparser.h"
#include <stdio.h>

// LibFuzzer stub
//
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  struct image *test_img;

  FILE *input = fopen("testfile.png","w");
  fwrite(Data, Size, 1, input);
  fclose(input);

  if (load_png("testfile.png", &test_img) == 0) {
  	
      int res = store_png("testfile_restored.png", test_img, NULL, 0);

      free(test_img);

  }

  // Always return 0
  return 0;
}
