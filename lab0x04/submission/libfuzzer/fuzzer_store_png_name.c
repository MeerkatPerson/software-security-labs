#include "pngparser.h"
#include <stdio.h>
#include <string.h>

// LibFuzzer stub
//
int LLVMFuzzerTestOneInput(const char *Data, size_t Size) {

  if (Size > 0) {
  
    struct image *test_img;

    char dest[Size];

    memset(dest, '\0', Size);

    for (int i = 0; i < (Size-1); i++) {
      dest[i] = Data[i];
    }

    if (load_png("./seeds/palette.png", &test_img) == 0) {

        int res = store_png(dest, test_img, NULL, 0);

        free(test_img);

    }

  }

  // Always return 0
  return 0;
}