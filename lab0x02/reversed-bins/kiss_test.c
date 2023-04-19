
#include <stdio.h>


int check_local_28(int param_1)

{
  int uVar1;
  
  if (param_1 < 0x38) {
    uVar1 = 0;
  }
  else if (param_1 < 0x6c) {
    if (param_1 / 2 < param_1 + -0x31) {
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

int check_local_24(int param_1)

{
  int uVar1;

  param_1 = param_1 + -0x4153;
  if (param_1 < 1) {
    uVar1 = 0;
  } else if (param_1 * 3 + -0x80 < (int)((param_1 - (param_1 >> 0x1f) & 1U) +
                                         (param_1 >> 0x1f) + param_1)) {
    uVar1 = 1;
  } else {
    uVar1 = 0;
  }
  return uVar1;
}

int check_local_20(int param_1)

{
  int uVar1;
  
  if ((param_1 & 1) == 0) {
    uVar1 = 0;
  }
  else if ((int)param_1 % 7 == 0) {
    if ((int)param_1 < 0x1f0f3) {
      uVar1 = 0;
    }
    else if ((int)(param_1 * 5) < (int)(((int)param_1 / 0x6930) * param_1)) {
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

int check_local_1c(int param_1)

{
  int uVar1;
  
  if ((int)param_1 >> 4 < 0x395eb) {
    uVar1 = 0;
  }
  else if ((int)(param_1 * 2) < 0x72bde0) {
    if ((param_1 & 1) == 0) {
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}


int main(int argc, char *argv[]) {

  for (int i = 0; i <= 2147483647; i++) {

    int res = check_local_24(i);

    if (res == 1) {

      printf("Solution for local_24: %d\n", i);

      break;
    
    }
  }

    for (int i = 11; i <= 2147483647; i++) {

    int res = check_local_20((i - 2)*3);

    if (res == 1) {

      printf("Solution for local_20: %d\n", i);

      break;
    
    }

    }


    for (int i = 0; i <= 2147483647; i++) {

        int res = check_local_1c(i);

        if (res == 1) {

        printf("Solution for local_1c: %d\n", i);

        break;
        
        }

    }

}