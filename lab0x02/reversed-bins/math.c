
#include <stdio.h>
#include <stdlib.h>

int MATH(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  double dVar3;
  int local_1c;
  dVar3 = sqrt((double)param_1);
  dVar3 = ceil(dVar3);
  local_1c = (int)dVar3;
  do {
    if (param_1 < local_1c) {
      return 1;
    }
    iVar1 = local_1c * local_1c - param_1;
    iVar2 = FUN_00100999(iVar1);
    if (iVar2 != 0) {
      dVar3 = sqrt((double)iVar1);
      iVar1 = local_1c - (int)dVar3;
      if ((((iVar1 != 1) && (iVar1 != param_1)) && (iVar1 == param_2)) &&
         ((int)dVar3 + local_1c == param_3)) {
        // WIN();
        return 0;
      }
    }
    local_1c = local_1c + 1;
  } while( true );
}
