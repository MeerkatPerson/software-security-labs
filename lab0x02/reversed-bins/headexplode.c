
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


long func2(long[] param_1)

{
  long local_10;
  long local_c;
  
  local_10 = 0;
  for (local_c = 0x1f; -1 < local_c; local_c = local_c + -1) {
    local_10 = local_10 * 2;
    if (*(long *)(param_1 + (long)local_c * 4) == 1) {
      local_10 = local_10 + 1;
    }
  }
  return local_10;
}

long func1()

{
  long lVar1;
  long *puVar2;
  long in_FS_OFFSET;
  long local_a0;
  long local_9c;
  long local_98 [17];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28); // Canary, egal
  puVar2 = local_98;
  for (lVar1 = 0x10; lVar1 != 0; lVar1 = lVar1 + -1) { // set all values in array to 0
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  local_a0 = 1;
  for (local_9c = 8; 1 < local_9c; local_9c = local_9c + -1) {  // local_9c in range 8 => 1
    //FUN_00100e3f(local_a0,local_9c,local_98);
    local_a0 = func2(local_98);
    memset(local_98,0,0x80);
  }
  printf("%ld\n",(long) local_a0);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    //__stack_chk_fail();
    printf("Canary");
  }
  return local_a0;
}

int main()

{
  printf("%ld", func1());
  return 0;
}