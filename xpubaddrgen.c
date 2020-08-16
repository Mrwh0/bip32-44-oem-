#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "bip32.h"
#include "curves.h"
#include "ecdsa.h"

#define VERSION_PUBLIC 0x0488b21e
#define VERSION_PRIVATE 0x0488ade4

void process_job(const char *xpub, uint32_t change,
                 uint32_t from, uint32_t to) {
  HDNode node, child;
  if (change > 1 || to <= from ||
      hdnode_deserialize(xpub, VERSION_PUBLIC, VERSION_PRIVATE, SECP256K1_NAME,
                         &node, NULL) != 0) {
    printf("error\n");
    return;
  }
  hdnode_public_ckd(&node, change);
  uint32_t i;
  char address[36];
  for (i = from; i < to; i++) {
    memcpy(&child, &node, sizeof(HDNode));
    hdnode_public_ckd(&child, i);
    ecdsa_get_address(child.public_key, 0, HASHER_SHA2, HASHER_SHA2D, address,
                      sizeof(address));
    printf(" %d %s\n",  i, address);
  }
}

int main(void) {
  char xpub[1024] = "xpub6BcjTvRCYD4VvFQ8whztSXhbNyhS56eTd5P3g9Zvd3zPEeUeL5CUqBYX8NSd1b6Thitr8bZcSnesmXZH7KerMcc4tUkenBShYCtQ1L8ebVe";
  uint32_t  change = 0;
  uint32_t  from = 0;
  uint32_t  to = 5;
  printf("%s %u %u %u\n", xpub, change, from, to);
  process_job(xpub, change, from, to);
  return 0;
}
