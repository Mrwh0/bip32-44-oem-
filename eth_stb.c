#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bip32.h"
#include "curves.h"
#include "secp256k1.h"
#include "address.h"

#include <check.h>
#include "check_mem.h"


#define VERSION_PUBLIC 0x0488b21e
#define VERSION_PRIVATE 0x0488ade4


#define FROMHEX_MAXLEN 512

const uint8_t *fromhex(const char *str) {
  static uint8_t buf[FROMHEX_MAXLEN];
  size_t len = strlen(str) / 2;
  if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
      c += (str[i * 2 + 1] - '0');
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    buf[i] = c;
  }
  return buf;
}


int main() {
  uint8_t pubkeyhash[20];
  //int res;
  uint32_t fingerprint;
  char str[112];
  //int r;
  //     init m

  HDNode node;

  // init m
  hdnode_from_seed(fromhex("000102030405060708090a0b0c0d0e0f"), 16,
                   SECP256K1_NAME, &node);

  // [Chain m]
  hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
  fingerprint = 0;
  hdnode_serialize_private(&node, fingerprint, VERSION_PRIVATE, str,sizeof(str));
  printf("compare with https ://iancoleman.io/bip39/ BIP32 CUSTON PATH m/0'/0\n\n");
  printf("BIP39 Seed         : 000102030405060708090a0b0c0d0e0f\n");
  printf("BIP32 Root Key     : %s\n\n", str);

  //res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);

  //ck_assert_int_eq(res, 1);
  //ck_assert_mem_eq(pubkeyhash,fromhex("056db290f8ba3250ca64a45d16284d04bc6f5fbf"), 20);

  // [Chain m/0']
  hdnode_private_ckd_prime(&node, 0);
  hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
  //ck_assert_int_eq(res, 1);
  //ck_assert_mem_eq(pubkeyhash,
  //                 fromhex("bf6e48966d0dcf553b53e7b56cb2e0e72dca9e19"), 20);

  // [Chain m/0'/0]
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd(&node, 0);
  hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
  hdnode_serialize_private(&node, fingerprint, VERSION_PRIVATE, str,sizeof(str));
  printf("Extended Private Key: %s\n", str);
  hdnode_fill_public_key(&node);
  hdnode_serialize_public(&node, fingerprint, VERSION_PUBLIC, str,sizeof(str));
  printf("Extended Public Key (master key for all stb) : %s\n\n", str);

  for(size_t y = 0; y < 20; y++ )
  {
  printf("%" PRIu8,pubkeyhash[y]);
  }
  printf("\n");
  char address[41];

  ethereum_address_checksum(pubkeyhash, address, false, 0);
  printf("STB CARD ID:    BIP32 PATH:m/0'/0/    segwit_p2sh ADDRESS:%s\n",address);

  //ck_assert_int_eq(res, 1);
  //ck_assert_mem_eq(pubkeyhash,
  //                 fromhex("29379f45f515c494483298225d1b347f73d1babf"), 20);


  return (0);
}
