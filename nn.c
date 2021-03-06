/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   test_main.c
 * Author: analiser
 *
 * Created on August 13, 2020, 1:21 PM
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bip32.h"
#include "curves.h"
#include "secp256k1.h"

//#include "options.h"

/*#include "address.h"
#include "aes/aes.h"
#include "base32.h"
#include "base58.h"
#include "bignum.h"
#include "bip32.h"
#include "bip39.h"
#include "blake256.h"
#include "blake2b.h"
#include "blake2s.h"
#include "curves.h"
#include "ecdsa.h"
#include "ed25519-donna/ed25519-donna.h"
#include "ed25519-donna/ed25519-keccak.h"
#include "ed25519-donna/ed25519.h"
#include "hmac_drbg.h"
#include "memzero.h"
#include "monero/monero.h"
#include "nem.h"
#include "nist256p1.h"
#include "pbkdf2.h"
#include "rand.h"
#include "rc4.h"
#include "rfc6979.h"
#include "script.h"
#include "secp256k1.h"
#include "sha2.h"
#include "sha3.h"
#include "shamir.h"
#include "slip39.h"
*/


/*
 * 
 */
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
  HDNode root; //, node2, node3;
  uint32_t fingerprint;
  char str[112];
  //int r;
  //	 init m
  hdnode_from_seed(fromhex("000102030405060708090a0b0c0d0e0f"), 16,
                   SECP256K1_NAME, &root);

  // [chain m]
  fingerprint = 0;
  hdnode_serialize_private(&root, fingerprint, VERSION_PRIVATE, str,
                           sizeof(str));
  printf("compare with https ://iancoleman.io/bip39/ BIP44\n");
  printf("BIP39 Seed         : 000102030405060708090a0b0c0d0e0f\n");
  printf("BIP32 Root Key     : %s\n", str);

  // [Chain m/44']
  fingerprint = hdnode_fingerprint(&root);
  hdnode_private_ckd_prime(&root, 44);

  hdnode_serialize_private(&root, fingerprint, VERSION_PRIVATE, str,
                           sizeof(str));
  //printf("bip32 m/44' priv key: %s\n", str);


  // [Chain m/44'/0']
  fingerprint = hdnode_fingerprint(&root);
  hdnode_private_ckd_prime(&root, 0);

  hdnode_serialize_private(&root, fingerprint, VERSION_PRIVATE, str,
                           sizeof(str));
  //printf("bip32 m/44'/0' priv key: %s\n", str);



  // [Chain m/44'/0'/0']
  fingerprint = hdnode_fingerprint(&root);
  //hdnode_private_ckd(&root, 0);
  hdnode_private_ckd_prime(&root, 0);

  hdnode_serialize_private(&root, fingerprint, VERSION_PRIVATE, str,
                           sizeof(str));
  printf("Account Extended Private Key: %s\n", str);

  //hdnode_public_ckd(&root, 0);
  hdnode_fill_public_key(&root);

  hdnode_serialize_public(&root, fingerprint, VERSION_PUBLIC, str,
                           sizeof(str));
  printf("Account Extended Public Key : %s\n", str);



  // [Chain m/44'/0'/0'/0]
  fingerprint = hdnode_fingerprint(&root);
  hdnode_private_ckd(&root, 0);
  //hdnode_private_ckd_prime(&root, 0);

  hdnode_serialize_private(&root, fingerprint, VERSION_PRIVATE, str,
                           sizeof(str));
  printf("BIP32 Extended Private Key  : %s\n", str);

  hdnode_fill_public_key(&root);

  hdnode_serialize_public(&root, fingerprint, VERSION_PUBLIC, str,
                           sizeof(str));
  printf("BIP32 Extended Public Key   : %s\n", str);


  // Adreess derivation
  curve_point pub;
  ecdsa_read_pubkey(&secp256k1, root.public_key, &pub);
  //HDNode node;
  char addr1[MAX_ADDR_SIZE];
  for (int i = 0; i < 10; i++) {
    // optimized
    hdnode_public_ckd_address_optimized(&pub, root.chain_code, i, 0,
                                        HASHER_SHA2_RIPEMD, HASHER_SHA2D, addr1,
                                        sizeof(addr1), 0);
    // check agianst ian coleman bip39 site
    printf("address%d   : %s\n", i,addr1);
  }



  //hdnode_deserialize(str, VERSION_PUBLIC, VERSION_PRIVATE, SECP256K1_NAME,
  //                       &node, NULL);

  //hdnode_public_ckd(&node, 0);

  //uint32_t i;
  //char address[36];
  //hdnode_public_ckd(&root, 0);
  //memcpy(&node, &root, sizeof(HDNode));
  //hdnode_public_ckd(&node, 0);

  //ecdsa_get_address(node.public_key, 0, HASHER_SHA2, HASHER_SHA2D, address,
  //                    sizeof(address));


  //printf("address   : %s\n", address);



  //printf("%s", node.child_num);
  //printf("%" PRIu32 "\n",node.child_num);
  //for(size_t i = 0; i < 32; i++ )
  //{
  // printf("%" PRIu8 "\n",node.private_key[i]);
  //}
  //printf("%x" PRIu8 "\n",node.private_key[32]);
  //printf("%c"node.private_key);
  return (0);
}

