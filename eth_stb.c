#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bip32.h"
#include "curves.h"
#include "secp256k1.h"
#include "address.h"


#define VERSION_PUBLIC 0x0488b21e
#define VERSION_PRIVATE 0x0488ade4

//Chain m/0'/0
//Extended Public Key : xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG


int main() {
  HDNode root, node;
  uint8_t pubkeyhash[20];
  char address[41];

  char xpub_key[112] = "xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG";
  printf("BIP32 Extended Public Key  m/0'/0: %s \n\n",xpub_key);

  hdnode_deserialize(xpub_key, VERSION_PUBLIC, VERSION_PRIVATE, SECP256K1_NAME,
                     &root, NULL);
  memcpy(&node, &root, sizeof(HDNode));
  hdnode_public_ckd(&node, 0);
  hdnode_fill_public_key(&node);
  hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
  //ethereum_address_checksum(pubkeyhash, address, false, 0);



  //ecdsa_get_address(node.public_key, 0, HASHER_SHA2_RIPEMD, HASHER_SHA2D, addr1,sizeof(addr1));


  //void hdnode_get_address_raw(HDNode *node, uint32_t version, uint8_t *addr_raw);

  //hdnode_fill_public_key(&root);
  //hdnode_get_ethereum_pubkeyhash(&root, pubkeyhash);
  //char address[41];
  //ethereum_address_checksum(pubkeyhash, address, false, 0);
  printf("ETH  m/0'/0: %s \n\n",address);












  return (0);
}

