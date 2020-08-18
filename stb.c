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

//CHAIN BIP44 TEST 02867fc06f31dfb7bc373f346ac3c374af7395e23eab3083464c71d2d2311584cd53682b410f0ed66cee3b9e5f78d3ca6d373db6d9b3170e8816ab680764d9a5
//49'/0'/0'/0

//Chain m/0'/0
//Extended Public Key : xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG


int main() {
  HDNode root;
  char xpub_key[112] = "xpub6ASuArnXKPbfEVRpCesNx4P939HDXENHkksgxsVG1yNp9958A33qYoPiTN9QrJmWFa2jNLdK84bWmyqTSPGtApP8P7nHUYwxHPhqmzUyeFG";
  //char xpub_key[112] = "xpub6EQT5CixTp6NNaz9iZQgG7Zxb9xKbtFWMcouvTrqEWesqDbHrythtu2Kk9SgQQDzcYAttyVWfFSeb2HdWiKVZWGSh5exByCekoeYnLGPaQQ";
  printf("BIP32 Extended Public Key  m/0'/0: %s \n\n",xpub_key);

  hdnode_deserialize(xpub_key, VERSION_PUBLIC, VERSION_PRIVATE, SECP256K1_NAME,
                         &root, NULL);

  //hdnode_fill_public_key(&root);

  HDNode node;
  char addr1[MAX_ADDR_SIZE], addr2[MAX_ADDR_SIZE], addr3[MAX_ADDR_SIZE], addr4[MAX_ADDR_SIZE], addr5[MAX_ADDR_SIZE], addr6[MAX_ADDR_SIZE];

  //uint8_t pubkeyhash[20];
  //char address[41];


  for (int i = 0; i < 5; i++) {
    memcpy(&node, &root, sizeof(HDNode));
    hdnode_public_ckd(&node, i);
    hdnode_fill_public_key(&node);
    printf("STB CARD ID:%d   BIP32 PATH:m/0'/0/%d  public_key_hex: ",i,i);
    for(size_t y = 0; y < 32; y++ )
    {
    printf("%" PRIu8,node.public_key[y]);
    }
    printf("\n");

    ecdsa_get_address(node.public_key, 0, HASHER_SHA2_RIPEMD, HASHER_SHA2D, addr1,sizeof(addr1));
    printf("BTC           P2PKH ADDRESS: %s\n",addr1);

    ecdsa_get_address_segwit_p2sh(node.public_key, 5, HASHER_SHA2_RIPEMD, HASHER_SHA2D,addr2, sizeof(addr2));
    printf("BTC           P2SH  ADDRESS: %s\n",addr2);

    ecdsa_get_address(node.public_key, 48, HASHER_SHA2_RIPEMD, HASHER_SHA2D, addr3,sizeof(addr3));
    printf("LTC           P2PKH ADDRESS: %s\n",addr3);

    ecdsa_get_address_segwit_p2sh(node.public_key, 50, HASHER_SHA2_RIPEMD, HASHER_SHA2D,addr4, sizeof(addr4));
    printf("LTC           P2SH  ADDRESS: %s\n",addr4);

    ecdsa_get_address(node.public_key, 111, HASHER_SHA2_RIPEMD, HASHER_SHA2D,addr5, sizeof(addr5));
    printf("BTC TESTNET 3 P2PKH ADDRESS: %s\n",addr5);

    ecdsa_get_address_segwit_p2sh(node.public_key, 196, HASHER_SHA2_RIPEMD, HASHER_SHA2D,addr6, sizeof(addr6));
    printf("BTC TESTNET 3 P2SH  ADDRESS: %s\n\n",addr6);
  
    //hdnode_private_ckd(&node, i);
    //hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
    //ethereum_address_checksum(pubkeyhash, address, false, 0);
    //printf("ETH  ADDRESS: %s\n\n",address);



  }


  return (0);
}

