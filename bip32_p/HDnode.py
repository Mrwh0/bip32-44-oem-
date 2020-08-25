#BIP39
print("BIP39 WALLET")
from mnemonic import Mnemonic
mnemo = Mnemonic("english")
words = 'copy hockey genuine fossil giraffe banana guitar wagon detect word wasp suspect'
print("BIP39 words               :",words)
seed = mnemo.to_seed(words, passphrase="")
print("BIP39 seed                :",seed.hex())
print("")
print("")

#BIP32 internal node Master node.
#https://github.com/darosior/python-bip32
from bip32 import BIP32, HARDENED_INDEX
bip32_path = ("m/0'/0'/0'/0")
print(f"BIP32 HD MASTER INTERNAL NODE {bip32_path}")
bip32      = BIP32.from_seed(seed)
m_priv     = bip32.get_xpriv_from_path("m")
print("BIP32 Root             Key:",m_priv)
e_priv     = bip32.get_xpriv_from_path(bip32_path)
print("BIP32 Extended Private Key:",e_priv)
e_pub      = bip32.get_xpub_from_path(bip32_path)
print("BIP32 Extended Public  Key:",e_pub)
print("")
print("")


#BIP32 external node Public node.
print(f"PUBLIC HD NODE (STB's derivation keys) from parent path {bip32_path}")
from utils import *

bip32  = BIP32.from_xpub(e_pub)
#https://bitcoin.stackexchange.com/questions/62533/key-derivation-in-hd-wallets-using-the-extended-private-key-vs-hardened-derivati
stb_card_ids = [0,1,2] #,3,4,2147483647]

for id in stb_card_ids:
    child_path             = "m/"+str(id)
    compressed_pub_key     = bip32.get_pubkey_from_path(child_path)
    unconpressed_pub_key   = decompress_pubkey(compressed_pub_key)


    #BITCOIN ADDRESS
    version_hash   =  b'\x00' #https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp#L126
    BTC_P2PKH      = public_key_to_address(version_hash,compressed_pub_key)
    version_hash   =  b'\x05' #https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp#L127
    BTC_P2SH       = public_key_to_segwit_address(version_hash,compressed_pub_key)
    #BITCOIN TESTNET ADDRESS
    version_hash   =  b'\x6f' #https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp#L223
    BTC_TEST_P2PKH = public_key_to_address(version_hash,compressed_pub_key)
    version_hash   =  b'\xc4' #https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp#L224
    BTC_TEST_P2SH  = public_key_to_segwit_address(version_hash,compressed_pub_key)
    #LITECOIN ADDRESS
    version_hash =  b'\x30' #https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp#L128
    LTC_P2PKH    = public_key_to_address(version_hash,compressed_pub_key)
    version_hash =  b'\x32' #https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp#L130
    LTC_P2SH     = public_key_to_segwit_address(version_hash,compressed_pub_key)
    #ETHEREUM ADDRESS
    ETH_HEX  = ethereum_address(unconpressed_pub_key)



    print(f"STB CARD ID   : {id}    bip32 path: {bip32_path}/{id}    Pub Key : {compressed_pub_key.hex()}")
    print(f"BTC P2PKH     : {BTC_P2PKH}")
    print(f"BTC P2SH      : {BTC_P2SH}")
    print(f"BTC TEST P2PKH: {BTC_TEST_P2PKH}")
    print(f"BTC TEST P2SH : {BTC_TEST_P2SH}")
    print(f"LTC P2PKH     : {LTC_P2PKH}")
    print(f"LTC P2SH      : {LTC_P2SH}")
    print(f"ETH HEX       : {ETH_HEX}")
    print("")



