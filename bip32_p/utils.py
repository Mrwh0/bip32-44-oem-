from coincurve   import PrivateKey #as ECPrivateKey
from binascii    import hexlify, unhexlify
from collections import deque
from hashlib     import new, sha256 as _sha256
import time
import sys
from sha3        import keccak_256

PUBKEY_HASH = b'\x00'
PRIVATE_KEY = b'\x80'
PRIVATE_KEY_COMPRESSED_PUBKEY = b'\x01'
SCRIPT_HASH = b'\x05'
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_ALPHABET_LIST = list(BASE58_ALPHABET)
BASE58_ALPHABET_INDEX = {char: index for index, char in enumerate(BASE58_ALPHABET)}

ZERO = b'\x00'
KEY_SIZE = 32

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

#util
def int_to_unknown_bytes(num, byteorder='big'):
    """Converts an int to the least number of bytes as possible."""
    return num.to_bytes((num.bit_length() + 7) // 8 or 1, byteorder)
def pad_scalar(scalar):
    return (ZERO * (KEY_SIZE - len(scalar))) + scalar
def pad_hex(hexed):
    # Pad odd-length hex strings.
    return hexed if not len(hexed) & 1 else '0' + hexed
if hasattr(int, "from_bytes"):
    def bytes_to_int(bytestr):
        return int.from_bytes(bytestr, 'big')
else:
    def bytes_to_int(bytestr):
        return int(bytestr.encode('hex'), 16)
if hasattr(int, "to_bytes"):
    def int_to_bytes(num):
        return num.to_bytes((num.bit_length() + 7) // 8 or 1, 'big')
    def int_to_bytes_padded(num):
        return pad_scalar(num.to_bytes((num.bit_length() + 7) // 8 or 1, 'big'))
else:
    def int_to_bytes(num):
        return unhexlify(pad_hex('%x' % num))
    def int_to_bytes_padded(num):
        return pad_scalar(unhexlify(pad_hex('%x' % num)))
if hasattr(bytes, "hex"):
    def bytes_to_hex(bytestr):
        return bytestr.hex()
else:
    def bytes_to_hex(bytestr):
        return ensure_unicode(hexlify(bytestr))
if hasattr(bytes, "fromhex"):
    def hex_to_bytes(hexed):
        return pad_scalar(bytes.fromhex(pad_hex(hexed)))
else:
    def hex_to_bytes(hexed):
        return pad_scalar(unhexlify(pad_hex(hexed)))






#hash funtion
def sha256(bytestr):
    r = _sha256(bytestr).digest()
#    print("sha256                   ",r.hex())
    return r
def double_sha256(bytestr):
    r = _sha256(_sha256(bytestr).digest()).digest()
#    print("double_sha256            ",r.hex())
    return r
def double_sha256_checksum(bytestr):
    r = double_sha256(bytestr)[:4]
#    print("double_sha256_checksum   ",r.hex())
    return r
def ripemd160_sha256(bytestr):
    r = new('ripemd160', sha256(bytestr)).digest()
#    print("ripemd160_sha256         ",r.hex(),sys.getsizeof(r))
    return r

def decompress_pubkey(pk):
    x = int.from_bytes(pk[1:33], byteorder='big')
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != pk[0] % 2:
        y = p - y
    y = y.to_bytes(32, byteorder='big')
    return b'\x04' + pk[1:33] + y

#print(unhexlify('0003a57b5886a19694cee77cf1133acfd2312e4caa79a6f930ce8193f0591a654a59'))
#print(hexlify(decompress_pubkey(unhexlify('02f15446771c5c585dd25d8d62df5195b77799aa8eac2f2196c54b73ca05f72f27'))).decode())
#base58encode
def b58encode(bytestr):
    alphabet = BASE58_ALPHABET_LIST
    encoded = deque()
    append = encoded.appendleft
    _divmod = divmod
    num = int.from_bytes(bytestr, 'big')
    while num > 0:
        num, rem = _divmod(num, 58)
        append(alphabet[rem])
    encoded = ''.join(encoded)
    pad = 0
    for byte in bytestr:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + encoded
def b58encode_check(bytestr):
    return b58encode(bytestr + double_sha256_checksum(bytestr))

#base58decode
def b58decode(string):
    alphabet_index = BASE58_ALPHABET_INDEX
    num = 0
    try:
        for char in string:
            num *= 58
            num += alphabet_index[char]
    except KeyError:
        raise ValueError('"{}" is an invalid base58 encoded '
                         'character.'.format(char)) from None
    bytestr = int_to_unknown_bytes(num)
    pad = 0
    for char in string:
        if char == '1':
            pad += 1
        else:
            break
    return b'\x00' * pad + bytestr

def b58decode_check(string):
    decoded = b58decode(string)
    shortened = decoded[:-4]
    decoded_checksum = decoded[-4:]
    hash_checksum = double_sha256_checksum(shortened)
    if decoded_checksum != hash_checksum:
        raise ValueError('Decoded checksum {} derived from "{}" is not equal to hash '
                         'checksum {}.'.format(decoded_checksum, string, hash_checksum))
    return shortened

#a = b58decode_check('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH')
#print("DECODE hash160",a[1:].hex())

#address
def public_key_to_address(version,public_key):
    #version = PUBKEY_HASH
    length = len(public_key)
    if length not in (33, 65):
        raise ValueError('{} is an invalid length for a public key.'.format(length))
    return b58encode_check(version + ripemd160_sha256(public_key))

def public_key_to_segwit_address(version,public_key):
    #version = SCRIPT_HASH
    length = len(public_key)
    if length != 33:
        raise ValueError('{} is an invalid length for a public key. Segwit only uses compressed public keys'.format(length))
    return b58encode_check(version + ripemd160_sha256(b'\x00\x14' + ripemd160_sha256(public_key)))

def ethereum_address(uncompressed_pub_key):
    eth_pub_key      = uncompressed_pub_key[1:]
    address          = keccak_256(eth_pub_key).hexdigest()[-40:]
    checksumed       = '0x'
    checksum_address = address.encode('utf-8')
    checksum_address = keccak_256(checksum_address).hexdigest()
    for i in range(len(address)):
        address_char = address[i]
        keccak_char = checksum_address[i]
        if int(keccak_char, 16) >= 8:
            checksumed += address_char.upper()
        else:
            checksumed += str(address_char)
    return checksumed

#WIF
def bytes_to_wif(private_key, compressed=False):
    prefix = PRIVATE_KEY
    if compressed:
        suffix = PRIVATE_KEY_COMPRESSED_PUBKEY
    else:
        suffix = b''
    private_key = prefix + private_key + suffix
    return b58encode_check(private_key)


#start_time = time.time()
#print("{0:.8f}".format((time.time()-start_time)))

#pub_ = ['03f5068dc5651e6a79b87d8ba0be63d1c96759c707b69ebbe1ac26d8fb69da4c93']
#for x in pub_:
    #x = int(x,16).hex()
    #print(type(x))
    #x = bytes.fromhex(x)
#    x = hex_to_bytes(x)
    #print("from int                 ",x)
    #_pk = PrivateKey.from_int(1)
    #pub_key_compressed = _pk.public_key.format(compressed=True)
    #print("pub_key_compressed       ",pub_key_compressed)
    #pub_key_uncompressed = _pk.public_key.format(compressed=False)
    #print("pub_key_uncompressed     ",pub_key_uncompressed.hex())

#    compressed_address = public_key_to_address(x)
#    print("compressed_address       ",compressed_address, sys.getsizeof(compressed_address))
#    segwit_address = public_key_to_segwit_address(x)
#    print("segwit_address           ",segwit_address, sys.getsizeof(segwit_address) )

    #uncompressed_address = public_key_to_address(x)
    #print("uncompressed_address     ",uncompressed_address,sys.getsizeof(uncompressed_address))

    #_wif = bytes_to_wif(_pk.secret, compressed=False)
    #print("priv_key_wif_uncompressed",_wif)

    #_wif = bytes_to_wif(_pk.secret, compressed=True)
    #print("priv_key_wif_compressed  ",_wif)

    #print("secret hex               ",_pk.secret.hex())
    #print("                                           ")
    #print("                                           ")

#a = '0000000000000000000000000000000000000000000000000000000000000001'
#a = int(a, 16)
#b = '0x5e'
#b = int(b, 16)
#print(a)
#print(b)
#print(a+b)

#https://bitcoin.stackexchange.com/questions/86234/how-to-uncompress-a-public-key
#print(int_to_bytes(111))
#hex(111).encode())
#print(bytes.fromhex('0x'+hex(111)))
#print(hex_to_bytes(hex(111).hex()))
#print(hex(196))
#print(int.from_bytes(bytestr, 'big'))
#print(type(PRIVATE_KEY))
#a = (111).to_bytes((((111).bit_length() + 7) // 8),"big").hex()
#print(hex_to_bytes(a))
#hex = '0x{:02x}'.format(1111111)
#print(hex(111))
#print(bytearray(hex.encode()))
#print(hex.to_bytes())
#print(struct.pack('B', 111))
#hex= hexlify(int_to_bytes(1111))

#print(struct.pack('B', hex))
#hex = '0x{:02x}'.format(hex)
#print(bytes.fromhex(hex(111)))

#a = struct.pack("B",111)
#print(chr(111))
#print(bytes.fromhex(chr(111)))
#print(codecs.encode(struct.pack("B",122),"hex"))
#print(struct.pack('>I', 111))
#hex = unhexlify('6f')
#print(hexlify(111))
#print(hex(50))
