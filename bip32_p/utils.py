#from coincurve   import PrivateKey
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
    return r
def double_sha256(bytestr):
    r = _sha256(_sha256(bytestr).digest()).digest()
    return r
def double_sha256_checksum(bytestr):
    r = double_sha256(bytestr)[:4]
    return r
def ripemd160_sha256(bytestr):
    r = new('ripemd160', sha256(bytestr)).digest()
    return r

def decompress_pubkey(pk):
    x = int.from_bytes(pk[1:33], byteorder='big')
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != pk[0] % 2:
        y = p - y
    y = y.to_bytes(32, byteorder='big')
    return b'\x04' + pk[1:33] + y

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


#address
def public_key_to_address(version,public_key):
    length = len(public_key)
    if length not in (33, 65):
        raise ValueError('{} is an invalid length for a public key.'.format(length))
    return b58encode_check(version + ripemd160_sha256(public_key))

def public_key_to_segwit_address(version,public_key):
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



