# XXTEA in python 
import binascii
import hashlib
import struct

def p1_plaintext_to_number(plaintext):
    
    # convert the plaintext to numbers
    s = plaintext

    s += ' ' * ((4-len(s))%4)

    s_bytes = s.encode('utf-8')

    # Convert bytes to hex
    buf = binascii.hexlify(s_bytes).decode('utf-8')

    # We convert the hexadecimal string back to bytes
    s_bytes = binascii.unhexlify(buf)

    # We add padding to make the length a multiple of 4
    s_bytes += b'\0' * ((4 - len(s_bytes)) % 4)

    # We convert the bytes to integers
    v = list(struct.unpack('<' + 'I' * (len(s_bytes) // 4), s_bytes))
    
    return(v)

def p2_key_to_number(key):
    # Generate the MD5 hash of the string
    m = hashlib.md5()
    m.update(key.encode('utf-8'))
    # The result is a 128-bit key
    k = list(struct.unpack('<' + 'I' * (len(m.digest()) // 4), m.digest()))
    return(k)

def p3_xxtea_encrypt(v, k):
    # Define necessary constants
    DELTA = 0x9e3779b9
    n = len(v)
    q = 6 + 52 // n
    
    # Initial sum
    sum = 0
    # Initialize z as the last element of v
    z = v[n-1]
    
    # Encipher
    while q > 0:
        sum = (sum + DELTA) & 0xffffffff
        e = sum >> 2 & 3
        for p in range(n):
            y = v[(p+1)%n]
            z = v[p] = (v[p] + ((z>>5 ^ y<<2) + (y>>3 ^ z<<4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff
        q -= 1
    
    return v

def p3_xxtea_decrypt(v, k):
    # Define necessary constants
    DELTA = 0x9e3779b9
    n = len(v)
    q = 6 + 52 // n

    # Initial sum and z
    sum = (q * DELTA) & 0xffffffff
    y = v[0]
    
    # Decipher
    while q > 0:
        e = sum >> 2 & 3
        for p in reversed(range(n)):
            z = v[(p-1)%n]
            y = v[p] = (v[p] - ((z>>5 ^ y<<2) + (y>>3 ^ z<<4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff
        sum = (sum - DELTA) & 0xffffffff
        q -= 1

    return v

def p4_number_to_hex(encrypted_v):
    
    # convert int to bytes
    v_bytes = struct.pack('<' + 'I' * len(encrypted_v), *encrypted_v)

    # convert bytes to hex 
    ciphertext = str(v_bytes.hex()).upper()
    
    return(ciphertext)

def p5_hex_to_number(ciphertext):

    # convert hex to bytes
    s_bytes = binascii.unhexlify(ciphertext)

    # convert bytes to int
    s_bytes += b'\0' * ((4 - len(s_bytes)) % 4)

    # We convert the bytes to integers
    v = list(struct.unpack('<' + 'I' * (len(s_bytes) // 4), s_bytes))
    
    return(v)

def p6_number_to_plaintext(decrypted_v):
    
    # convert integer to bytes
    v_bytes = struct.pack('<' + 'I' * len(decrypted_v), *decrypted_v)
    # Decode the bytes to a string
    s = v_bytes.decode('utf-8')
    
    return(s.strip())

# TEST 
Unencrypted = ['152455', '152461', '152473', '123456789', '424024464', '123456789', 'Hello, my name is Phillip.']
key = 'ABCD'

plaintext = Unencrypted[1]

v = p1_plaintext_to_number(plaintext)
k = p2_key_to_number(key)

print("v = ", v)
print("k = ", k)

print("\n")

print("Plaintext: ", plaintext)
# test encrypt function
encrypted = p4_number_to_hex(p3_xxtea_encrypt(v=p1_plaintext_to_number(plaintext),k=p2_key_to_number(key)))
print('Enciphered: ', encrypted)

decrypted = p6_number_to_plaintext(p3_xxtea_decrypt(v=p5_hex_to_number(encrypted),k=p2_key_to_number(key)))
print('Deciphered: ', decrypted)