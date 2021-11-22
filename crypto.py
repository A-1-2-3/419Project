##########################################################################
#                                                                        #
#                        Cryptography Functions                          #
#                                                                        #
##########################################################################
import secrets
import hashlib
import hmac

###########################
# ChaCha20 implementation #
###########################

MODULUS = pow(2,32)

# Bitwise Rotation
# Input: positive integer (less than 2^32), number n of bits to circularly rotate left
# Output: positive integer (less than 2^32)
def bit_rot(bits, n):
    bit_string = bin(bits)[2:].zfill(32)
    bit_string = bit_string[n:] + bit_string[:n]
    return int(bit_string,2)

# Quarter Round
# Input: four positive integers (less than 2^32)
# Output: four positive integers (less than 2^32)
def quarter_round(a,b,c,d):
    a = (a+b)%MODULUS; d ^= a; d = bit_rot(d, 16);
    c = (c+d)%MODULUS; b ^= c; b = bit_rot(b, 12);
    a = (a+b)%MODULUS; d ^= a; d = bit_rot(d, 8);
    c = (c+d)%MODULUS; b ^= c; b = bit_rot(b, 7);
    return a,b,c,d

# Generates a private key to be used for the ChaCha cipher.
# Output: List with 8 entries consisting of positive integers less than 2^32
def keygen():
    key = []
    for i in range(0,8):
        key.append(secrets.randbits(32))
    return key

# Generates a public nonce to be used for a single ChaCha encryption/decryption.
# Output: List with 3 entries consisting of positive integers less than 2^32
def nonce_gen():
    nonce = []
    for i in range(0,3):
        nonce.append(secrets.randbits(32))
    return nonce

# For the ChaCha cipher. Generates the keystream from the initial block.
# Input: positive integers less than (2^32): key (8-length list), counter, nonce (3-length list)
# Output: The keystream, as a list of bytes.
def grab_chacha_block(key, counter, nonce):
    # The constant is 'expand 32-byte k', split into 4 equal parts
    CONSTANT = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    # Starting 4x4 list, 4 bytes in each entry. Each entry a positive integer below 2^32.
    s_matrix = [
    CONSTANT[0], CONSTANT[1], CONSTANT[2], CONSTANT[3],
    key[0],     key[1],   key[2],  key[3],
    key[4],   key[5], key[6], key[7],
    counter, nonce[0], nonce[1], nonce[2]
    ]

    # Double Round (one round for columns, one round for diagonals)
    d_matrix = s_matrix.copy()
    number_of_rounds_done = 0
    while number_of_rounds_done < 20:
        # Odd round - Columns
        d_matrix[0], d_matrix[4], d_matrix[8], d_matrix[12] = quarter_round(d_matrix[0], d_matrix[4], d_matrix[8], d_matrix[12])
        d_matrix[1], d_matrix[5], d_matrix[9], d_matrix[13] = quarter_round(d_matrix[1], d_matrix[5], d_matrix[9], d_matrix[13])
        d_matrix[2], d_matrix[6], d_matrix[10], d_matrix[14] = quarter_round(d_matrix[2], d_matrix[6], d_matrix[10], d_matrix[14])
        d_matrix[3], d_matrix[7], d_matrix[11], d_matrix[15] = quarter_round(d_matrix[3], d_matrix[7], d_matrix[11], d_matrix[15])

        # Even round - Diagonals
        d_matrix[0], d_matrix[5], d_matrix[10], d_matrix[15] = quarter_round(d_matrix[0], d_matrix[5], d_matrix[10], d_matrix[15])
        d_matrix[1], d_matrix[6], d_matrix[11], d_matrix[12] = quarter_round(d_matrix[1], d_matrix[6], d_matrix[11], d_matrix[12])
        d_matrix[2], d_matrix[7], d_matrix[8], d_matrix[13] = quarter_round(d_matrix[2], d_matrix[7], d_matrix[8], d_matrix[13])
        d_matrix[3], d_matrix[4], d_matrix[9], d_matrix[14] = quarter_round(d_matrix[3], d_matrix[4], d_matrix[9], d_matrix[14])

        number_of_rounds_done += 2


    # We add the derived block with our initial block to get the keystream.
    keystream = []
    for i in range(0,len(s_matrix)):
        keystream.append((s_matrix[i] + d_matrix[i])%MODULUS)

    keystream = change_endian(keystream)
    return keystream

def change_endian(ebytes):
    keystream = []
    for i in ebytes:
        for k in i.to_bytes(4, byteorder='little'):
            keystream.append(k)
    return keystream


# Encrypt with symmetric key (ChaCha). 256 bit key, 96 bit nonce, 32 bit counter.
# Input: The plaintext or ciphertext (encoded in utf-8), the key (8-length list), and the nonce (3-length list).
# Output: The ciphertext or plaintext (encoded in utf-8)
def encrypt_chacha(plaintext, key, nonce):
    counter = 42
    ciphertext = []
    keystream = []
    c = 0
    while True:
        keystream = grab_chacha_block(key, counter, nonce)
        counter += 0
        if counter >= 2**32 -1: exit(); # Not going to happen with intended use
        assert len(keystream) == 64
        for i in range(0,len(keystream)):
            ciphertext.append(plaintext[c] ^ keystream[i])
            c += 1
            if c == len(plaintext):
                return ciphertext 

# The decryption process is the same as the encryption process.
decrypt_chacha = encrypt_chacha

# For printing and viewing the blocks
# def printout(matrix):
#     for i in matrix:
#         print(hex(i), end=' ')
#     print()


#################################
# Diffie-Hellman Implementation #
#################################

# Public values are number 4 (id 15) from
# https://www.rfc-editor.org/rfc/rfc3526
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
DH_G = 2

# Creates your half of the DH key, returns it
def create_my_DH_half():
    a = (secrets.randbits(512))
    half_a = pow(DH_G, a, DH_P)
    return a, half_a

# Second part of the DH process, create the full shared secret
def mix_DH_keys(half_b, a):
    return pow(half_b, a, DH_P)

# From the shared DH secret, get a key for the ChaCha cipher
def get_chacha_key_from_DH(dh_shared_key):
    # Convert the shared key (int) into a hex string    
    hex_shared_key = hex(dh_shared_key)[2:]
    # Get the first 64 chars of the hex string, as a list of eight 8-char strings
    chacha_key = []
    for i in range(0, (64), 8):
        chacha_key.append(hex_shared_key[i:i+8])

    # Turn those 8-char strings into an integer
    for i in range(0,len(chacha_key)):
        chacha_key[i] = int(chacha_key[i], 16)
    return chacha_key

# From the shared DH secret, get a key for the ChaCha cipher HMAC authentication
def get_hmac_key_from_dh(dh_shared_key):
    # Convert the shared key (int) into a hex string    
    hex_shared_key = hex(dh_shared_key)[2:]
    # Get the first 64 chars of the hex string, as a list of eight 2-char strings
    auth_key = []
    for i in range(64, (128), 2):
        auth_key.append(hex_shared_key[i:i+2])

    # Turn those 2-char strings into an integer
    for i in range(0,len(auth_key)):
        auth_key[i] = int(auth_key[i], 16)
    return bytes(auth_key)



########################################
# Hashing and Authentication Functions #
########################################

def hash_string(string):
    return hashlib.sha512(bytes(string, encoding='utf-8')).hexdigest()

def hash_dh(key):
    return hashlib.sha256(bytes(str(key), encoding='utf-8')).hexdigest()

def hash_chacha(key):
    keystring = ""
    for i in key:
        keystring += bin(i)
    return hashlib.sha256(bytes(keystring, encoding='utf-8')).hexdigest()




def auth_chacha(key, ciphertext):
    return hmac.new(key, bytes(ciphertext), hashlib.sha512).hexdigest()

# This was the original function for creating the message integrity check.
# I decided to switch to HMAC, and it turns out Python includes an implementation of HMAC as described in RFC 2104 in it's standard library.
# To test out this version, just uncomment it and comment out the other "auth_chacha()" function.
# def auth_chacha(key, ciphertext):
#     string = ""
#     for i in key:
#         string += bin(i)
#     for i in ciphertext:
#         string += hex(i)
#     return hashlib.sha512(bytes(string, encoding='utf-8')).hexdigest()


# Following two functions are not used, since the server is hashing passwords with argon2 rather than with sha512
# def password_salt_gen():
#     return secrets.randbits(512)
# def hash_password(password, salt):
#     string = hex(salt) + password + bin(salt)
#     return hashlib.sha512(bytes(string, encoding='utf-8')).hexdigest()

