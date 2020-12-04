import sys
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from os import walk

# Params: <dir to lock>, <public key>, <private key>, <subject>
# dir to lock:  Directory the AES encryption/sign will happen
# public key:   Public key of receipient
# private key:  Own Private key (locking party)
# subject:      Name of current locking party

################################# Prep #########################################
arg_names = ["-d", "-p", "-r", "-s"]
arg_values = ["", "", "", ""]
# Extract command line args into arg_values
for i in range(len(sys.argv)):
    for j in range(len(arg_names)):
        if sys.argv[i] == arg_names[j] and i < len(sys.argv) - 1:
            arg_values[j] = sys.argv[i + 1]
            i = i + 1
            break
# Check for missing args
for j in range(len(arg_names)):
    if arg_values[j] == "":
        print("Usage: ./lock -d <dir to lock> -p <public key> -r <private key> -s <subject>\n")
        sys.exit("Missing value for arg \"" + arg_names[j] + "\".")
# Extract args into variables
directory = arg_values[0]
public_filename = arg_values[1]
private_filename = arg_values[2]
subject = arg_values[3]
# Open and tokenize certificates by line
public_file = open(public_filename, "rb")
private_file = open(private_filename, "rb")
public = public_file.read()
public_file.close()
private = private_file.read()
private_file.close()
public_tokens = public.decode().split("\n")
private_tokens = private.decode().split("\n")
# Reconstruct the public/private key format
public_key_text = public_tokens[4] + "\n"
for x in range(5, len(public_tokens)):
    public_key_text += public_tokens[x] + "\n"
private_key_text = private_tokens[4] + "\n"
for x in range(5, len(private_tokens)):
    private_key_text += private_tokens[x] + "\n"

# Generate the asymmetic AES key to be shared
key_AES = get_random_bytes(16)

############################ Verify subject ####################################

# Validate subject matches public certificate
if subject != public_tokens[1]:
    sys.exit("Subject does not match public certificate")
print("(1) Successfully verify the subject")

############################ Encrypt AES key ###################################

# Use the receipiant's Public key to encrypt the AES key
public_key = RSA.import_key(public_key_text)
session_key = get_random_bytes(16)
# Encrypt the session key
cipher_rsa = PKCS1_OAEP.new(public_key)
enc_session_key = cipher_rsa.encrypt(session_key)
# Encrypt the data with the session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(key_AES)
# Write encrypted asymmetric key into file
x = enc_session_key+cipher_aes.nonce+tag+ciphertext
keyfile = open("keyfile", "wb")
keyfile.write(x)
keyfile.close()
print("(2) Successfully encrypt the message")

############################ Sign the encrypted AES key ########################

# Use own Private key to sign the message
private_key = RSA.import_key(private_key_text)
h = SHA256.new(x)
signature = pkcs1_15.new(private_key).sign(h)
# write the signature into keyfile.sig
keyfilesig = open("keyfile.sig", "wb")
keyfilesig.write(signature)
keyfilesig.close()
print("(3) Successfully sign the message")

############################ Synmmetric AES key ################################

# Helper function to encrypt and tag one plaintext
def AESEncryptAndSign(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    header = b"header"
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # construct encryption and tag message
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode() for x in (cipher.nonce, header, ciphertext, tag) ]
    result = json.dumps(dict(zip(json_k, json_v)))
    return result.encode()

# Encrypt and Sign all files specified in directory
f = []
for (dirpath, dirnames, filenames) in walk(directory):
    f.extend(filenames)
    # operate all files at current directpry
    for filename in filenames:
        fullfilename = dirpath+"/"+filename
        # read this file, encrypt the contenct, sign and write back the ciphertext
        file = open(fullfilename, "rb+")
        plaintext = file.read()
        ciphertest = AESEncryptAndSign(plaintext, key_AES)
        # ciphertext overwritten back to file
        file.seek(0)
        file.truncate()
        file.write(ciphertest)
        file.close()
print("(4) Successfully encrypt/sign the directory")
