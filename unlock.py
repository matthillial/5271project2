#!/usr/bin/env python3
import sys
import os
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from os import walk

# Params:: <dir to lock>, <public key>, <private key>, <subject>
# dir to lock:  Directory the AES verify/decryption will happen
# public key:   Public key of the sender
# private key:  Own Private key (unlocking party)
# subject:      Name of current unlocking party

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
        print("Usage: ./unlock -d <dir to unlock> -p <public key> -r <private key> -s <subject>\n")
        sys.exit("Missing value for arg \"" + arg_names[j] + "\".")
# Extract args into variables
directory = arg_values[0]
public_filename = arg_values[1]
private_filename = arg_values[2]
subject = arg_values[3]
# Open and tokenize certificates by line
public_file = open(public_filename, "rb")
public = public_file.read()
public_file.close()
private_file = open(private_filename, "rb")
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

############################ Verify subject ####################################

# Validate subject matches public certificate
if subject != public_tokens[1]:
    sys.exit("Subject does not match public certificate")
print("(1) Successfully verify the subject")

################### Verify the integrity of the message ########################

# Use sender's Public key to verify the signature
public_key = RSA.import_key(public_key_text)
# Read the signature
keyfilesig = open(directory + "/keyfile.sig", "rb")
signature = keyfilesig.read()
keyfilesig.close()
# Read the keyfile
keyfile = open(directory + "/keyfile", "rb")
# Part of next step: Use private_key to decrypt the message
private_key = RSA.import_key(private_key_text)
enc_session_key, nonce, tag, ciphertext = [ keyfile.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
keyfile.close()
# verify the signature
x = enc_session_key+nonce+tag+ciphertext
h = SHA256.new(x)
try:
    pkcs1_15.new(public_key).verify(h, signature)
    print("(2) Successfully verify the integrity of keyfile")
except (ValueError, TypeError):
    print("(2) Verification fails")
    exit()

################## Decrypt the message to extract the AES key ##################

# Use own Private key to decrypt the message (private key fetched before)
# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)
# Decrypt the data with the session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
key_AES = cipher_aes.decrypt_and_verify(ciphertext, tag)
print("(3) Successfully decrypt the AES key")

###################### Delete keyfile and keyfile.sig ##########################

if os.path.exists(directory+"/keyfile"):
  os.remove(directory+"/keyfile")
if os.path.exists(directory+"/keyfile.sig"):
  os.remove(directory+"/keyfile.sig")
print("(4) Successfully delete keyfile and keyfile.sig")

###################### Verify and decrypt the directory ########################

# Helper function to verify and decrypt one ciphertext
def AESVerifyAndDecrypt(ciphertext, key):
    try:
        b64 = json.loads(ciphertext)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k:b64decode(b64[k]) for k in json_k}
        cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        return plaintext.decode()
    except (ValueError, TypeError):
        print("Incorrect AES decryption")
        exit()

# Verift and Decrypt all files
f = []
for (dirpath, dirnames, filenames) in walk(directory):
    f.extend(filenames)
    for filename in filenames:
        fullfilename = dirpath+"/"+filename
        # read this file, verify the contenct, decrypt and write back the plaintext
        file = open(fullfilename, "rb+")
        ciphertext = file.read()
        plaintext = AESVerifyAndDecrypt(ciphertext.decode(), key_AES)
        # plaintext overwritten back to file
        file.seek(0)
        file.truncate()
        file.write(plaintext.encode())
        file.close()
print("(5) Successfully verify/decrypt the directory")
