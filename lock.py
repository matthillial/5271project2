#!/usr/bin/env python
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

testKey = RSA.generate(2048)

arg_names = ["-d", "-p", "-r", "-s"]
arg_values = ["", "", "", ""]

for i in range(len(sys.argv)):
    for j in range(len(arg_names)):
        if sys.argv[i] == arg_names[j] and i < len(sys.argv) - 1:
            arg_values[j] = sys.argv[i + 1]
            i = i + 1
            break

for j in range(len(arg_names)):
    #print("arg " + arg_names[j] + " = " + arg_values[j])
    if arg_values[j] == "":
        print("Usage: ./lock -d <dir to lock> -p <public key> -r <private key> -s <subject>\n")
        sys.exit("Missing value for arg \"" + arg_names[j] + "\".")

directory = arg_values[0]
public_filename = arg_values[1]
private_filename = arg_values[2]
subject = arg_values[3]

public_file = open(public_filename, "rb")
private_file = open(private_filename, "rb")
public = public_file.read()
private = private_file.read()
public_tokens = public.split("\n")
private_tokens = private.split("\n")

#extract public and private keys from certificates
public_key_text = public_tokens[4] + "\n"
for x in range(5, len(public_tokens)):
    public_key_text += public_tokens[x] + "\n"
print(public_key_text)
public_key = RSA.import_key(public_key_text)
private_key_text = private_tokens[4] + "\n"
for x in range(5, len(private_tokens)):
    private_key_text += private_tokens[x] + "\n"

#generate AES key and encode it with public key
key = get_random_bytes(16)
print(key)
cipher_rsa = PKCS1_OAEP.new(public_key)
enc_key = cipher_rsa.encrypt(key)

keyfile = open("keyfile", "wb")
keyfile_sig = open("keyfile.sig", "wb")
keyfile.write(enc_key)
keyfile_sig.write(private_key_text)



iv = "0000000000000000"
data = "secret"
cipher = AES.new(key, AES.MODE_GCM, iv)
# cipher = AES.new(RSAkey, AES.MODE_GCM, iv)
# plaintext = cipher.decrypt_and_verify(ciphertext, tag)
# print(plaintext)
