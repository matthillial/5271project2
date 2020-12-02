#!/usr/bin/env python
import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

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

public_file = open(public_filename, "r")
private_file = open(private_filename, "r")
public = public_file.read()
private = private_file.read()
public_tokens = public.split("\n")
private_tokens = private.split("\n")
# print(public_tokens)
# print(private_tokens)

key = public_tokens[5]
for x in range(6, len(public_tokens)-1):
    key += public_tokens[x]

RSAkey = RSA.import_key(key)

iv = "0000000000000000"
data = "secret"
cipher = AES.new(RSAkey, AES.MODE_GCM, iv)
ciphertext, tag = cipher.encrypt_and_digest(data)
print(ciphertext)
print(tag)
cipher = AES.new(RSAkey, AES.MODE_GCM, iv)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)
