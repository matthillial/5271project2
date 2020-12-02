#!/usr/bin/env python
import sys
from Crypto.Cipher import AES

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

key = "testkey890123456"
iv = "0000000000000000"
data = "secret"
cipher = AES.new(key, AES.MODE_GCM, iv)
ciphertext, tag = cipher.encrypt_and_digest(data)
print(ciphertext)
print(tag)
cipher = AES.new(key, AES.MODE_GCM, iv)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)
