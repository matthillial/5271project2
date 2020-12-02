#!/usr/bin/env python
import sys
from Crypto.PublicKey import RSA

arg_names = ["-s", "-pub", "-priv"]
arg_values = ["", "", ""]

for i in range(len(sys.argv)):
    for j in range(len(arg_names)):
        if sys.argv[i] == arg_names[j] and i < len(sys.argv) - 1:
            arg_values[j] = sys.argv[i + 1]
            i = i + 1
            break


for j in range(len(arg_names)):
    #print("arg " + arg_names[j] + " = " + arg_values[j])
    if arg_values[j] == "":
        sys.exit("Missing value for arg \"" + arg_names[j] + "\".")


subject = arg_values[0]
public_filename = arg_values[1]
private_filename = arg_values[2]

key = RSA.generate(2048)
#print("Key: " + key + "\n")
private_key = key.exportKey()
#print("Key obj: " + private_key + "\n")
file_out = open(private_filename, "wb")
file_out.write("SUBJECT:\n" + subject + "\nALGORITHM:\nRSA\n")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().exportKey()
file_out = open(public_filename, "wb")
file_out.write("SUBJECT:\n" + subject + "\nALGORITHM:\nRSA\n")
file_out.write(public_key)
file_out.close()
