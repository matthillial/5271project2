#!/usr/bin/env python
import sys
from Crypto.PublicKey import RSA

# Params: <subject> <public key file> <private key file>
# subject: name of party
# public key file: file to store its public key (certificate)
# private key file: file to store its private key (certificate)

# Take parameters
arg_names = ["-s", "-pub", "-priv"]
arg_values = ["", "", ""]

for i in range(len(sys.argv)):
    for j in range(len(arg_names)):
        if sys.argv[i] == arg_names[j] and i < len(sys.argv) - 1:
            arg_values[j] = sys.argv[i + 1]
            i = i + 1
            break

for j in range(len(arg_names)):
    if arg_values[j] == "":
        print("Usage: ./keygen -s <subject> -pub <public key file> -priv <private key file>\n")
        sys.exit("Missing value for arg \"" + arg_names[j] + "\".")

subject = arg_values[0]
public_filename = arg_values[1]
private_filename = arg_values[2]

# Generate RAS public/private key pair
key = RSA.generate(2048)
# Write private key file
private_key = key.export_key()
file_out = open(private_filename, "wb")
file_out.write("SUBJECT:\n".encode() + subject.encode() + "\nALGORITHM:\nRSA\n".encode())
file_out.write(private_key)
file_out.close()
# Write public key file
public_key = key.publickey().export_key()
file_out = open(public_filename, "wb")
file_out.write("SUBJECT:\n".encode() + subject.encode() + "\nALGORITHM:\nRSA\n".encode())
file_out.write(public_key)
file_out.close()

print("Successfully generate public/private key for "+subject)
