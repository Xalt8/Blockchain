from Crypto.PublicKey import RSA

key = RSA.generate(2048)

print(f"key -> {key}")
print(f"public key -> {key.public_key()}")


# Save the key to disk
with open('mykey.pem', 'wb') as f:
    f.write(key.export_key('PEM'))