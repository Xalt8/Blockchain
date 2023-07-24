from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Signature import pkcs1_15

# Created keys using RSA algorithm
key = RSA.generate(2048)
print(f"Memory address ->  {key}\n")

private_key = key.export_key('PEM')
print(f"private_key -> {private_key.decode()}\n")

public_key = key.public_key().export_key('PEM')
print(f"public key -> {public_key.decode()}")

# Save the key to disk
with open('mykey.pem', 'wb') as f:
    f.write(key.export_key('PEM'))

# Read the key from disk
with open('mykey.pem', 'r') as f2:
    read_key = RSA.import_key(f2.read())

# Make the keys human readable
read_private_key = read_key.export_key('PEM')
read_public_key = read_key.public_key().export_key('PEM')

# Check to see if the keys read-in are the same as the ones created
assert read_private_key.decode() == private_key.decode(), "The key read from file is different"
assert read_public_key.decode() == public_key.decode(), "The key read from file is different"

# Create a message
plainText1 = b"Hello World"
# Hash the message
hashed_message1 = SHA256.new(plainText1)
print(f"\nmessage -> {plainText1}\nhashed_message digest-> {hashed_message1.digest()}\n")

plainText2 = b"hello world"
hashed_message2 = SHA256.new(plainText2)
print(f"\nmessage -> {plainText2}\nhashed_message digest-> {hashed_message2.digest()}\n")


# Digitally sign the hashed message using the private key
digitalSignature = pkcs1_15.new(key).sign(hashed_message1)
print(f"digitalSignature ->\n{digitalSignature}\n")


def verify_message(message_hash: SHA256Hash, public_key:RsaKey, digital_sig:bytes) -> bool:
    """ Takes a message hash and a digital signature and returns True 
        if the message matches the signature """
    try:
        pkcs1_15.new(public_key).verify(message_hash, digital_sig)
        return True
    except ValueError:
        return False


assert verify_message(message_hash= hashed_message1, 
                      public_key= RSA.import_key(read_public_key), 
                      digital_sig= digitalSignature), "Message was not verified"

assert not verify_message(message_hash= hashed_message2, 
                          public_key= RSA.import_key(read_public_key), 
                          digital_sig= digitalSignature), "Message was not verified"

print("Everything is working")