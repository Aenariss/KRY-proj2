## KRY Projekt 2 - Client code
## Author: Vojtech Fiala <xfiala61>

from Crypto.PublicKey import RSA
from os import path, mkdir, urandom
from Crypto.Hash import MD5

CERT_FOLDER = "certs"

def readKey(filename):
    key_loc = path.join(CERT_FOLDER, filename)
    f = open(key_loc, 'r')
    key = RSA.import_key(f.read())
    f.close()
    return key

# function to generate a RSA with a given filename key if it doesnt exist
def generateKey(filename):

    def writeKey(key, name):
        f = open(name,'wb')
        f.write(key.export_key('PEM'))
        f.close()

    global CERT_FOLDER
    
    if not (path.isdir(CERT_FOLDER)): # if folder doesnt exists, create it
        mkdir(CERT_FOLDER)

    key_loc = path.join(CERT_FOLDER, filename)
    if not (path.exists(key_loc) and path.exists(key_loc + ".pub")): # create new keypair if it doesnt exist already
        priv_key = RSA.generate(2048) # 2048 bit RSA
        pub_key = priv_key.public_key()

        writeKey(priv_key, key_loc)
        writeKey(pub_key, key_loc + ".pub")

def formatKeyPrint(key):
    key = key.decode('utf-8') # byte to string
    key = key.split('\n') # spit by newline
    key = ''.join(key[1:-1]) # remove headers and join together
    return key

def generateHash(message):
    message_hash = MD5.new() # 128bit md5
    message_hash.update(message.encode('UTF-8'))
    return message_hash

# Function to add padding to the hash so that the hash is the same length as the key
def RSApadding(hash, key_len):
    
    binary_hash = format(hash, 'b')

    binary_hash = list(binary_hash)

    base_len = len(binary_hash)
    # until I reach the designated length of the RSA key, add padding
    # lets add 1 anmd then all 0 (same as md5 hash)

    prepend = []

    while base_len < key_len-3: # until I reach the RSA length-3 (cuz of the 0s that end the padding), add 1s
        prepend.append('1')
        base_len += 1

    prepend.append('0')
    prepend.append('0')

    binary_hash = prepend + binary_hash
    binary_hash = ''.join(binary_hash)
    return int(binary_hash, 2)

def RSAunpadding(msg):

    binary_msg = str(format(msg, 'b'))

    new_msg = []
    add_now = False
    for i in range(len(binary_msg)):

        if add_now:
            new_msg.append(binary_msg[i])

        if i > 1:
            if binary_msg[i-1] == '0' and binary_msg[i] == '0':
                add_now = True


    binary_no_prep = ''.join(new_msg)

    return int(binary_no_prep, 2)

def getRandomKey(size):
    return urandom(size)
