## KRY Projekt 2 - Client code
## Author: Vojtech Fiala <xfiala61>

import socket
from utils import generateKey, readKey, formatKeyPrint, RSAunpadding, generateHash, getRandomKey, RSApadding, parseKey, getTextAndSig
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

HOST="localhost" # loopback

def startServer(port):
    global HOST
 
    generateKey("server_key") # if the key does not exist, this takes a bit of time

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # lets use ipv4 and TCP
    sock.bind((HOST, port))
    sock.listen() # wait for a client
    first = 1
    while True:
        connection, _ = sock.accept()

        handleClient(connection, first)
        first = 0


def hashes(msg, given_hash, client_pub_key):

    given_hash = pow(given_hash, client_pub_key.e, client_pub_key.n) # decrypt signature - m = s^e % n
    given_hash = RSAunpadding(int(given_hash)) # remove padding

    new_hash = generateHash(msg)
    new_hash = int("0x" + new_hash.hexdigest(), base=16)

    return new_hash, given_hash


def handleClient(connection, first):

    priv_key = readKey("server_key")
    pub_key = readKey("server_key.pub")

    # send server pubkey to client
    connection.send(pub_key.export_key())   

    #receive clients pub key
    client_pub_key = RSA.importKey(connection.recv(len(pub_key.export_key()))) # receive a length of a pub key - that should be constant and match the size of client pubkey

    data = connection.recv(16384)
    if not data: 
        return

    nonce, key, rest = parseKey(data)
    key = int(key)
    nonce = int(nonce)
    nonce = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
    
    aes_key = pow(key, priv_key.d, priv_key.n) # encrypted aes key, decrypt it - m = c^d % n
    aes_key = RSAunpadding(aes_key)

    if first:
        print("Client has joined")
        print("RSA_public_key_sender=%s\n" % formatKeyPrint(pub_key.export_key()))
        print("RSA_private_key_sender=%s\n" % formatKeyPrint(priv_key.export_key()))
        print("RSA_public_key_receiver=%s\n" % formatKeyPrint(client_pub_key.export_key()))
    print("ciphertext=%s\n" % str(data))
    print("RSA_AES_key=%x\n" % key)
    print("AES_cipher=%s\n" % str(rest))
    print("AES_key=%x\n" % aes_key)

    cipher = AES.new(aes_key.to_bytes(16, "big"), AES.MODE_EAX, nonce=nonce)
    text_hash = cipher.decrypt(rest)
    
    print("text_hash=%s\n" % str(text_hash))

    msg, signature = getTextAndSig(text_hash)

    print("plaintext=%s" % msg)

    myHash, given_hash = hashes(msg, signature, client_pub_key)

    print("MD5=%x\n" % myHash)

    # no integrity damage
    response = "The integrity of the message has not been compromised." + "'" + str(signature)
    bad_resp = "WARNING! Integrity was compromised." + "'" + str(signature)

    aes_key = getRandomKey(16) # get random key from /dev/urandom that is 128 bits long, so thats 16 bytes
    padded_key = RSApadding(int.from_bytes(aes_key, "big"), 2048)
    encrypted_key = pow(padded_key, client_pub_key.e, client_pub_key.n)
    cipher = AES.new(aes_key, AES.MODE_EAX)
    key_nonce = "'" + str(encrypted_key) + "'" + str(int.from_bytes(cipher.nonce, "big"))

    response, _ = cipher.encrypt_and_digest(response.encode())
    cipher = AES.new(aes_key, AES.MODE_EAX)
    key_nonce_bad = "'" + str(encrypted_key) + "'" + str(int.from_bytes(cipher.nonce, "big"))

    bad_resp, _ = cipher.encrypt_and_digest(bad_resp.encode())

    encoded_resp = (response + key_nonce.encode()) # add ' to find where the key ends
    encoded_bad_resp = (bad_resp + key_nonce_bad.encode()) # add ' to find where the key ends

    if given_hash == myHash:
        print("The integrity of the message has not been compromised.\n")
        connection.send(encoded_resp)
    else:
        print("WARNING!!! The integrity of the message has been COMPROMISED.\n")
        connection.send(encoded_bad_resp)
