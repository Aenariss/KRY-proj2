## KRY Projekt 2 - Client code
## Author: Vojtech Fiala <xfiala61>

import socket
from utils import generateKey, readKey, formatKeyPrint, RSAunpadding, generateHash
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

def parseKey(message):
    tmp = str(message)[::-1]
    key = []
    nonce = []
    it = 1
    
    while it < len(tmp):
        if tmp[it] == "'":
            break
        nonce.append(tmp[it])
        it += 1
    
    it += 1
    while it < len(tmp):
        if tmp[it] == "'":
            break
        key.append(tmp[it])
        it += 1

    if key[0] == '\\': # i have no idea why sometimes this appears, sometimes doesnt, this fixes it
        key = key[1:] 
    new_message = message[::-1]
    new_message = new_message[it-1:]
    new_message = new_message[::-1]
    
    return ''.join(nonce[::-1]), ''.join(key[::-1]), new_message

def getTextAndSig(text):
    text = text.decode('utf-8', 'ignore')

    text = text[::-1]
    l = len(text)

    i = 0
    while i < l:
        if text[i] == "'":
            break
        i += 1

    msg = text[i+1:][::-1]
    signature = text[:i][::-1]

    if not signature[0].isnumeric(): # i have no idea why sometimes this appears, sometimes doesnt, this fixes it
        signature = signature[1:] 
    if not signature[-1].isnumeric(): # i have no idea why sometimes this appears, sometimes doesnt, this fixes it
        signature = signature[:-1] 

    return msg, int(signature)

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
    if given_hash == myHash:
        print("The integrity of the message has not been compromised.\n")
        connection.send("The message was successfully delivered\n".encode())
    else:
        print("WARNING!!! The integrity of the message has been COMPROMISED.\n")
        connection.send("Error with message integrity, please send again!\n".encode())
