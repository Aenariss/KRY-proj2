## KRY Projekt 2 - Client code
## Author: Vojtech Fiala <xfiala61>

from utils import generateKey, readKey, generateHash, RSApadding, getRandomKey
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import socket

HOST="localhost"

def startConnection(port):
    global HOST
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # ipv4, tcp
    sock.connect((HOST, port)) # connect to server
    return sock

def startClient(port):

    generateKey("client_key")

    pub_key = readKey("client_key.pub")
    priv_key = readKey("client_key")

    while True:
        
        sock = startConnection(port)

        server_pub_key = RSA.importKey(sock.recv(len(pub_key.export_key()))) # receive a length of a pub key - that should be constant and match the size of client pubkey
        # to be especially correct, public key shoudl be ccertified by a higher level public key to make a chain of trust, but I dont really have a higher authority key now, do I
        sock.send(pub_key.export_key())   

        message = input("Enter input: ")

        msg_hash = generateHash(message)
        msg_hash = int("0x" + msg_hash.hexdigest(), base=16) # convert hex hash to itneger
        padded_hash = RSApadding(msg_hash, 2048) # 2048 bits of RSA key

        aes_key = getRandomKey(16) # get random key from /dev/urandom that is 128 bits long, so thats 16 bytes
        cipher = AES.new(aes_key, AES.MODE_EAX)

        print_aes = int.from_bytes(aes_key, "big")
        padded_key = RSApadding(print_aes, 2048)

        print("AES_key=%x\n" % print_aes)
        print("AES_key_padding=%x\n" % padded_key)
        print("MD5=%x\n" % msg_hash)
        print("MD5_padding=%x\n" % padded_hash)
        
        signature = pow(padded_hash, priv_key.d, priv_key.n) # s = m^d % n

        msg_to_encode = message + "'" + str(signature) # add ' between message and signature to difference between those two

        encoded_text, _ = cipher.encrypt_and_digest(msg_to_encode.encode())

        encrypted_key = pow(padded_key, server_pub_key.e, server_pub_key.n) # c = m^e % n

        everything_encoded = (encoded_text + "'".encode() + str(encrypted_key).encode() + "'".encode() + str(int.from_bytes(cipher.nonce, "big")).encode()) # add ' to find where the key ends

        print("RSA_MD5_hash=%x\n" % signature)
        print("AES_cipher=%s\n" % str(encoded_text))
        print("RSA_AES_key=%x\n" % encrypted_key)
        print("ciphertext=%s\n" % str(everything_encoded))

        sock.sendall(everything_encoded)
        result = sock.recv(1024) # wait for server answer
        print(result.decode())

        sock.close()
        