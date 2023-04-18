## KRY Projekt 2 - Client code
## Author: Vojtech Fiala <xfiala61>

from utils import generateKey, readKey, generateHash, RSApadding, getRandomKey, RSAunpadding, parseKey, getTextAndSig
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

        print("AES_key=%x" % print_aes)
        print("AES_key_padding=%x" % padded_key)
        print("MD5=%x" % msg_hash)
        print("MD5_padding=%x" % padded_hash)
        
        signature = pow(padded_hash, priv_key.d, priv_key.n) # s = m^d % n
        msg_to_encode = message + "'" + str(signature) # add ' between message and signature to difference between those two
        encoded_text, _ = cipher.encrypt_and_digest(msg_to_encode.encode())
        encrypted_key = pow(padded_key, server_pub_key.e, server_pub_key.n) # c = m^e % n
        everything_encoded = (encoded_text + "'".encode() + str(encrypted_key).encode() + "'".encode() + str(int.from_bytes(cipher.nonce, "big")).encode()) # add ' to find where the key ends

        print("RSA_MD5_hash=%x" % signature)
        print("AES_cipher=%s" % encoded_text.hex())
        print("RSA_AES_key=%x" % encrypted_key)
        print("ciphertext=%s" % everything_encoded.hex())

        sock.sendall(everything_encoded)
        result = sock.recv(4096) # wait for server answer


        nonce, key, rest = parseKey(result)
        key = int(key)
        nonce = int(nonce)
        nonce = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
        
        aes_key = pow(key, priv_key.d, priv_key.n) # encrypted aes key, decrypt it - m = c^d % n
        aes_key = RSAunpadding(aes_key)

        cipher = AES.new(aes_key.to_bytes(16, "big"), AES.MODE_EAX, nonce=nonce)
        text_hash = cipher.decrypt(rest)

        msg, recv_sig = getTextAndSig(text_hash)

        if signature == recv_sig:
            print(msg)
        # hashes dont match
        else:
            # if only the hash dosnt match
            if (msg == "WARNING! Integrity was compromised. Please send again."):
                print("Error with message integrity, please send again!")
            # if even the error message doesnt match
            else:
                print(msg)
                print("Server response integrity error! Something bad is going on...")

        
        sock.close()
