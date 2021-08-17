import matplotlib.pyplot as plt
import matplotlib.animation as animation
import time
import math
import socket
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

class SimpleNetworkClient :
    def __init__(self, port1, port2) :
        self.fig, self.ax = plt.subplots()
        now = time.time()
        self.lastTime = now
        self.times = [time.strftime("%H:%M:%S", time.localtime(now-i)) for i in range(30, 0, -1)] #prints out last 30 seconds in %H:%M:%S format
        self.infTemps = [0]*30
        self.incTemps = [0]*30
        self.infLn, = plt.plot(range(30), self.infTemps, label="Infant Temperature")
        self.incLn, = plt.plot(range(30), self.incTemps, label="Incubator Temperature")
        plt.xticks(range(30), self.times, rotation=45)
        plt.ylim((20,50))
        plt.legend(handles=[self.infLn, self.incLn])
        self.infPort = port1
        self.incPort = port2

        self.infToken = None
        self.incToken = None

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

    def scrypt_PBKDF(self, pw, transmit_mode, salt=None) : #generate key used for AES encryption from password https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
        s = b""
        if transmit_mode == b"1": #if generating a key for outbound message
            print("mode 1")
            s = get_random_bytes(16)
        elif transmit_mode == b"2": #if generating a key to decrypt inbound message
            s = salt
            print("mode 2")
        key = scrypt(pw, s, 16, N=2**14, r=8, p=1)
        print("key length is " + str(len(key)))
        return key, s

    def AES_encrypt(self, key, command) : #encrypt command to server using key derived from scrypt_PBKDF https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
        cipher = AES.new(key, AES.MODE_EAX)
        print("aes encrypt key length is " + str(len(key)))
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(command)
        print(type(nonce))
        print(type(ciphertext))
        print(type(tag))
        return nonce, ciphertext, tag

    def AES_decrypt(self, key, ciphertext, nonce, tag) : #encrypt command to server using key derived from scrypt_PBKDF https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
        cipher = AES.new(key, AES.MODE_EAX, nonce=bytes(nonce))
        print("aes decrypt key length is " + str(len(key)))
        plaintext = cipher.decrypt(bytes(ciphertext)) #returns password as bytes object
        try:
            #This method checks if the decrypted message is indeed valid (that is, if the key is correct) and it has not been tampered with while in transit.
            #tag is the hash of the plaintext
            cipher.verify(bytes(tag))
            print ("The message is authentic!")
            return plaintext.decode("utf-8").strip()
        except ValueError:
            print ("Tag of decrypted message not consistent with sent tag!")

    def updateTime(self) :
        now = time.time()
        if math.floor(now) > math.floor(self.lastTime) :
            t = time.strftime("%H:%M:%S", time.localtime(now))
            self.times.append(t)
            #last 30 seconds of of data
            self.times = self.times[-30:]
            self.lastTime = now
            plt.xticks(range(30), self.times,rotation = 45)
            plt.title(time.strftime("%A, %Y-%m-%d", time.localtime(now)))

    def getTemperatureFromPort(self, p, tok) :
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        key, salt = self.scrypt_PBKDF(pw=b"!Q#E%T&U8i6y4r2w", transmit_mode=b"1")
        command = bytearray(bytes(tok, "utf-8"))
        command.extend(b';GET_TEMP')
        nonce, encrypted_msg, tag = self.AES_encrypt(key, command)
        full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag + b"CS-GY6803" + salt + b"CS-GY6803" + b"2"
        s.sendto(full_msg, ("127.0.0.1", p)) 

        msg, addr = s.recvfrom(1024)
        cmds = msg.split(b'CS-GY6803')
        print("length after split:" + str(len(cmds)))
        plaintext = self.AES_decrypt(key, cmds[1], cmds[0], cmds[2])
        #m = msg.decode("utf-8")
        return (float(plaintext))

    def authenticate(self, p, pw) : #credentials sent in plaintext!
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        key, salt = self.scrypt_PBKDF(pw=b"!Q#E%T&U8i6y4r2w", transmit_mode=b"1")
        command = bytearray(b'AUTH ') #PBKDF function parameters cannot be encrypted because it will be used to generate the decryption key on the server
        command.extend(pw)
        nonce, encrypted_msg, tag = self.AES_encrypt(key, command)
        print("Session key for encryption:")
        print(str(key))
        full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag + b"CS-GY6803" + salt + b"CS-GY6803" + b"2"
        print(str(nonce))
        print(str(encrypted_msg))
        print(str(tag))
        print(str(salt))
        print(str(b"2"))
        s.sendto(full_msg, ("127.0.0.1", p)) 
        # current authentication process allows anyone with knowledge of the secret to execute some task on the incubator, but server does not prompt for identity. 

        msg, addr = s.recvfrom(1024)
        #session keys are rotated after one exchange
        #decrypt commands here
        #msg = msg.decode("utf-8").strip()
        cmds = msg.split(b'CS-GY6803')
        print("length after split:" + str(len(cmds)))

        #session_key, salt = self.scrypt_PBKDF(pw=b"!Q#E%T&U8i6y4r2w", transmit_mode=b"2", salt=salt)
        plaintext = self.AES_decrypt(key, cmds[1], cmds[0], cmds[2]) #a token is returned if authentication was successful
        return plaintext

    def updateInfTemp(self, frame) :
        self.updateTime()
        if self.infToken is None : #not yet authenticated
            self.infToken = self.authenticate(self.infPort, b"!Q#E%T&U8i6y4r2w")

        self.infTemps.append(self.getTemperatureFromPort(self.infPort, self.infToken)-273)
        #self.infTemps.append(self.infTemps[-1] + 1)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame) :
        self.updateTime()
        if self.incToken is None : #not yet authenticated
            self.incToken = self.authenticate(self.incPort, b"!Q#E%T&U8i6y4r2w")

        self.incTemps.append(self.getTemperatureFromPort(self.incPort, self.incToken)-273)
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,
    


        
snc = SimpleNetworkClient(23456, 23457)

plt.grid()
plt.show()
