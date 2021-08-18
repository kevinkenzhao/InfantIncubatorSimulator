import threading
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import infinc
import time
import math
import socket
import fcntl
import os
import errno
import random
import string
from hashlib import blake2b
import time
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from dotenv import load_dotenv

class SmartNetworkThermometer (threading.Thread) :
    open_cmds = ["AUTH", "LOGOUT"]
    prot_cmds = ["SET_DEGF", "SET_DEGC", "SET_DEGK", "GET_TEMP", "UPDATE_TEMP"]

    def __init__ (self, source, updatePeriod, port) :
        threading.Thread.__init__(self, daemon = True) 
        #set daemon to be true, so it doesn't block program from exiting
        self.source = source
        self.updatePeriod = updatePeriod
        self.curTemperature = 0
        self.updateTemperature()
        self.tokens = {}

        self.serverSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.serverSocket.bind(("127.0.0.1", port))
        fcntl.fcntl(self.serverSocket, fcntl.F_SETFL, os.O_NONBLOCK)

        self.deg = "K"

    def scrypt_PBKDF(self, pw, transmit_mode, salt=None) : #generate key used for AES encryption from password https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
        pw = bytes(pw, 'utf-8')
        s = b""
        if transmit_mode == b"1": #if generating a key for outbound message
            s = get_random_bytes(16)
            print("mode 1")
        elif transmit_mode == b"2": #if generating a key to decrypt inbound message
            s = salt
            print("mode 2")
        key = scrypt(pw, s, 16, N=2**14, r=8, p=1)
        print("scrypt key length is " + str(len(key)))
        return key, s

    def AES_encrypt(self, key, command) : #encrypt command to server using key derived from scrypt_PBKDF https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(command)
        return nonce, ciphertext, tag

    def AES_decrypt(self, key, ciphertext, nonce, tag) : #encrypt command to server using key derived from scrypt_PBKDF https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
        cipher = AES.new(key, AES.MODE_EAX, nonce=bytes(nonce))
        plaintext = cipher.decrypt(bytes(ciphertext)) #returns password as bytes object
        try:
            #This method checks if the decrypted message is indeed valid (that is, if the key is correct) and it has not been tampered with while in transit.
            #tag is the hash of the plaintext
            cipher.verify(bytes(tag))
            print ("The message is authentic!")
            return plaintext.decode("utf-8").strip()
        except ValueError:
            print ("Tag of decrypted message not consistent with sent tag!")

    def setSource(self, source) :
        self.source = source

    def setUpdatePeriod(self, updatePeriod) :
        self.updatePeriod = updatePeriod 

    def setDegreeUnit(self, s) :
        self.deg = s
        if self.deg not in ["F", "K", "C"] :
            self.deg = "K"

    def updateTemperature(self) :
        self.curTemperature = self.source.getTemperature()

    def getTemperature(self) :
        if self.deg == "C" :
            return self.curTemperature - 273
        if self.deg == "F" :
            return (self.curTemperature - 273) * 9 / 5 + 32

        return self.curTemperature



    def processCommands(self, msg, session_key, addr) :
        env_file = os.getcwd() + "/env.example"
        try:
            print("env file found!")
            load_dotenv(env_file)
        except:
            print("env file not found!")
        BLAKE_KEY = os.environ['BLAKE_KEY']
        cmds = msg.split(';')
        gen_token = ""
        for c in cmds :
            cs = c.split(' ')
            if len(cs) == 3 : #should be either AUTH or LOGOUT
                if cs[0] == "AUTH":
                    try:
                        USER_HASH = os.environ[cs[1]] #loads username from user-submitted input (format: AUTH USERNAME PASSWORD)
                    except:
                        nonce, encrypted_msg, tag = self.AES_encrypt(session_key, "Username not found!")
                        full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag                     
                        self.serverSocket.sendto(full_msg, addr)
                    h = blake2b(key=BLAKE_KEY.encode('utf8'), digest_size=16)
                    h.update(cs[2].encode())
                    h.hexdigest()
                    print("hash comparison")
                    print(str(h.hexdigest()))
                    print(USER_HASH)
                    if str(h.hexdigest()) == USER_HASH:
                        #creates string like "HBD7lmLdHKerOQVE", with (26+26+10)^16 as the number of possible values
                        gen_token = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(64))
                        for k in self.tokens:
                            if gen_token != k:
                                continue
                            else:
                                gen_token = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(64))
                        self.tokens[gen_token] = time.time()
                        msg = [k for k in self.tokens][-1].encode("utf-8") + b"\n"
                        print("sending the following token: " + str(msg))
                        nonce, encrypted_msg, tag = self.AES_encrypt(session_key, msg)
                        full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag                     
                        self.serverSocket.sendto(full_msg, addr)

                    else:
                        nonce, encrypted_msg, tag = self.AES_encrypt(session_key, "Incorrect username/password!")
                        full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag                     
                        self.serverSocket.sendto(full_msg, addr)
                elif cs[0] == "LOGOUT":
                    if cs[1] in self.tokens :
                        self.tokens.pop(cs[1])
                else : #unknown command
                    self.serverSocket.sendto(b"Invalid Command\n", addr)
            elif c == "SET_DEGF" :
                self.deg = "F"
            elif c == "SET_DEGC" :
                self.deg = "C"
            elif c == "SET_DEGK" :
                self.deg = "K"
            elif c == "GET_TEMP" :
                msg = b"%f\n" % self.getTemperature()
                nonce, encrypted_msg, tag = self.AES_encrypt(session_key, msg)
                full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag                     
                self.serverSocket.sendto(full_msg, addr)
            elif c == "UPDATE_TEMP" :
                self.updateTemperature()
            elif c :
                self.serverSocket.sendto(b"Invalid Command\n", addr)


    def run(self) : #the running function
        print("run function")
        while True : 
            try :
                msg, addr = self.serverSocket.recvfrom(1024)
                #decrypt commands here
                #msg = msg.decode("utf-8").strip()
                encrypted_params = msg.split(b"CS-GY6803")
                for x in encrypted_params:
                    print(str(x))
                session_key, s = self.scrypt_PBKDF(pw="!Q#E%T&U8i6y4r2w", transmit_mode=encrypted_params[4], salt=encrypted_params[3])
                print("session_key for decryption:")
                print(str(session_key))
                plaintext = self.AES_decrypt(session_key, encrypted_params[1], encrypted_params[0], encrypted_params[2])
                print("plaintext is of type" + str(type(plaintext)))
                print("plaintext is: " + str(plaintext))
                cmds = plaintext.split(' ')
                if len(cmds) == 1 : # protected commands case
                    semi = plaintext.find(';')
                    if semi != -1 : #if we found the semicolon
                        #print (msg)
                        if plaintext[:semi] in self.tokens : #if its a valid token
                            #checks for token expiration/validity
                            submitted_token = plaintext[:semi]
                            if time.time() - self.tokens[submitted_token] > 43200:
                                self.tokens.remove(submitted_token)
                                nonce, encrypted_msg, tag = self.AES_encrypt(session_key, b"Expired Token\n")
                                full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag
                                self.serverSocket.sendto(full_msg, addr)                                
                            self.processCommands(plaintext[semi+1:], session_key, addr)
                        else :
                            nonce, encrypted_msg, tag = self.AES_encrypt(session_key, b"Bad Token\n")
                            full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag
                            self.serverSocket.sendto(full_msg, addr)
                    else :
                        nonce, encrypted_msg, tag = self.AES_encrypt(session_key, b"Bad Command\n")
                        full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag
                        self.serverSocket.sendto(full_msg, addr)
                elif len(cmds) == 3 :
                    if cmds[0] in self.open_cmds : #if its AUTH or LOGOUT
                        print("cmds[0] is of type" + str(type(cmds[0])))
                        print("cmds[1] is of type" + str(type(cmds[1])))
                        self.processCommands(plaintext, session_key, addr) 
                    else :
                        nonce, encrypted_msg, tag = self.AES_encrypt(session_key, b"Authenticate first\n")
                        full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag
                        self.serverSocket.sendto(full_msg, addr)
                else :
                    # otherwise bad command
                    nonce, encrypted_msg, tag = self.AES_encrypt(session_key, b"Bad Command\n")
                    full_msg = nonce + b"CS-GY6803" + encrypted_msg + b"CS-GY6803" + tag
                    self.serverSocket.sendto(full_msg, addr)
    
            except IOError as e :
                if e.errno == errno.EWOULDBLOCK :
                    #do nothing
                    pass
                else :
                    #do nothing for now
                    pass
                msg = ""

 

            self.updateTemperature()
            time.sleep(self.updatePeriod)




class SimpleClient :
    def __init__(self, therm1, therm2) :
        self.fig, self.ax = plt.subplots()
        now = time.time()
        self.lastTime = now
        self.times = [time.strftime("%H:%M:%S", time.localtime(now-i)) for i in range(30, 0, -1)]
        self.infTemps = [0]*30
        self.incTemps = [0]*30
        self.infLn, = plt.plot(range(30), self.infTemps, label="Infant Temperature")
        self.incLn, = plt.plot(range(30), self.incTemps, label="Incubator Temperature")
        plt.xticks(range(30), self.times, rotation=45)
        plt.ylim((20,50))
        plt.legend(handles=[self.infLn, self.incLn])
        self.infTherm = therm1
        self.incTherm = therm2

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

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


    def updateInfTemp(self, frame) :
        self.updateTime()
        self.infTemps.append(self.infTherm.getTemperature()-273)
        #self.infTemps.append(self.infTemps[-1] + 1)
        #for x in self.infTemps:
        #    print(str(x))
        #print("chicken")
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame) :
        self.updateTime()
        self.incTemps.append(self.incTherm.getTemperature()-273)
        #for x in self.incTemps:
        #    print(str(x))
        #print("broccoli")
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,

UPDATE_PERIOD = .05 #in seconds
SIMULATION_STEP = .1 #in seconds

#create a new instance of IncubatorSimulator
bob = infinc.Human(mass = 8, length = 1.68, temperature = 36 + 273)
#bobThermo = infinc.SmartThermometer(bob, UPDATE_PERIOD)
bobThermo = SmartNetworkThermometer(bob, UPDATE_PERIOD, 23456)
bobThermo.start() #start the thread

inc = infinc.Incubator(width = 1, depth=1, height = 1, temperature = 37 + 273, roomTemperature = 20 + 273)
#incThermo = infinc.SmartNetworkThermometer(inc, UPDATE_PERIOD)
incThermo = SmartNetworkThermometer(inc, UPDATE_PERIOD, 23457)
incThermo.start() #start the thread

incHeater = infinc.SmartHeater(powerOutput = 1500, setTemperature = 45 + 273, thermometer = incThermo, updatePeriod = UPDATE_PERIOD)
inc.setHeater(incHeater)
incHeater.start() #start the thread

sim = infinc.Simulator(infant = bob, incubator = inc, roomTemp = 20 + 273, timeStep = SIMULATION_STEP, sleepTime = SIMULATION_STEP / 10)

sim.start()

sc = SimpleClient(bobThermo, incThermo)

plt.grid()
plt.show()
