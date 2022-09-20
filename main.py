#!/usr/bin/env python
# -*- coding: utf-8 -*- 
#Created by Dagger -- https://github.com/gavazquez
#Recreated by Ali Can Gonullu -- https://github.com/alicangnll
import time

def Xor(buf):
    cccam = "CCcam"
    for i in range(0, 8):
        buf[8 + i] = 0xff & (i * buf[i])
        if i < 5:   
            buf[i] ^= ord(cccam[i])
    return buf

class CryptographicBlock(object):
    def __init__(self):
        self._keytable = [0] * 256
        self._state = 0
        self._counter = 0
        self._sum = 0

    def Init(self, key, len):
        for i in range(0, 256):
            self._keytable[i] = i
        j = 0
        for i in range(0, 256):
            j = 0xff & (j + key[i % len] + self._keytable[i])
            self._keytable[i], self._keytable[j] = self._keytable[j], self._keytable[i]
        self._state = key[0]
        self._counter = 0
        self._sum = 0

    def Decrypt(self, data, len):
        for i in range(0, len):
            self._counter = 0xff & (self._counter + 1)
            self._sum = self._sum + self._keytable[self._counter]

            #Swap keytable[counter] with keytable[sum]
            self._keytable[self._counter], self._keytable[self._sum & 0xFF] = \
                self._keytable[self._sum & 0xFF], self._keytable[self._counter]

            z = data[i]
            data[i] = z ^ self._keytable[(self._keytable[self._counter] + \
                self._keytable[self._sum & 0xFF]) & 0xFF] ^ self._state
            z = data[i]
            self._state = 0xff & (self._state ^ z)

    def Encrypt(self, data, len):
        for i in range(0, len):
            self._counter = 0xff & (self._counter + 1)
            self._sum = self._sum + self._keytable[self._counter]
            
            #Swap keytable[counter] with keytable[sum]
            self._keytable[self._counter], self._keytable[self._sum & 0xFF] = \
                self._keytable[self._sum & 0xFF], self._keytable[self._counter]

            z = data[i]
            data[i] = z ^ self._keytable[(self._keytable[self._counter & 0xFF] + \
                self._keytable[self._sum & 0xFF]) & 0xff] ^ self._state

            self._state = 0xff & (self._state ^ z)

recvblock = CryptographicBlock()
sendblock = CryptographicBlock()

def TestCline(cline):
    import socket, re, sys, array, time, select

    returnValue = False
    regExpr = re.compile('[C]:\s*(\S+)+\s+(\d*)\s+(\S+)\s+([\w.-]+)')
    match = regExpr.search(cline)

    if match is None:
        return False

    testSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
    testSocket.settimeout(30) #timeout of 30 seconds

    host = str(match.group(1))
    port = int(match.group(2))
    username = str(match.group(3))
    password = str(match.group(4))

    try:
        ip = socket.gethostbyname(host)
        testSocket.connect((ip, port))

        DoHanshake(testSocket) #Do handshake with the server

        try:
            userArray = GetPaddedString(username, 20)
            sendcount = SendMessage(userArray, len(userArray), testSocket) #Send the username

            passwordArray = GetPaddedString(password, len(password))
            sendblock.Encrypt(passwordArray, len(passwordArray)) #We encript the password

            #But we send "CCCam" with the password encripted CriptoBlock
            cccamArray = GetPaddedString("CCcam", 6)
            sendcount = SendMessage(cccamArray, len(cccamArray), testSocket)

            receivedBytes = bytearray(20)
            recvCount = testSocket.recv_into(receivedBytes, 20)

            if recvCount > 0:
                recvblock.Decrypt(receivedBytes, 20)
                if (receivedBytes.decode("ascii").rstrip('\0') == "CCcam"):
                    print("SUCCESS! working cline: " + cline)
                    time.sleep(500)
                    #data = input("Command :")
                    #print("\n")
                    #if(data == "exit"):
                        #print("Quiting..")
                        #testSocket.close()
                        #sys.exit(0)
                    #else:
                        #DoHanshake(testSocket)
                        #SendMessage(userArray, len(userArray), testSocket)
                        #sendblock.Encrypt(passwordArray, len(passwordArray)) 
                        #SendMessage(cccamArray, len(cccamArray), testSocket)
                        #testSocket.recv_into(bytearray(20), 20)
                        #testSocket.send(data.encode())
                        #dataFromServer = testSocket.recv(1024)
                        #print(dataFromServer)
                    returnValue = True
                else:
                    print("Yanlıs ACK Alindi!")
                    time.sleep(500)
                    returnValue = False
            else:
                print("Bad username/password for cline: " + cline)
                time.sleep(500)
                returnValue = False

        except:
            print("Bad username/password for cline: " + cline)
            time.sleep(500)
            returnValue = False
    except:
        print("Error while connecting to cline: " + cline)
        time.sleep(500)

def GetPaddedString(string, padding):
    import sys, array

    #We create an array of X bytes with the string in it as bytes and padded with 0 behind
    #Like: [23,33,64,13,0,0,0,0,0,0,0...]

    if sys.version_info[0] < 3:
        strBytes = array.array("B", string)
    else:
        strBytes = array.array("B")
        strBytes.frombytes(string.encode())

    return FillArray(bytearray(padding), strBytes)

def DoHanshake(socket):
    import hashlib, array, CriptoBlock

    random = bytearray(16)
    socket.recv_into(random, 16) #Receive first 16 "Hello" random bytes
    print("Hello bytes: %s" % random)

    random = CriptoBlock.Xor(random); #Do a Xor with "CCcam" string to the hello bytes

    sha1 = hashlib.sha1()
    sha1.update(random)
    sha1digest = array.array('B', sha1.digest()) #Create a sha1 hash with the xor hello bytes
    sha1hash = FillArray(bytearray(20), sha1digest)

    recvblock.Init(sha1hash, 20) #initialize the receive handler
    recvblock.Decrypt(random, 16)

    sendblock.Init(random, 16) #initialize the send handler
    sendblock.Decrypt(sha1hash, 20)

    rcount = SendMessage(sha1hash, 20, socket) #Send the a crypted sha1hash!
    return rcount

def SendMessage(data, len, socket):
    buffer = FillArray(bytearray(len), data)
    sendblock.Encrypt(buffer, len)
    rcount = socket.send(buffer)
    return rcount

def FillArray(array, source):
    if len(source) <= len(array):
        for i in range(0, len(source)):
            array[i] = source[i]
    else:
        for i in range(0, len(array)):
            array[i] = source[i]
    return array

if __name__ == "__main__":
    girisyap = input("Write to CCCam Informations (C: free.example.net user pass example.net) : ")
    TestCline(str(girisyap))
    time.sleep(500)
