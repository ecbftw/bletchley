'''
Created on Jul 4, 2010

Copyright (C) 2010 ELOI SANFÈLIX
@author: Eloi Sanfelix < eloi AT limited-entropy.com >

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License, version 3,
 as published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import random
import struct
from .Exceptions import *

class DecryptionOracle:
    '''
    This class implements a decryption oracle based on a given padding oracle.
    The attacked padding scheme is the one defined in PKCS#5 and RFC2040, and maybe other places.
    The attack was first described in the "Security Flaws Induced by CBC Padding. Applications to SSL, IPSEC, WTLS... by Serge Vaudenay"
    '''

    
    def __init__(self,oracle,blockSize=8):
        '''
        Creates a new DecryptionOracle object. Receives an oracle function which returns True 
        if the given ciphertext results in a correct padding and False otherwise. A second 
        parameter defining the cipher block size in bytes is also supported (default is 8). 
        '''
        self.oracle = oracle
        self.blockSize = blockSize
        
    def decrypt_last_bytes(self,block):
        '''
        Decrypts the last bytes of block using the oracle.
        '''
        if(len(block)!=self.blockSize):
            raise InvalidBlockError(self.blockSize,len(block))
        
        #First we get some random bytes
        rand = [random.getrandbits(8) for i in range(self.blockSize)]
        
        for b in range(256):
            
            #XOR with current guess
            rand[-1] = rand[-1]^b
            #Generate padding string    
            randStr = "".join([ struct.pack("B",i) for i in rand ] )
            if(self.oracle(randStr+block)):
                break
            else:
                #Remove current guess
                rand[-1]=rand[-1]^b
                
        #Now we have a correct padding, test how many bytes we got!
        for i in range(self.blockSize-1):
            #Modify currently tested byte
            rand[i] = rand[i]^0x01
            randStr = "".join([ struct.pack("B",j) for j in rand ] )
            if(not self.oracle(randStr+block)):
                #We got a hit! Byte i is also part of the padding
                paddingLen = self.blockSize-i
                #Correct random i
                rand[i] = rand[i]^0x01
                #Return paddingLen final bytes
                return "".join([ struct.pack("B",i^paddingLen) for i in rand[-paddingLen:]])
            
            #Nothing to do when there is no hit. This byte is useless then.

        #Could only recover 1 byte. Return it.    
        return "".join(struct.pack("B",rand[-1]^0x01))

    def decrypt_next_byte(self,block,known_bytes):
        '''
        Given some known final bytes, decrypts the next byte using the padding oracle. 
        '''
        if(len(block)!=self.blockSize):
            raise InvalidBlockError
        numKnownBytes = len(known_bytes)
        
        if(numKnownBytes >= self.blockSize):
            return known_bytes
        
        # Craft data that will produce xx ... xx <numKnownBytes+1> ... <numKnownBytes+1> after decryption
        
        rand = [random.getrandbits(8) for i in range(self.blockSize-numKnownBytes)]
        for i in known_bytes:
            rand.append(struct.unpack("B",i)[0]^(numKnownBytes+1))
        
        #Now we do same trick again to find next byte.
        for b in range(256):
            rand[-(numKnownBytes+1)] =rand[-(numKnownBytes+1)]^b 
            #Generate padding string    
            randStr = "".join([ struct.pack("B",i) for i in rand ] )

            if(self.oracle(randStr+block)):
                break
            else:
                rand[-(numKnownBytes+1)] =rand[-(numKnownBytes+1)]^b
        
        #  Return previous bytes together with current byte
        return "".join([struct.pack("B",rand[i]^(numKnownBytes+1)) for i in range(self.blockSize-numKnownBytes-1,self.blockSize)])
    
    def decrypt_block(self,block):
        '''
        Decrypts the block of ciphertext provided as a parameter.
        '''
        bytes = self.decrypt_last_bytes(block)
        while(len(bytes)!=self.blockSize):
            bytes = self.decrypt_next_byte(block,bytes)
        return bytes
    
    def decrypt_message(self,ctext, iv = None):
        '''
        Decrypts a message using CBC mode. If the IV is not provided, it assumes a null IV.
        '''
        #Recover first block
        result = self.decrypt_block(ctext[0:self.blockSize])
        
        #XOR IV if provided, else we assume zero IV.
        if( iv != None):
            result = self.xor_strings(result, iv)

        #Recover block by block, XORing with previous ctext block
        for i in range(self.blockSize,len(ctext),self.blockSize):
            prev = ctext[i-self.blockSize:i]
            current = self.decrypt_block(ctext[i:i+self.blockSize])
            result += self.xor_strings(prev,current)
        return result
    
    def xor_strings(self,s1,s2):
        result = ""
        for i in range(len(s1)):
            result += struct.pack("B",ord(s1[i])^ord(s2[i]))
        return result
    
    def hex_string(self,data):
        return "".join([ hex(ord(i))+" " for i in data])
