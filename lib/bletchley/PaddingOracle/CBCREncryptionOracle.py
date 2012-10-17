'''
Created on Sep 19, 2010

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

from PaddingOracle.InvalidBlockError import InvalidBlockError
import random
import struct

class CBCREncryptionOracle:
    '''
    This class implements an encryption oracle based on a decryption oracle.
    The decryption oracle must implement a decrypt_block method, which given an input ciphertext
    block returns the corresponding plaintext block.
    
    The technique used is known as CBC-R and was described by Juliano Rizzo and Thai Duong in 
    their BlackHat 2010 presentation "Practical Padding Oracle Attacks".
    '''

    def __init__(self,oracle,blockSize=8):
        self.oracle = oracle
        self.blockSize = blockSize

    def encrypt_block(self,input_block, prev_block = None):
        if (len(input_block) != self.blockSize):
            print("Received input block of len ",len(input_block))
            raise InvalidBlockError(self.blockSize,len(input_block))
        
        if (prev_block == None):
            prev_block =  "".join([struct.pack("B",random.getrandbits(8)) for i in range(self.blockSize) ])
        ctext = self.oracle.decrypt_block(prev_block)
        iv = self.oracle.xor_strings(ctext,input_block)
        return iv+prev_block        
    
    def encrypt_message(self,message):
        if (len(message) % self.blockSize != 0):
            raise InvalidBlockError(self.blockSize,len(message))
        
        nblocks = len(message) / self.blockSize
        # Encrypt last block
        ctext = self.encrypt_block(message[-self.blockSize:])
        for i in range(1,nblocks):
            #Obtain next ctext and IV using previous ciphertext block + current message block
            next = self.encrypt_block(message[-(i+1)*self.blockSize:-(i)*self.blockSize],ctext[0:self.blockSize])
            #Add computed previous block to the ciphertext list
            ctext = next[0:self.blockSize] + ctext
        return ctext
