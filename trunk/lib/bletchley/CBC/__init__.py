'''
Created on Jul 4, 2010

Copyright (C) 2010 ELOI SANFÈLIX
Copyright (C) 2012-2015 Timothy D. Morgan
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
    retries = 2
    decrypted = None
    threads = None
    log_fh = None
    
    def __init__(self, oracle, block_size, ciphertext, iv=None,
                 threads=1, decrypted=b'', log_file=None):
        """Creates a new padding oracle attack (POA) object. 

        Arguments:
        oracle -- A function which returns True if the given ciphertext
         results in a correct padding upon decryption and False
         otherwise.  This function should implement the prototype:
           def myOracle(ciphertext, iv): ...
         If the initialization vector (iv) is unknown or not included in
         the ciphertext message, it can be ignored in your oracle
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
         is, the tail of the plaintext including the pad.

        log_file -- A Python file object where log messages will be
         written.

        """

        if(len(ciphertext)%block_size != 0 or len(ciphertext) < block_size):
            raise InvalidBlockError(block_size,len(ciphertext))
        if(iv != None and len(iv)%block_size != 0):
            raise InvalidBlockError(block_size,len(iv))
        if len(decrypted) > len(ciphertext):
            raise Exception #XXX: custom exception
        
        self.block_size = block_size
        self.decrypted = decrypted
        self.threads = threads
        self.log_fh = log_file

        self._oracle = oracle
        self._ciphertext = ciphertext
        if iv == None:
            self._iv = b'\x00'*self.block_size
        else:
            self._iv = iv


    def log_message(self, s):
        if self.log_fh != None:
            self.log_fh.write('BLETCHLEY: %s\n' % s)


    def probe_padding(self):
        """Attempts to verify that a CBC padding oracle exists and then determines the
        pad value.  

        Returns the pad string, or None on failure. 
        XXX: Currently only works for PKCS 5/7.
        """

        blocks = buffertools.splitBuffer(self._ciphertext, self.block_size)
        final = blocks[-1]
        if len(blocks) == 1:
            # If only one block present, then try to use IV as prior
            prior = self._iv
        else:
            prior = blocks[-2]

        ret_val = None
        # First probe for beginning of pad
        for i in range(0-self.block_size,0):
            if i == -1:
                break
            tweaked = prior[i] ^ 0xFF
            tweaked = struct.pack("B", tweaked)
            if not self._oracle(self._ciphertext+prior[:i]+tweaked+prior[i+1:]+final, self._iv):
                break

        pad_length = 0-i
        self.log_message("Testing suspected pad length: %d" % pad_length)
        if pad_length > 1:
            # XXX: If this test case fails, we should try instead
            # lengthing the pad by one byte with all 256 values (as is
            # done in the 1-byte pad case).
            #
            # Verify suspected pad length by changing last pad byte to 1
            # and making sure the padding succeeds
            tweaked = prior[-1] ^ (pad_length^1)
            tweaked = struct.pack("B", tweaked)

            #XXX: This replaces the pad bytes with spaces.  The hope is
            #     that any UTF-8 decoding errors that the pad bytes
            #     might generate are addressed this way.  It is not yet
            #     well tested.  An option should be added to allow other
            #     bytes to be used or to turn off the behavior.
            prior = bytearray(prior)
            for q in range(0-self.block_size,-1):
                prior[q] = prior[q]^(pad_length^32) # space

            if self._oracle(self._ciphertext+prior[:-1]+tweaked+final, self._iv):
                ret_val = buffertools.pkcs7Pad(pad_length)

        else:
            # Verify by changing pad byte to 2 and brute-force changing
            # second-to-last byte to 2 as well
            tweaked = prior[-1] ^ (2^1)
            tweaked = struct.pack("B", tweaked)
            for j in range(1,256):
                guess = prior[-2] ^ j
                guess = struct.pack("B", guess)
                if self._oracle(self._ciphertext+prior[:-2]+guess+tweaked+final, self._iv):
                    # XXX: Save the decrypted byte for later
                    ret_val = buffertools.pkcs7Pad(pad_length)

        return ret_val


    # XXX: This could be generalized as a byte probe utility for a variety of attacks
    def _test_value_set(self, prefix, suffix, value_set):
        for b in value_set:
            if self._thread_result != None:
                # Stop if another thread found the result
                break
            if self._oracle(prefix+struct.pack("B",b)+suffix, self._iv):
                self._thread_result = b
                break


    def decrypt_next_byte(self, prior, block, known_bytes, cache=True):
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
        base = prior[self.block_size-numKnownBytes-1]
        # Adjust known bytes to appear as a PKCS 7 pad
        suffix = [0]*numKnownBytes
        for i in range(0,numKnownBytes):
            suffix[i] ^= prior[0-numKnownBytes+i]^known_bytes[i]^(numKnownBytes+1)
        suffix = struct.pack("B"*len(suffix),*suffix)+block

        # XXX: catch any signal exceptions, such as ^C, and communicate
        #      this back to the rest of the script so it can end immediately 
        for x in range(0, 1+self.retries):
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
                
            # If a byte fails to decrypt, it could be because the prior
            # block's decrypted value violates UTF-8 decoding rules, or
            # because it randomly introduced a delimiter that causes
            # problems.  If retries are enabled, we insert an additional
            # random block before the prior block so that the decrypted
            # value can be changed.
            if self._thread_result == None:
                if x < self.retries:
                    self.log_message("Value of a byte could not be determined. Retrying...")
                    # XXX: Instead of adding a new random block to the
                    #      beginning every time, would be better to just keep
                    #      randomizing the same block before the original
                    #      prior_prefix.
                    prior_prefix = bytes([random.getrandbits(8) for i in range(self.block_size)]) + prior_prefix
            else:
                break

        if self._thread_result == None:
            self.log_message("Value of a byte could not be determined.  Current plaintext suffix: "+ repr(self.decrypted))
            raise Exception #XXX: custom exception
        
        decrypted = struct.pack("B",self._thread_result^base^(numKnownBytes+1))
        if cache:
            self.decrypted = decrypted + self.decrypted
        #  Return previous bytes together with current byte
        return decrypted+known_bytes 
    

    def decrypt_block(self, prior, block, last_bytes=b'', cache=True):
        """Decrypts the block of ciphertext provided as a parameter.

        """

        while(len(last_bytes)!=self.block_size):
            last_bytes = self.decrypt_next_byte(prior, block, last_bytes, cache)

        self.log_message("Decrypted block: %s" % repr(last_bytes))
        return last_bytes


    def decrypt(self):
        """Decrypts the previously supplied ciphertext. If the IV was
        not provided, it assumes a IV of zero bytes.

        """

        if len(self.decrypted) == 0:
            # First decrypt the padding (quick to decrypt and good sanity check)
            pad_bytes = self.probe_padding()
            if pad_bytes == None:
                # XXX: custom exception
                self.log_message("Could not determine pad length")
                raise Exception
            
            self.decrypted = pad_bytes


        # Start where we left off last, whether that be with just a pad,
        # or with additional decrypted blocks.

        # number of bytes in any partially decrypted blocks
        num_partial = len(self.decrypted) % self.block_size

        # number of blocks fully decrypted
        finished_blocks = len(self.decrypted) // self.block_size

        # contents of the partial block
        partial = self.decrypted[0:num_partial]

        # contents of fully decrypted blocks
        decrypted = self.decrypted[num_partial:]
        
        blocks = buffertools.splitBuffer(self._ciphertext, self.block_size)

        # Start with the partially decrypted block at the end, and work
        # our way to the front.  Don't decrypt the very first block of
        # the ciphertext yet.
        for i in range(len(blocks)-1-finished_blocks, 0, -1):
            decrypted = self.decrypt_block(blocks[i-1], blocks[i], partial) + decrypted
            partial = b''
                
        # Finally decrypt first block
        if finished_blocks < len(blocks):
            decrypted = self.decrypt_block(self._iv, blocks[0], partial) + decrypted
        
        # Remove the padding and return
        return buffertools.stripPKCS7Pad(decrypted, self.block_size, self.log_fh)


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

        ptext = self.decrypt_block(b'\x00'*self.block_size, ciphertext, cache=False)
        prior = buffertools.xorBuffers(ptext, plaintext)
        self.log_message("Encrypted block: %s to %s with prior %s" % (repr(plaintext),
                                                                      repr(bytes(ciphertext)),
                                                                      repr(bytes(prior))))
        return prior,ciphertext
    
    
    def encrypt(self, plaintext, ciphertext=None):
        """Encrypts a plaintext value through "CBC-R" style prior-block
        propagation.
        
        Returns a tuple of the IV and ciphertext.  

        NOTE: If your target messages do not include an IV with the
        ciphertext, you can instead opt to encrypt a suffix of the
        message and include the IV in the the middle of the ciphertext as 
        if it were an encrypted block. This one block alone will decrypt
        to an uncontrollable random value, but with careful placement,
        this might be ok.

        """
        
        blocks = buffertools.splitBuffer(buffertools.pkcs7PadBuffer(plaintext, self.block_size), 
                                         self.block_size)
        if ciphertext not in (None, b''):
            if len(ciphertext) % self.block_size != 0:
                raise InvalidBlockError(self.block_size,len(ciphertext))

            cblocks = buffertools.splitBuffer(ciphertext, self.block_size)
            prior = cblocks[0]

            # remove first block from ciphertext since it'll be re-added later
            # after the prior is converted to finished ciphertext.
            del cblocks[0]
            ciphertext = b''.join(cblocks)

            # now remove the plaintext blocks we've already completed
            num_finished = len(cblocks)
            del blocks[len(blocks)-num_finished:]
            self.log_message("Reusing previous decryption of final %d blocks" % num_finished)
            
        elif (len(self.decrypted) >= self.block_size
            and len(self._ciphertext) >= 2*self.block_size):
            
            self.log_message("Reusing previous decryption of final block")

            # If possible, reuse work from prior decryption efforts on original
            # message for last block
            old_prior = self._ciphertext[0-self.block_size*2:0-self.block_size]
            final_plaintext = self.decrypted[0-self.block_size:]
            prior = buffertools.xorBuffers(old_prior,
                                           buffertools.xorBuffers(final_plaintext, blocks[-1]))
            ciphertext = self._ciphertext[0-self.block_size:]
            del blocks[-1]
        else:
            self.log_message("Starting decryption from scratch with random final block")
            
            # Otherwise, select a random last block and generate the prior block
            prior = struct.pack("B"*self.block_size, 
                                     *[random.getrandbits(8) for i in range(self.block_size)])
            ciphertext = b''

        self.log_message("Encrypting %d blocks..." % len(blocks))
        try:
            # Continue generating all prior blocks
            for i in range(len(blocks)-1, -1, -1):
                prior,cblock = self.encrypt_block(blocks[i],prior)
                ciphertext = cblock+ciphertext
        except Exception as e:
            self.log_message("Encryption failure. prior+ciphertext: %s" % repr(prior+ciphertext))

        # prior as IV
        return prior,ciphertext
