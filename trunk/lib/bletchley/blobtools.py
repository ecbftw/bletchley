'''
A collection of tools to assist in analyzing encrypted blobs of data

Copyright (C) 2011-2012 Virtual Security Research, LLC
Author: Timothy D. Morgan, Jason A. Donenfeld

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

import sys
import string
import base64
import binascii
import urllib
import fractions
import operator
import functools
import itertools
import buffertools

# abstract class
class DataEncoding(object):
    charset = frozenset('')
    dialect = None
    name = None
    priority = None

    def __init__(self, dialect=''):
        self.dialect = dialect

    def isExample(self, blob):
        sblob = frozenset(blob)
        if self.charset != None and not sblob.issubset(self.charset):
            return False
        return self.extraTests(blob)
    
    def extraTests(self, blob):
        """May return True, False, or None, for is an example, isn't an
        example, or unknown, respectively. 

        """
        return True

    def decode(self, blob):
        return None

    def encode(self, blob):
        return None


class base64Encoding(DataEncoding):
    name = 'base64'
    def __init__(self, dialect='rfc3548'):
        super(base64Encoding, self).__init__(dialect)
        if dialect.startswith('rfc3548'):
            self.c62 = '+'
            self.c63 = '/'
            self.pad = '='
        elif dialect.startswith('filename'):
            self.c62 = '+'
            self.c63 = '-'
            self.pad = '='
        elif dialect.startswith('url1'):
            self.c62 = '-'
            self.c63 = '_'
            self.pad = '='
        elif dialect.startswith('url2'):
            self.c62 = '-'
            self.c63 = '_'
            self.pad = '.'
        elif dialect.startswith('url3'):
            self.c62 = '_'
            self.c63 = '-'
            self.pad = '.'
        elif dialect.startswith('url4'):
            self.c62 = '-'
            self.c63 = '_'
            self.pad = '!'
        elif dialect.startswith('url5'):
            self.c62 = '+'
            self.c63 = '/'
            self.pad = '$'
        elif dialect.startswith('otkurl'):
            self.c62 = '-'
            self.c63 = '_'
            self.pad = '*'
        elif dialect.startswith('xmlnmtoken'):
            self.c62 = '.'
            self.c63 = '-'
            self.pad = '='
        elif dialect.startswith('xmlname'):
            self.c62 = '_'
            self.c63 = ':'
            self.pad = '='
        
        self.charset = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                                 +'abcdefghijklmnopqrstuvwxyz0123456789'
                                 +self.c62+self.c63+self.pad)

    def _guessPadLength(self, nopad_len):
        length = ((4 - nopad_len % 4) % 4)
        if length != 3:
            return length
        return None

    def extraTests(self, blob):
        nopad = blob.rstrip(self.pad)
        padlen_guess = self._guessPadLength(len(nopad))
        if padlen_guess == None:
            return False

        # we don't accept bad pads, only missing pads
        if self.dialect.endswith('nopad'):
            return self.pad not in blob

        # pad must not appear in the middle of the 
        # string and must be the correct length at the end
        return (self.pad not in nopad) and (len(blob) == len(nopad)+padlen_guess)

    def decode(self, blob):
        if self.dialect.endswith('nopad'):
            if self.pad in blob:
                raise Exception("Unpadded base64 string contains pad character")

            padlen = self._guessPadLength(len(blob))
            if padlen == None:
                raise Exception("Invalid length for unpadded base64 string.")

            blob = blob+(self.pad*padlen)

        if not self.dialect.startswith('rfc3548'):
            table = string.maketrans(self.c62+self.c63+self.pad, '+/=')
            blob = blob.translate(table)

        return base64.standard_b64decode(blob)


    def encode(self, blob):
        ret_val = base64.standard_b64encode(blob)

        if not self.dialect.startswith('rfc3548'):
            table = string.maketrans('+/=', self.c62+self.c63+self.pad)
            ret_val = ret_val.translate(table)

        if ret_val != None and self.dialect.endswith('nopad'):
            ret_val = ret_val.rstrip(self.pad)

        return ret_val


class base32Encoding(DataEncoding):
    name = 'base32'
    def __init__(self, dialect='rfc3548upper'):
        super(base32Encoding, self).__init__(dialect)
        if dialect.startswith('rfc3548upper'):
            self.pad = '='
            self.charset = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'+self.pad)

        elif dialect.startswith('rfc3548lower'):
            self.pad = '='
            self.charset = frozenset('abcdefghijklmnopqrstuvwxyz234567'+self.pad)

    def _guessPadLength(self, nopad_len):
        pad_lengths = {0:0, 7:1, 5:3, 4:4, 2:6}
        return pad_lengths.get(nopad_len%8, None)  

    def extraTests(self, blob):
        nopad = blob.rstrip(self.pad)
        padlen_guess = self._guessPadLength(len(nopad))
        if padlen_guess == None:
            return False

        # we don't accept bad pads, only missing pads
        if self.dialect.endswith('nopad'):
            return self.pad not in blob

        # pad must not appear in the middle of the 
        # string and must be the correct length at the end
        return (self.pad not in nopad) and (len(blob) == len(nopad)+padlen_guess)


    def decode(self, blob):
        if self.dialect.endswith('nopad'):
            if self.pad in blob:
                raise Exception("Unpadded base64 string contains pad character")

            padlen = self._guessPadLength(len(blob))
            if padlen == None:
                raise Exception("Invalid length for unpadded base64 string.")

            blob = blob+(self.pad*padlen)

        return base64.b32decode(blob.upper())


    def encode(self, blob):
        ret_val = base64.b32encode(blob)

        if ret_val != None and self.dialect.endswith('nopad'):
            ret_val = ret_val.rstrip(self.pad)

        if 'lower' in self.dialect:
            ret_val = ret_val.lower()
        else:
            ret_val = ret_val.upper()

        return ret_val


class hexEncoding(DataEncoding):
    name = 'hex'
    def __init__(self, dialect='mixed'):
        super(hexEncoding, self).__init__(dialect)
        if 'mixed' in dialect:
            self.charset = frozenset('ABCDEFabcdef0123456789')
        elif 'upper' in dialect:
            self.charset = frozenset('ABCDEF0123456789')            
        elif 'lower' in dialect:
            self.charset = frozenset('abcdef0123456789')


    def extraTests(self, blob):
        return (len(blob) % 2 == 0)

    def decode(self, blob):
        return binascii.a2b_hex(blob)

    def encode(self, blob):
        if 'upper' in self.dialect:
            return binascii.b2a_hex(blob).upper()
        if 'lower' in self.dialect:
            return binascii.b2a_hex(blob).lower()
        else:
            return binascii.b2a_hex(blob)


class percentEncoding(DataEncoding):
    name = 'percent'
    def __init__(self, dialect='mixed'):
        super(percentEncoding, self).__init__(dialect)
        self.charset = None
        if 'mixed' in dialect:
            self.hexchars = frozenset('ABCDEFabcdef0123456789')
        elif 'upper' in dialect:
            self.hexchars = frozenset('ABCDEF0123456789')            
        elif 'lower' in dialect:
            self.hexchars = frozenset('abcdef0123456789')

    def extraTests(self, blob):
        chunks = blob.split('%')
        if len(chunks) < 2:
            return None
        for c in chunks[1:]:
            if len(c) < 2:
                return False
            if (c[0] not in self.hexchars) or (c[1] not in self.hexchars):
                return False
        return True

    def decode(self, blob):
        if 'plus' in self.dialect:
            return urllib.unquote(blob)
        else:
            return urllib.unquote_plus(blob)

    # XXX: should technically produce quoted digits in same upper/lower case
    def encode(self, blob):
        if 'plus' in self.dialect:
            return urllib.quote(blob)
        else:
            return urllib.quote_plus(blob)


priorities = [
    (hexEncoding, 'upper', 100),
    (hexEncoding, 'lower', 101),
    (hexEncoding, 'mixed', 102),
    (base32Encoding, 'rfc3548upper', 150),
    (base32Encoding, 'rfc3548lower', 151),
    (base32Encoding, 'rfc3548upper-nopad', 160),
    (base32Encoding, 'rfc3548lower-nopad', 161),
    (base64Encoding, 'rfc3548', 200),
    (base64Encoding, 'rfc3548-nopad', 201),
    (base64Encoding, 'filename', 210),
    (base64Encoding, 'filename-nopad', 211),
    (base64Encoding, 'url1', 230),
    (base64Encoding, 'url1-nopad', 231),
    (base64Encoding, 'otkurl', 235),
    (base64Encoding, 'otkurl-nopad', 236),
    (base64Encoding, 'url2', 240),
    (base64Encoding, 'url2-nopad', 241),
    (base64Encoding, 'url3', 250),
    (base64Encoding, 'url3-nopad', 251),
    (base64Encoding, 'url4', 260),
    (base64Encoding, 'url4-nopad', 261),
    (base64Encoding, 'url5', 265),
    (base64Encoding, 'url5-nopad', 266),
    (base64Encoding, 'xmlnmtoken', 270),
    (base64Encoding, 'xmlnmtoken-nopad', 271),
    (base64Encoding, 'xmlname', 280),
    (base64Encoding, 'xmlname-nopad', 281),
    (percentEncoding, 'upper-plus', 400),
    (percentEncoding, 'upper', 401),
    (percentEncoding, 'lower-plus', 410),
    (percentEncoding, 'lower', 411),
    (percentEncoding, 'mixed-plus', 420),
    (percentEncoding, 'mixed', 421),
    ]

encodings = {}
for enc,d,p in priorities:
    e = enc(d)
    e.priority = p
    encodings["%s/%s" % (enc.name, d)] = e

def supportedEncodings():
    e = encodings.keys()
    e.sort()
    return e


def possibleEncodings(blob):
    likely = set()
    possible = set()
    for name,encoding in encodings.items():
        result = encoding.isExample(blob)
        if result == True:
            likely.add(name)
        elif result == None:
            possible.add(name)
    return likely,possible


def encodingIntersection(blobs):
    ret_val = set(encodings.keys())
    p = set(encodings.keys())
    for b in blobs:
        likely,possible = possibleEncodings(b)
        ret_val &= likely | possible
        p &= possible
    return ret_val - p


def bestEncoding(encs):
    priority = 999999999
    best = None
    for e in encs:
        if encodings[e].priority < priority:
            best = e
            priority = encodings[e].priority
    return best


def decode(encoding, blob):
    return encodings[encoding].decode(blob)

def encode(encoding, blob):
    return encodings[encoding].encode(blob)

def decodeAll(encoding, blobs):
    return map(encodings[encoding].decode, blobs)

def encodeAll(encoding, blobs):
    return map(encodings[encoding].encode, blobs)

def decodeChain(decoding_chain, blob):
    for decoding in decoding_chain:
        blob = decode(decoding, blob)
    return blob

def encodeChain(encoding_chain, blob):
    for encoding in encoding_chain:
        blob = encode(encoding, blob)
    return blob

def getLengths(s):
    lengths = set()
    for bin in s:
        lengths.add(len(bin))
    lengths = list(lengths)
    lengths.sort()
    return lengths


def maxBlockSize(blob_lengths):
    divisor = 0
    for bl in blob_lengths:
        divisor = fractions.gcd(divisor, bl)

    return divisor


allTrue = functools.partial(reduce, (lambda x,y: x and y))

def checkCommonBlocksizes(lengths):
    common_block_sizes = (8,16,20)
    ret_val = []
    for cbs in common_block_sizes:
        gcdIsCBS = (lambda x: fractions.gcd(x,cbs)==cbs)
        if allTrue(map(gcdIsCBS, lengths)):
            ret_val.append(cbs)
    return ret_val


def int2binary(x, bits=8):
        """
        Integer to binary
        Count is number of bits
        """
        return "".join(map(lambda y:str((x>>y)&1), range(bits-1, -1, -1)))


#XXX: move this to buffertools
def smartPermutateBlobs(blobs, block_size=8):
    """
    Intelligently permutates through blocks in blobs.
    If the same blob shows up in the same place for
    every blob, the resultant permutations will have
    this property as well.
    blobs should be an array containing blobs
    block_size should be an integer block_size or an
    array of block sizes.
    """

    if len(blobs) == 0:
        return

    if not isinstance(block_size, (int, long)):
        for size in block_size:
             for blob in smartPermutateBlobs(blobs, size):
                 yield blob
        return

    # First we find the indexes of the chunks that are different
    different = set()
    for combo in itertools.combinations(blobs, 2):
        different |= set(buffertools.blockWiseDiff(block_size, combo[0], combo[1]))
    
    # Next we form a set containing the chunks that are different
    different_chunks = []
    for blob in blobs:
        different_chunks.extend([blob[i * block_size:(i + 1) * block_size] for i in different])
    # Remove duplicates
    different_chunks = set(different_chunks)
    
    # We want to know which chunks are the same, too
    chunk_len = len(blobs[0]) / block_size
    same = set(range(0, chunk_len)) - different

    # Now let's mix and match the differnet blocks, for all possible lengths
    for i in range(1, chunk_len + 1):
        for mix in itertools.permutations(different_chunks, i):
            # We add back in the part that stays the same
            for j in same:
                mix.insert(j, blobs[0][j * block_size:(j + 1) * block_size])
            mix = "".join(mix)
            if mix in blobs:
                continue
            yield mix 
