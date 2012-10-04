'''
A collection of tools to assist in analyzing encrypted blobs of data 
through chosen plaintext attacks.

Copyright (C) 2011-2012 Virtual Security Research, LLC
Author: Timothy D. Morgan

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
from buffertools import blockWiseDiff


# Chosen plaintext attack on ECB encryption
#
# The encryptionOracle should accept a single string argument, 
# encrypt that argument as part of a larger (unknown) plaintext string,
# and then return the ciphertext.
#
# This function will then return a dictionary with information about the 
# algorithm and chosen string attributes, including:
#  block_size - the algorithm's block size
#  chosen_offset - the chosen string's offset within the plaintext
#  fragment_length - the length of a chosen from the chosen_offset to the
#                    end of its current block
#
def ECB_FindChosenOffset(encryptionOracle):
    ret_val = {}

    # Guaranteed to have one block boundary on 128 bit block ciphers
    chosen_length = 17
    chosen = 'O'*chosen_length
    base = encryptionOracle(chosen)

    chosen = 'X' + 'O'*(chosen_length-1)
    test_result = encryptionOracle(chosen)

    different_blocks = blockWiseDiff(1, base, test_result)
    block_size = len(different_blocks)
    # Sanity check
    different_blocks = blockWiseDiff(block_size, base, test_result)
    if different_blocks == None:
        sys.stderr.write("ERROR: Block size test yielded undiff-able ciphertexts.\n")
        return None
    if len(different_blocks) > 1:
        sys.stderr.write("ERROR: Block size test yielded multiple altered blocks (not ECB mode?).\n")
        return None

    for i in range(2,chosen_length):
        chosen = 'X'*i + 'O'*(chosen_length-i)
        test_result = encryptionOracle(chosen)
        different_blocks = blockWiseDiff(block_size, base, test_result)
        
        if different_blocks == None or len(different_blocks) == 0 or len(different_blocks) > 2:
            sys.stderr.write("ERROR: Offset detection yielded inconsistent block diffs.\n")
            return None
        if len(different_blocks) == 2:
            break

    ret_val['block_size'] = block_size
    ret_val['fragment_length'] = i-1
    ret_val['chosen_offset'] = max(different_blocks)*block_size - ret_val['fragment_length']

    return ret_val
