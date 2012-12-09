'''
A collection of tools to assist in analyzing encrypted blobs of data 
through known plaintext attacks.

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

from buffertools import xorBuffers

# Attack OFB mode with static IV
#
def OFB_TestKnownPlaintext(plaintext, ciphertext1, ciphertext2):
    ret_val = []

    p1p2 = xorBuffers(ciphertext1,ciphertext2)
    for i in range(0,len(p1p2)-len(plaintext)):
        ret_val.append(xorBuffers(p1p2[i:i+len(plaintext)], plaintext))
        
    return ret_val

