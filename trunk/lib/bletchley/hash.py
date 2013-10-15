'''
Tools for helping with hash-related attacks

Copyright (C) 2013 Virtual Security Research, LLC
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
import subprocess
import ast
import os
from . import blobtools



def compute_length_extension(data, signature, appended, key_length):
    '''A crude wrapper around HashPump for conducting HLE attacks.
    HashPump must be installed and available in the current PATH.
    For more info, see: https://github.com/bwall/HashPump
    
    The data, signature, and appended parameters must be provided as
    bytes objects.  The key_length parameter must be an integer.

    Returns a 2-tuple of ({new_data}, {new_signature}) in their binary forms.
    '''

    signature = blobtools.encode('hex/lower', signature)

    process = subprocess.Popen(['/usr/bin/env', 'HashPump', '-s', signature, '-d', data, 
                                '-a', appended, '-k', "%d" % key_length],
                               bufsize=1, stdout=subprocess.PIPE, shell=False, 
                               close_fds=True, env=os.environ)
    new_signature = process.stdout.readline().strip()
    new_data = process.stdout.readline().strip().decode('utf-8')
    process.wait()

    new_signature = blobtools.decode('hex/lower', new_signature)
    new_data = ast.literal_eval("b'''"+new_data.replace("'", "\\x27")+"'''")

    return (new_data,new_signature)
