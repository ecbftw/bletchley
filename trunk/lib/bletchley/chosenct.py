'''
A collection of tools to assist in analyzing encrypted data 
through chosen ciphertext attacks.

Copyright (C) 2012-2013 Virtual Security Research, LLC
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
import threading
import struct
import queue

def probe_bytes(checker, ciphertext, values, max_threads=1):
    '''For each offset in the ciphertext, XORs each of the values with
    it and sends it to the checker to determine what kind of response or
    error message was generated.

    TODO
    '''
    if max_threads < 1:
        return None

    ciphertext = bytearray(ciphertext)
    values = bytearray(values)

    ret_val = {}
    num_threads = min(len(values),max_threads)
    threads = []
    for j in range(0,len(ciphertext)):
        prefix = ciphertext[0:j]
        target = ciphertext[j]
        suffix = ciphertext[j+1:]
        results = queue.Queue()
        for i in range(0,num_threads):
            subset = [values[s] for s in range(i,len(values),num_threads)]
            t = threading.Thread(target=probe_worker, 
                                 args=(checker, prefix, suffix, target,
                                       subset, results))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        ret_val[j] = {}
        while not results.empty():
            ret_val[j].update(results.get())

    return ret_val


def probe_worker(checker, prefix, suffix, target, value_subset, results):
    for v in value_subset:
        results.put({v:checker(prefix+bytearray((v^target,))+suffix)})

