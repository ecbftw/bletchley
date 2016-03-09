'''
Utilities for manipulating certificates and SSL/TLS connections.

Copyright (C) 2016 Blindspot Security LLC
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
import argparse
import traceback
import socket
try:
    import OpenSSL
    from OpenSSL import SSL
except:
    sys.stderr.write('ERROR: Could not locate pyOpenSSL module.  Under Debian-based systems, try:\n')
    sys.stderr.write('       # apt-get install python3-openssl\n')
    sys.stderr.write('NOTE: pyOpenSSL version 0.14 or later is required!\n')
    sys.exit(2)
try:
    import cffi
except:
    sys.stderr.write('ERROR: Could not locate cffi module.  Under Debian-based systems, try:\n')
    sys.stderr.write('       # apt-get install python3-cffi\n')
    sys.stderr.write('NOTE: This is a requirement because pyOpenSSL does not provide '
                     'certificate extension removal procedures.  Consider lobbying for the '
                     'implementation of this:\n  https://github.com/pyca/pyopenssl/issues/152\n')
    sys.exit(2)


def createContext(method=SSL.TLSv1_METHOD, key=None, certChain=[]):
    context = SSL.Context(method)
    context.set_verify(SSL.VERIFY_NONE, (lambda a,b,c,d,e: True))
    if key and len(certChain) > 0:
        context.use_privatekey(key)
        context.use_certificate(certChain[0])
        for c in certChain[1:]:
            context.add_extra_chain_cert(c)
    
    return context


def startSSLTLS(sock, mode='client', handshake=SSL.TLSv1_METHOD, key=None, certChain=[]):
    conn = SSL.Connection(createContext(handshake, key=key, certChain=certChain), sock)
    if mode == 'client':
        conn.set_connect_state()
        conn.do_handshake()
    else:
        conn.set_accept_state()
    
    return conn


def ConnectSSLTLS(host, port):
    protocols = [("SSL 2/3", SSL.SSLv23_METHOD),
                 ("TLS 1.0", SSL.TLSv1_METHOD), 
                 ("TLS 1.1", SSL.TLSv1_1_METHOD),
                 ("TLS 1.2", SSL.TLSv1_2_METHOD),
                 ("SSL 3.0", SSL.SSLv3_METHOD),
                 ("SSL 2.0", SSL.SSLv2_METHOD)]

    conn = None
    for pname,p in protocols:
        serverSock = socket.socket()
        serverSock.connect((host,port))
        
        try:
            conn = startSSLTLS(serverSock, mode='client', handshake=p)
            break
        except ValueError as e:
            sys.stderr.write("%s handshake not supported by your openssl library, trying others...\n" % pname)
        except SSL.Error as e:
            sys.stderr.write("Exception during %s handshake with server." % pname)
            sys.stderr.write("\nThis could happen because the server requires "
                             "certain SSL/TLS versions or a client certificiate."
                             "  Have no fear, we'll keep trying...\n")            
        except Exception as e:
            sys.stderr.write("Unknown exception during handshake with server: \n")
            traceback.print_exc(file=sys.stderr)

    return conn


def fetchCertificateChain(connection):
    chain = connection.get_peer_cert_chain()
    if chain:
        return chain
    return None


def normalizeCertificateName(cert_name):
    n = cert_name.get_components()
    n.sort()
    return tuple(n)


def normalizeCertificateChain(chain):
    # Organize certificates by subject and issuer for quick lookups
    subject_table = {}
    issuer_table = {}
    for c in chain:
        subject_table[normalizeCertificateName(c.get_subject())] = c
        issuer_table[normalizeCertificateName(c.get_issuer())] = c

    # Now find root or highest-level intermediary
    root = None
    for c in chain:
        i = normalizeCertificateName(c.get_issuer())
        s = normalizeCertificateName(c.get_subject())
        if (i == s) or (i not in subject_table):
            if root != None:
                sys.stderr.write("WARN: Multiple root certificates found or broken certificate chain detected.")
            else:
                # Go with the first identified "root", since that's more likely to link up with the server cert
                root = c

    # Finally, build the chain from the top-down in the correct order
    new_chain = []
    nxt = root
    while nxt != None:
        new_chain = [nxt] + new_chain
        s = normalizeCertificateName(nxt.get_subject())
        nxt = issuer_table.get(s)
    
    return new_chain
    

def genFakeKey(certificate):
    fake_key = OpenSSL.crypto.PKey()
    old_pubkey = certificate.get_pubkey()
    fake_key.generate_key(old_pubkey.type(), old_pubkey.bits())

    return fake_key


def getDigestAlgorithm(certificate):
    # XXX: ugly hack because pyopenssl API for this is limited
    if b'md5' in certificate.get_signature_algorithm():
        return 'md5'
    else:
        return 'sha1'


def deleteExtension(certificate, index):
    '''
    A dirty hack until this is implemented in pyOpenSSL. See:
    https://github.com/pyca/pyopenssl/issues/152
    '''
    ffi = cffi.FFI()
    ffi.cdef('''void* X509_delete_ext(void* x, int loc);''')
    libssl = ffi.dlopen('libssl.so')
    ext = libssl.X509_delete_ext(certificate._x509, index)
    #XXX: memory leak.  supposed to free ext here


def removePeskyExtensions(certificate):
    #for index in range(0,certificate.get_extension_count()):
    #    e = certificate.get_extension(index)
    #    print("extension %d: %s\n" % (index, e.get_short_name()), e)

    index = 0
    while index < certificate.get_extension_count():
        e = certificate.get_extension(index)
        if e.get_short_name() in (b'subjectKeyIdentifier', b'authorityKeyIdentifier'):
            deleteExtension(certificate, index)
            #XXX: would be nice if each of these extensions were re-added with appropriate values
            index -= 1
        index += 1
    
    #for index in range(0,certificate.get_extension_count()):
    #    e = certificate.get_extension(index)
    #    print("extension %d: %s\n" % (index, e.get_short_name()), e)


def genFakeCertificateChain(cert_chain):
    ret_val = []
    cert_chain.reverse() # start with highest level authority

    c = cert_chain[0]
    i = normalizeCertificateName(c.get_issuer())
    s = normalizeCertificateName(c.get_subject())
    if s != i:
        # XXX: consider retrieving root locally and including a forged version instead
        c.set_issuer(c.get_subject())
    k = genFakeKey(c)
    c.set_pubkey(k)
    removePeskyExtensions(c)
    c.sign(k, getDigestAlgorithm(c))
    ret_val.append(c)

    prev = k
    for c in cert_chain[1:]:
        k = genFakeKey(c)
        c.set_pubkey(k)
        removePeskyExtensions(c)
        c.sign(prev, getDigestAlgorithm(c))
        prev = k
        ret_val.append(c)

    ret_val.reverse()
    return k,ret_val
