'''
Created on Sep 21, 2010

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

import web
import struct
from Crypto.Cipher import AES
from base64 import b64decode,b64encode
import time

urls = ( '/padding/', 'padding')
app = web.application(urls, globals())

key = "cacacacacacacaca"

def oracle(ctext):
	oracleCipher = AES.new(key,AES.MODE_CBC,"\x00"*16)
	ptext = oracleCipher.decrypt(ctext)
	paddingLen = struct.unpack("B",ptext[-1])[0]
	goodPadding = (ptext[-paddingLen:] == struct.pack("B",paddingLen)*paddingLen)
	
	return goodPadding

def encrypt(data):
	paddingLen = 16 - len(data) % 16
	data = data + struct.pack("B",paddingLen)*paddingLen
	cipher = AES.new(key,AES.MODE_CBC,"\x00"*16)
	return b64encode(cipher.encrypt(data))

class padding:
	def GET(self):		
		i = web.input(msg='secret!')
		return encrypt(i.msg)
	
	def POST(self):
		i = web.input(ctext=None)
		if(i.ctext!=None and oracle(b64decode(i.ctext))):
			time.sleep(1)
		return "Yeah!"

if __name__ == "__main__": app.run()
