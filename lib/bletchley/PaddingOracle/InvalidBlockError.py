'''
Created on Jul 4, 2010

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

class InvalidBlockError(Exception):
    '''
    classdocs
    '''

    

    def __init__(self, expectedSize, receivedSize):
        self.expected = expectedSize
        self.received = receivedSize
    def __str__(self):
        return "Invalid block size: "+self.received+" bytes. Block must be "+self.expected+" bytes long."
