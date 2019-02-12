#!/usr/bin/python

#############################################################################
##                                                                         ##
##  Quick script to get information from Vinself bitmap files              ##
##  HC128 class from https://github.com/nnazifi/HC128_Python               ##
##                                                                         ##
##  Copyright (C) 2014 Airbus Defence and Space Cybersecurity              ##
##                                                                         ##
##  This program is free software; you can redistribute it and/or modify   ##
##  it under the terms of the GNU General Public License as published by   ##
##  the Free Software Foundation; either version 2 of the License, or      ##
##  (at your option) any later version.                                    ##
##                                                                         ##
##  This program is distributed in the hope that it will be useful,        ##
##  but WITHOUT ANY WARRANTY; without even the implied warranty of         ##
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          ##
##  GNU General Public License for more details.                           ##
##                                                                         ##
##  Author: Fabien Perigaud                                                ##
##                                                                         ##
#############################################################################

# Sample:
# MD5         | 97fa1056c791110730b50ca89fdc2c3e
# SHA1        | 388d7cd368a15dd94410fd61581c6f3c6913f386
# SHA256      | dd2809b8f6de53c4614da77b5d5b37e57eb8c8eb83ab19ea13cfd131a3c1c6f5

from hc128 import hc128
import Image   
import sys
import struct

def array_to_chr(arr):
    v=0
    for b in arr:
        v = (v<<1) + b
    return chr(v)

def vinself_cipher(x, key):
    output = ""
    lkey = ord(x[0])
    for i in xrange(len(x)-1):
        output += chr( ( ( ord(x[i+1]) ^ ord(key[i%len(key)]) ) - lkey) & 0xff)
        lkey = ord(x[i+1])
    return output

if len(sys.argv) != 3:
    print "usage: %s <bitmap file> <key>" % sys.argv[0]
    sys.exit(-1)

file_name = sys.argv[1]
binary_key = sys.argv[2]

### STEGANO PART ###

img = Image.open(file_name)
pixels = img.load()

(width, height) = img.size
hidden_bits = []

for y in xrange(height):
    for x in xrange(width):
        for k in xrange(3):
            hidden_bits.append( pixels[x,y][k] & 0x1 )

info = ''.join( array_to_chr(hidden_bits[x:x+8][::-1]) for x in xrange(0, len(hidden_bits), 8) )
info = info[:info.find("\0\0\0\0\0")]

### STRUCTURE PARSING ###

(sz1,sz2) = struct.unpack(">2H",info[:4])
udata = info[4:]

data1 = udata[:sz2+1]
data2 = udata[sz2+1:sz2+1+0x21]

packet_key = vinself_cipher(data1, binary_key)

hc128_key = vinself_cipher(data2, packet_key)

print "[+] Key:", hc128_key

hc128_key_bswap = ""
for x in xrange(0, len(hc128_key), 4):
    hc128_key_bswap += hc128_key[x:x+4][::-1]

### HC-128 ###

size_deciph = sz1-sz2-0x23+1
offset = sz2+0x22
if (len(udata)-offset) != size_deciph:
    print "[-] Warning, size mismatch"

ciph_data = udata[offset:]

clear_text = hc128.decrypt(ciph_data, hc128_key_bswap)

### FINAL CIPHER ###

final_clear = vinself_cipher(clear_text, packet_key)

print "[+] Clear:", final_clear
