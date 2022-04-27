#!/usr/local/bin/python

__author__ = "Juan C Cortes"
__version__ = "1.0"
__email__ = "jcortes@paloaltonetworks.com"

from random import randint
import zlib
import binascii
import sys
import logging
import hashlib
import argparse
import os
import struct
from tabulate import tabulate
from Crypto import Random
from Crypto.Cipher import AES

def parse_arguments():
    """Argument Parser"""
    parser = argparse.ArgumentParser(
        usage="Decrypt strings for VerminRAT")
    parser.add_argument(
        "-v",
        "--verbosity",
        action="store_true",
        dest="vverbose",
        help="Print debugging information")
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        type=str,
        help="Output results file")
    parser.add_argument(
        "input",
        type=str,
        action='store',
        help="Input file of newline separated strings or single string")
    parser.add_argument(
        "-b",
        "--blob",
        action='store_true',
        help="Param use for decrypting blobs of data instead of strings. Blob is autosave to 'blob.out'")
    return parser

def write_out(output_list, headers, output_file=False):
    """
    Pretty outputs list
    :param output_list: List to output
    """
    print tabulate(output_list, headers, tablefmt="simple")
    print ""
    if output_file:
        with open(output_file, "ab") as file:
            file.write(tabulate(output_list, headers, tablefmt="simple"))
            file.write("\n\n")

def generateArray():
    abyte = bytearray(6)
    for i in range(0,6):
       abyte[i] = randint(0, 0x7FFFFFFF) % 7

    return abyte;

def parseEncrypteStr(encryptStr):
    try:
        decoded = encryptStr.decode('base64')
        hardcoded_crc32 = decoded[-4:]
        parsedEncrypted = decoded[16:-4]
        iv = decoded[:16]
        return hardcoded_crc32,parsedEncrypted,iv
    except Exception as e:
        print e

def bruteForceCRC32Value(valuecrc32):
    while (True):
        arry = generateArray()
        crc32 = binascii.crc32(arry)
        crc32 = crc32 % (1 << 32)
        if crc32 == valuecrc32:
            return(arry)

def decryptStr(str,key,iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    blob = aes.decrypt(str)
    return blob

def parsePlainText(str):
    char = ""
    for i in str:
        if 0x20 <= ord(i) <= 0x127:
            char += i
        else:
            continue
    return char

def parseUnicde(str):
    try:
        uni = ""
        for i in range(0,len(str)/2):
            uni += str[i]
        return uni.decode('utf16')
    except Exception as e:
        print e

def main():
    """Main Method"""
    args = parse_arguments().parse_args()
    strs = []

    if args.vverbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format=' %(asctime)s - %(levelname)s - %(message)s')

    if args.blob and os.path.exists(args.input) != True:
        b = args.input
        crc32Hardcode, encryptedStr, iv = parseEncrypteStr(b)
        crc32Hardcode = bytearray(crc32Hardcode)
        crc32Hardcode = struct.unpack('<I', crc32Hardcode)[0]
        bruteArray = bruteForceCRC32Value(crc32Hardcode)
        m = hashlib.md5()
        m.update(bruteArray)
        key = m.digest()
        plain = decryptStr(encryptedStr, key, iv)
        with open('blob.out', "wb") as file:
            file.write(plain)


    if os.path.exists(args.input) != True:
        strs.append(args.input)

    else:
        with open(args.input, "rb") as open_file:
            for line in open_file:
                hash = line.rstrip()
                strs.append(hash)

    for s in strs:

        crc32Hardcode,encryptedStr,iv = parseEncrypteStr(s)
        crc32Hardcode = bytearray(crc32Hardcode)
        crc32Hardcode = struct.unpack('<I', crc32Hardcode)[0]
        bruteArray = bruteForceCRC32Value(crc32Hardcode)
        m = hashlib.md5()
        m.update(bruteArray)
        key = m.digest()
        plain = decryptStr(encryptedStr,key,iv)
        parsestr = parsePlainText(plain)
        unistr = parseUnicde(plain)
        headers = ["ASCII","UNICODE"]
        outputlist = [[parsestr,unistr]]
        write_out(outputlist, headers, args.output_file)

if __name__ == '__main__':
    main()
