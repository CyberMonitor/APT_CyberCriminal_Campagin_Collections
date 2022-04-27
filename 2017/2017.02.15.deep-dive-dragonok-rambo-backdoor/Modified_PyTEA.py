#!/usr/bin/env python

#################################################################################

# Python implementation of the Tiny Encryption Algorithm (TEA)

# By Moloch

#

# About: TEA has a few weaknesses. Most notably, it suffers from

#        equivalent keys each key is equivalent to three others,

#        which means that the effective key size is only 126 bits.

#        As a result, TEA is especially bad as a cryptographic hash

#        function. This weakness led to a method for hacking Microsoft's

#        Xbox game console (where I first encountered it), where the

#        cipher was used as a hash function. TEA is also susceptible

#        to a related-key attack which requires 2^23 chosen plaintexts

#        under a related-key pair, with 2^32 time complexity.

#

#        Block size: 64bits

#          Key size: 128bits

#

##################################################################################



import os

import getpass

import platform

import struct


from random import choice

from hashlib import sha256

from ctypes import c_uint32

from string import ascii_letters, digits


if platform.system().lower() in ['linux', 'darwin']:

    INFO = "\033[1m\033[36m[*]\033[0m "

    WARN = "\033[1m\033[31m[!]\033[0m "

else:

    INFO = "[*] "

    WARN = "[!] "


### Magical Constants

DELTA = 0x9e3779b9

SUMATION = 0xc6ef3720

ROUNDS = 32

BLOCK_SIZE = 2  # number of 32-bit ints

KEY_SIZE = 4



### Functions ###

def encrypt_block(block, key, verbose=False):

    '''

    Encrypt a single 64-bit block using a given key

    @param block: list of two c_uint32s

    @param key: list of four c_uint32s

    '''

    assert len(block) == BLOCK_SIZE

    assert len(key) == KEY_SIZE

    sumation = c_uint32(0)

    delta = c_uint32(DELTA)

    for index in range(0, ROUNDS):

        sumation.value += delta.value

        block[0].value += ((block[1].value << 4) + key[0].value) ^ (block[1].value + sumation.value) ^ ((block[1].value >> 5) + key[1].value)

        block[1].value += ((block[0].value << 4) + key[2].value) ^ (block[0].value + sumation.value) ^ ((block[0].value >> 5) + key[3].value)

        if verbose: print("\t--> Encrypting block round %d of %d" % (index + 1, ROUNDS))

    return block


def decrypt_block(block, key, verbose=False):

    '''

    Decrypt a single 64-bit block using a given key

    @param block: list of two c_uint32s

    @param key: list of four c_uint32s

    '''

    assert len(block) == BLOCK_SIZE

    assert len(key) == KEY_SIZE

    sumation = c_uint32(SUMATION)

    delta = c_uint32(DELTA)

    for index in range(0, ROUNDS):

        block[1].value -= ((block[0].value << 4) + key[2].value) ^ (block[0].value + sumation.value) ^ ((block[0].value >> 5) + key[3].value);

        block[0].value -= ((block[1].value << 4) + key[0].value) ^ (block[1].value + sumation.value) ^ ((block[1].value >> 5) + key[1].value);

        sumation.value -= delta.value

        if verbose: print("\t<-- Decrypting block round %d of %d" % (index + 1, ROUNDS))

    return block


def to_c_array(data):

    ''' Converts a string to a list of c_uint32s '''

    c_array = []

    for index in range(0, len(data)/4):

        chunk = data[index*4:index*4+4]

        packed = struct.unpack(">L", chunk)[0]

        c_array.append(c_uint32(packed))

    return c_array


def to_string(c_array):

    ''' Converts a list of c_uint32s to a Python (ascii) string '''

    output = ''

    for block in c_array:

        output += struct.pack(">L", block.value)

    return output


def random_chars(nchars):

    chars = ''

    for n in range(0, nchars):

        chars += choice(ascii_letters + digits)

    return chars


def add_padding(data, verbose=False):

    pad_delta = 4 - (len(data) % 4)

    if verbose:

        print(INFO + "Padding delta: %d" % pad_delta)

    data += random_chars(pad_delta)

    data += "%s%d" % (random_chars(3), pad_delta)

    return data


def encrypt(data, key, verbose=False):

    '''

    Encrypt string using TEA algorithm with a given key

    '''

    data = add_padding(data, verbose)

    data = to_c_array(data)

    key = to_c_array(key.encode('ascii', 'ignore'))

    cipher_text = []

    for index in range(0, len(data), 2):

        if verbose:

            print(INFO + "Encrypting block %d" % index)

        block = data[index:index + 2]

        block = encrypt_block(block, key, verbose)

        for uint in block:

            cipher_text.append(uint)

    if verbose:

        print(INFO + "Encryption completed successfully")

    return to_string(cipher_text)


def decrypt(data, key, verbose=False):

    data = to_c_array(data)

    key = to_c_array(key.encode('ascii', 'ignore'))

    plain_text = []

    for index in range(0, len(data), 2):

        if verbose:

            print(INFO + "Encrypting block %d" % index)

        block = data[index:index + 2]

        decrypted_block = decrypt_block(block, key, verbose)

        for uint in decrypted_block:

            plain_text.append(uint)

    data = to_string(plain_text)

    if verbose:

        print(INFO + "Decryption compelted successfully")

    return data


def get_key(password=''):

    ''' Generate a key based on user password '''

    if 0 == len(password):

        password = getpass.getpass(INFO + "Password: ")

    sha = sha256()

    sha.update(password + "Magic Static Salt")

    sha.update(sha.hexdigest())

    return ''.join([char for char in sha.hexdigest()[::4]])


def encrypt_file(fpath, key, verbose=False):

    with open(fpath, 'rb+') as fp:

        data = fp.read()

        cipher_text = encrypt(data, key, verbose)

        fp.seek(0)

        fp.write(cipher_text)

    fp.close()


def decrypt_file(fpath, key, verbose=False):

    with open(fpath, 'rb+') as fp:

        data = fp.read()

        plain_text = decrypt(data, key, verbose)

        fp.close()

    fp = open(fpath, 'w')

    fp.write(plain_text)

    fp.close()



### UI Code ###

if __name__ == '__main__':

    from argparse import ArgumentParser

    parser = ArgumentParser(

        description='Python implementation of the TEA cipher',

    )

    parser.add_argument('-e', '--encrypt',

        help='encrypt a file',

        dest='epath',

        default=None

    )

    parser.add_argument('-d', '--decrypt',

        help='decrypt a file',

        dest='dpath',

        default=None

    )

    parser.add_argument('--verbose',

        help='display verbose output',

        default=False,

        action='store_true',

        dest='verbose'

    )

    args = parser.parse_args()

    if args.epath is None and args.dpath is None:

        print('Error: Must use --encrypt or --decrypt')

    elif args.epath is not None:

        print(WARN + 'Encrypt Mode: The file will be overwritten')

        if os.path.exists(args.epath) and os.path.isfile(args.epath):

            key = get_key()

            encrypt_file(args.epath, key, args.verbose)

        else:

            print(WARN + 'Error: target does not exist, or is not a file')

    elif args.dpath is not None:

        print(WARN + 'Decrypt Mode: The file will be overwritten')

        if os.path.exists(args.dpath) and os.path.isfile(args.dpath):

            key = get_key()

            decrypt_file(args.dpath, key, args.verbose)

        else:

            print(WARN + 'Error: target does not exist, or is not a file')
