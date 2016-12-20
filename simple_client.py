#!/usr/bin/python

from __future__ import print_function
import argparse
import socket

parser = argparse.ArgumentParser()
parser.add_argument('--ip', dest='dest_ip', default='localhost',
                    help='Server IP to connect to [default: localhost]')
parser.add_argument('--port', dest='dest_port', default=8888,
                    help='Server port to connect to [default: 8888]')
parser.add_argument('--count', dest='count', default=20,
                    help='Number of connections (echo requests) to try [default: 20]')
parser.add_argument('msg', default='ECHO', help='Message to send to the server') 
args = parser.parse_args()


def echo_client(msg, dest_ip, dest_port):
  conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  conn.connect((dest_ip, dest_port))
  conn.send(msg.encode());
  data = conn.recv(1024).decode()
  print("Client Received: %r" % data)
  conn.close()

if __name__ == '__main__':
  for num in range(20):
    echo_client(args.msg, args.dest_ip, args.dest_port)



