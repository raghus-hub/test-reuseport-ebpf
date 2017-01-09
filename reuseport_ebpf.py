#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
import sys
import socket
import os
import time
import multiprocessing as mp
import argparse

SO_ATTACH_REUSEPORT_EBPF=52

parser = argparse.ArgumentParser()
parser.add_argument('--port', dest='listen_port', type=int, default=8888,
                    help='Listening port for the echo server [default: 8888]')
parser.add_argument('--enable-filter', dest='enable_filter',
                    action='store_true',
                    help='Enable eBPF on the listening socket [default: false]')
args = parser.parse_args()


def process_function(p_lock, n_kids):
  try:
    main_function(p_lock, n_kids)
  except (KeyboardInterrupt, SystemExit):
    pass
  except:
    raise

def setup_socket(child_id):
  listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
  bpf = ()
  # Doing the following in multiple children screws up the REUSEPORT options on the socket and 
  # calling bind multiple times will result in EADDRINUSE Error. This issue
  # does not happen if EBPF filter is not being added (TBD: Need to debug this.. kernel issue?)
  if (args.enable_filter and child_id == 0) :
    print("[pid %d] Loading the BPF Program..." % os.getpid(), end='')
    bpf = BPF(src_file="bpf_filter.c", debug = 0)
    bpf_filter_fn = bpf.load_func("bpf_socket_filter", BPF.SOCKET_FILTER)
    listen_sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, bpf_filter_fn.fd)
    print("Done")

  print("[pid %d] Binding the  Listening Socket on port %d..." %
        (os.getpid(), args.listen_port), end='')
  try:
    listen_sock.bind(('', args.listen_port))
  except socket.error as msg:
    print("Failed. Error(%s): %s" % (str(msg[0]),  msg[1]))
    sys.exit()
  listen_sock.listen(5)
  print("Done")
  return (listen_sock, bpf);

def main_function(p_lock, n_kids):
  (listen_sock, junk)  = setup_socket(n_kids.value)
  n_kids.value = n_kids.value+1
  print('[Server pid: %d] Ready' % os.getpid())
  # Process the connections 
  while True:
    conn, addr = listen_sock.accept()
    p_lock.acquire()
    try:
      print('Connected to {}'.format(os.getpid()))
    finally:
      p_lock.release()
    data = '[Server pid: ' + str(os.getpid()) + '] '
    data = data + conn.recv(1024)
    conn.send(data)
    conn.close()

if __name__ == '__main__':
  # Synchronize prints done in the 2 processes using mp.Lock
  try:
    print("[pid: %d] Parent Ready\n" % os.getpid())

    lock = mp.Lock()
    num_children = mp.Value('i', 0)
    for num in range(2):
      proc = mp.Process(target=process_function, args=(lock, num_children))
      proc.start()
      while (num_children.value == num):
        time.sleep(0.1)
        if not proc.is_alive():
          print("Child died before the system was ready... Exiting")
          sys.exit()
    print("\n[pid %d] System Ready For Testing" % os.getpid()) 
    while mp.active_children():
      time.sleep(5)
  except (KeyboardInterrupt, SystemExit):
    pass
  except:
    raise
