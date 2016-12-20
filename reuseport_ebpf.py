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

def setup_socket(in_parent):
  listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
  bpf = ()
  # Doing the follwoing in children screws up the REUSEPORT options on teh socket and 
  # calling bind multiple times will result in EADDRINUSE Error. This issues
  # does not happen if EBPF filter is not being added
  if (args.enable_filter and in_parent) :
    print("[pid %d] Loading the BPF Program..." % os.getpid(), end='')
    bpf = BPF(src_file="bpf_filter.c", debug = 0)
    bpf_filter_fn = bpf.load_func("bpf_socket_filter", BPF.SOCKET_FILTER)
    listen_sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, bpf_filter_fn.fd)
    print("Done")

  # If bind and listen are not called in parent  the eBPF filter is not getting
  # called. Error?
  print("[pid %d] Binding the  Listening Socket on port %d..." %
        (os.getpid(), args.listen_port), end='')
  listen_sock.bind(('', args.listen_port))
  listen_sock.listen(1)
  print("Done")
  return (listen_sock, bpf);

def main_function(p_lock, n_kids):
  (listen_sock, junk)  = setup_socket(False)
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
  # Synchronize prints done in the 2 processes
  try:
    (junk, bpf) = setup_socket(True)
    print("[pid: %d] Parent Ready\n" % os.getpid())

    lock = mp.Lock()
    num_children = mp.Value('i', 0)
    for num in range(2):
      mp.Process(target=process_function, args=(lock, num_children)).start()
      while (num_children.value == num):
        time.sleep(0.1)
    print("\n[pid %d] System Ready For Testing" % os.getpid()) 
    while mp.active_children():
      time.sleep(0.5)
    bpf.trace_print()
  except (KeyboardInterrupt, SystemExit):
    pass
  except:
    raise
