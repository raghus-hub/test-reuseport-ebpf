# test-reuseport-ebpf
Code to test SO_ATTACH_REUSEPORT_EBPF
file reuseport_ebpf.py: Sets up the Echo server with options to enable eBPF
file bpf_filter.c:      Simple eBPF filter
file simple_client.py:  Tests the Echo server by sending multiple requests to it.

To test
A) Start 2 servers one on port 8887 and the other on default (8888) port
   ./reuseport_ebpf.py --port 8887
   ./reuseport_ebpf.py --enable-filter (This enables ebpf filter)
Each server starts 2 processes that listen on the same IP & Port

B) Start 2 clients on the same node as the server
   ./simple_client.py --port 8887
   ./simple_client.py --port 8888

The client connecting to the server with eBPF filter should only see responses
from a single Server Pid. The client connecting to the server without the eBPF
filter should see responses from 2 Server Pids
