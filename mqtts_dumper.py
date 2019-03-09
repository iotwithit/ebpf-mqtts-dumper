#!/usr/bin/python
#
#Adaptation of the http-parse-simple example from 
#Bertrone Matteo - Polytechnic of Turin
#
#eBPF application that dumps packets TCP packets to and from a certain port
#
#eBPF program mqtts_dumper.c is used as SOCKET_FILTER attached to a chosen interface.
#only packet of type ip and tcp from or to chosen port are returned to userspace, others dropped
#
from __future__ import print_function
from bcc import BPF
from sys import argv

import sys
import socket
import os

#args
def usage():
    print("USAGE: %s [-i_p <if_name,port>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-i,p <if_name,port>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i_p if_name,port_num    select interface if_name and port port_num. Defaults are eth0,8883")
    print("")
    print("examples:")
    print("    mqtts_dumper                   # bind socket to eth0,8883")
    print("    mqtts_dumper -i_p wlan0,27035  # bind socket to wlan0,27035")
    exit()

#arguments
interface="eth0"

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-i_p':
    interface, filter_port = argv[2].split(',')
  else:
    usage()

if len(argv) > 3:
  usage()

print ("binding socket to '%s'" % interface)

# initialize BPF - load source code from mqtts_dumper.c
bpf = BPF(src_file = "mqtts_dumper.c", cflags=["-DFILTER_PORT=" + str(filter_port)])

#load eBPF program mqtts_dumper of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_mqtts_dumper = bpf.load_func("mqtts_dumper", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_mqtts_dumper, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_mqtts_dumper.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)

while True:
  #retrieve raw packet from socket
  packet_bytes = os.read(socket_fd, 2048)

  print('PKTPKTs')
  print(' '.join(['%02x' % byte for byte in packet_bytes]))
  print('PKTPKTe')
