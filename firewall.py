import threading
import socket
import struct
from ctypes import *
import sys
import signal

class IP(Structure):
    _fields_= [
         ("version", c_ubyte, 4),
         ("ihl", c_ubyte, 4),
         ("tos", c_ubyte),
         ("len", c_ushort),
         ("id", c_ushort),
         ("offset", c_ushort),
         ("ttl", c_ubyte),
         ("protocal_num", c_ubyte),
         ("sum", c_ushort),
         ("src", c_uint32),
         ("dst", c_uint32)]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.src_address = socket.inet_ntoa(struct.pack("@I" ,self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I" ,self.dst))
        self.protocal_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        try:
            self.protocal = self.protocal_map[self.protocal_num]
        except:
            self.protocal = str(self.protocal_num)

try:
   inter1 = input('Type the first interface name: ')
   sockint01 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
   sockint01.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   sockint01.bind((inter1, 0))

   inter2 = input('Type the second interface name: ')
   sockint02 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
   sockint02.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   sockint02.bind((inter2, 0))

   socksend = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
   socksend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   socksend.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
except OSError:
   print ('No such interface')
   sys.exit()
except KeyboardInterrupt:
   print ('Exit.')
   sys.exit()
except Exception:
   print ('Error capturing or sending packets.')
   sys.exit()
   
def filterpack(ippack, sendpack):
   try:
      with open('rules.conf', 'r') as rules:
         for line in rules:
            currentline = line.split(',')
            if not currentline[0].startswith("#"):
               if currentline[0].replace(' ', '').upper().replace('\n','') == 'ALLOW' and currentline[1].replace(' ', '').upper() == ippack.protocal:
                  if currentline[2].replace(' ', '').upper() == 'ANY' or currentline[2].replace(' ', '') == ippack.src_address:
                     if currentline[3].replace(' ', '').upper().replace('\n','') == 'ANY' or currentline[3].replace(' ', '').replace('\n','') == ippack.dst_address:
                        socksend.sendto(sendpack,(ippack.dst_address, 0))
               elif str(currentline[0].replace(' ', '')).upper().replace('\n','') == 'DENY' and str(currentline[1].replace(' ', '')).upper() == ippack.protocal:
                  if currentline[2].replace(' ', '').upper() == 'ANY' or currentline[2].replace(' ', '') == ippack.src_address:
                     if currentline[3].replace(' ', '').upper().replace('\n','') == 'ANY' or currentline[3].replace(' ', '').replace('\n','') == ippack.dst_address:
                        print ('\n{} packet blocked from {} to {}'.format(ippack.protocal, ippack.src_address, ippack.dst_address))
                        print('Sending', end='', flush=True)
   except FileNotFoundError:
      print ('Could not find rules.conf file')
      sys.exit()
   except Exception:
      print ('Error packet filtering.')
      sys.exit()

def signal_handler(signum, frame):
     print("Exit the firewall program. Please Press 'Ctrl+Z' to exit.")
     ex_event.set()
     

print('Starting the firewall program')
print('Sending', end='', flush=True)
ex_event = threading.Event()
signal.signal(signal.SIGINT, signal_handler)

def int01_to_int02():
   while True:
      data01 = sockint01.recvfrom(65536)[0]
      ippack01 = IP(data01[14:])
      filterpack(ippack01, data01[14:])
      print ('.', end='', flush=True)
      if ex_event.is_set():
         break

def int02_to_int01():
   while True:
      data02 = sockint02.recvfrom(65536)[0]
      ippack02 = IP(data02[14:])
      filterpack(ippack02, data02[14:])
      print ('.', end='', flush=True)
      if ex_event.is_set():
         break

int01_to_int02 = threading.Thread(target=int01_to_int02)
int02_to_int01 = threading.Thread(target=int02_to_int01)
int01_to_int02.start()
int02_to_int01.start()
