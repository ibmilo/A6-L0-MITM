# A6-L0-MITM

The A6_S tool is a attack tool that launched attack at layer 0 in Secure Water and Treatment (SWaT) testbed. With this tool, one is able to control the components instrument of SWaT. With this tool, researchers can use to design experiments of attack and/or check against the defense solutions placed or of any other research studies. This is a Man-In-the-Middle attack where the ENIP packets communication are coming from the PLCs to the RIO module.


    Some attributes to  https://github.com/ifyouaretea/A6-MITM
                    		https://github.com/scy-phy/swat



## Hardware requirements

    Bootable Ubuntu OS
    Laptop with 2 interfaces Control

## Software requirements

    Python 2.7
    Bridge Control (https://help.ubuntu.com/community/NetworkConnectionBridge)
    NetfilterQueue (https://github.com/kti/python-netfilterqueue)
    Scapy (http://www.secdev.org/projects/scapy/)
    Ethernet/IP dissectors for Scapy (https://github.com/scy-phy/scapy-cip-enip)


## Setup

    Connect 2 physical wire. One from your laptop to the RIO module and the other from the RIO module back to the lapto. 
  
    Change network interfaces name in start-lvl0.sh
    Run start-lvl0.sh as root to connect the bridge.
    
    Attack scripts are A6_L0_P1.py, A6_L0_P1.py, A6_L0_P1.py, A6_L0_P2.py, A6_L0_P3.py, A6_L0_P4.py, A6_L0_P5.py,   
    A6_L0_P6.py respectively. 
    
    Run respective attack script of the stage used. 
     
     
     
## Instructions on how to use



## Component instruments
|Stage     |Acturators|Sensors   |
|----------|----------|----------|
|  1
|2
|3
|4
|5
|6


