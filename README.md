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
|  1| P101, P102,  MV101 | LIT101, FIT101 |
|2| P201, P202, P203, P204, P205, P206, P207, P208, MV201 |FIT201, AIT201, AIT202, AIT203, LS201, LS202| 
|3| P301, P302, MV301, MV302, MV303, MV304 | LIT301, FIT301, PSH301, DPSH301, DPIT301|
|4| P401 , P402, P403, P404, UV401 | LIT401, FIT401, AIT401, AIT402| 
|5| |MV501, MV502, MV503, MV504| FIT501, FIT502, FIT503, FIT504,  AIT501, AIT502, AIT503, AIT504, PIT501, PIT502, PIT503|
|6| P601, P602, P603| |


