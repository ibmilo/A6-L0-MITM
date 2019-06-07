#run this script to reset the bridge

sudo ifconfig br0 down
sudo brctl delbr br0
sudo ifconfig enp0s25 down  
sudo ifconfig enx000ec6a76988 down  
