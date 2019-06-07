modprobe br_netfilter
echo 1 >/proc/sys/net/ipv4/ip_forward
sudo brctl delbr br0
sudo brctl addbr br0
sudo brctl addif br0 enx000ec6a76988 enp0s25
sudo ifconfig enp0s25 up
sudo ifconfig enx000ec6a76988 up
sudo ifconfig br0 up

#change enx000ec6a76988, enx9cebe8aea755  interface accordingly to yours. 

