###############################################
 #  FORWARD CONNECTION TO AN OTHER INTERFACE
###############################################

# iptables -t nat -A PREROUTING -p tcp -d 10.10.10.1 --dport 8080 -j DNAT --to 10.10.10.1:8080

# iptables -A FORWARD -p tcp -d 192.168.1.2

# iptables -t nat -A PREROUTING -i eth0 -p tcp -d 10.10.10.1 --dport 8080 -j DNAT --to 10.10.10.1:8080
# iptables -A FORWARD -i eth0 -p tcp -d 192.168.1.2

#enable IP forwarding:
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

#then activate the changes
sudo sysctl -p

#Start iptables
#sudo systemctl start iptables

#Check iptables rules:
#(check that you don't have a deny policy )

#You can flush all rule to start in a clean env:
sudo iptables -F
#+For the nat
sudo iptables -t nat -F

#Add rules
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.5:80

#To check :
sudo iptables -t nat -L -n

#Save the iptables rule :
sudo iptables-save | sudo tee /etc/iptables.up.rules
