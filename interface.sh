###############################################
 #  FORWARD CONNECTION TO AN OTHER INTERFACE
###############################################

# enable IP forwarding
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

# activate the changes
sysctl -p

# clear all nat rules
iptables -t nat -F

# forwarding to 10.0.2.16
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.0.2.16:80
iptables  -A FORWARD -p tcp -d 10.0.2.16

