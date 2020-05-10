#!usr/bin/env bash

##########################
 # CLEAR ALL RULES
##########################
iptables -F

###########################
 # ADDING RULES
###########################

# blocking online.uom.lk site
iptables -A INPUT -s online.uom.lk -j DROP

# blocking port 433 for tcp
iptables -A INPUT -p tcp --dport 433 -j REJECT

# blocking www.rathnavali.lk
iptables -A INPUT -s www.rathnavali.com -j DROP



