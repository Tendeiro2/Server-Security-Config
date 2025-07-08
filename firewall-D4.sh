#!/bin/bash 

##############################################################
#     Team number: 4
#       Student names:
#         1 - Iuri Carrasqueiro
#         2 - Miguel Lopes
#         3 - Joao Tendeiro
#
##############################################################
# change the file name:
#   firewall-D4.sh
#       D4      -> change to the team number
##############################################################

###############################
# Init. of iptables
###############################
IPT=/usr/sbin/iptables

echo "Flush rules and personalized lists"
$IPT -F
$IPT -X

echo "Default policy"
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

echo "Permitir loopback interface"
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# Dynamic ports
DYN=1024:65535

###############################
# STATEFUL rules
###############################  

######################################
##### Regras Genericas stateful  #####
######################################
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  
######################################################
####### Registo e Negacao de pacotes invalidos #######
######################################################
echo "Deny invalid packets"
$IPT -A INPUT -m state --state INVALID -j LOG --log-prefix "INVALID Packets (IN):" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
$IPT -A INPUT -m state --state INVALID -j REJECT

$IPT -A OUTPUT -m state --state INVALID -j LOG --log-prefix "INVALID Packets (OUT):" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
$IPT -A OUTPUT -m state --state INVALID -j REJECT


###############################################
####### Negacao de ataques por flood ##########
###############################################
echo "ICMP packets flood"
$IPT -N packet_flood_icmp
$IPT -A packet_flood_icmp -j LOG --log-prefix "Services exposed (IN):" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
$IPT -A packet_flood_icmp -m limit --limit 5/second -j ACCEPT
$IPT -A packet_flood_icmp -j LOG --log-prefix "Packet ICMP DROP:" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
$IPT -A packet_flood_icmp -j DROP

echo "Udp packets flood"
$IPT -N packet_flood_udp
$IPT -A packet_flood_udp -j LOG --log-prefix "Services exposed (IN):" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
$IPT -A packet_flood_udp -p udp -m limit --limit 10/second --limit-burst 50 -j ACCEPT 
$IPT -A packet_flood_udp -j LOG --log-prefix "Packet UDP DROP:" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
$IPT -A packet_flood_udp -j DROP

echo "Tcp packets flood"
$IPT -N packet_flood_tcp
$IPT -A packet_flood_tcp -j LOG --log-prefix "Services exposed (IN):" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
$IPT -A packet_flood_tcp -p tcp -m limit --limit 50/second --limit-burst 100 -j ACCEPT 
$IPT -A packet_flood_tcp -j LOG --log-prefix "Packet TCP DROP:" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
$IPT -A packet_flood_tcp -j DROP

####################################
####### Funcoes do trafego #########
####################################

echo "Logs SSH"
$IPT -N log_ssh 
$IPT -A log_ssh -j LOG --log-prefix "Services exposed (IN):" --log-level 4 --log-ip-options --log-tcp-options --log-tcp-sequence
$IPT -A log_ssh -j ACCEPT

######## INPUT #########
$IPT -A INPUT -p icmp --icmp-type echo-request -j packet_flood_icmp #Ping

echo "Lista Personalizada para input"
$IPT -N trafego_input
$IPT -A trafego_input -p udp --sport $DYN --dport http -j packet_flood_udp #HTTP

LIST="http 443"
for service in $LIST; do
    echo " " $service
    iptables -A trafego_input -p tcp --sport $DYN --dport $service -j packet_flood_tcp
done

$IPT -A trafego_input -p tcp --sport $DYN --dport 22 -j log_ssh #SSH

######## OUTPUT #########
echo "Lista Personalizada para output"
$IPT -N trafego_output
$IPT -A trafego_output -p icmp --icmp-type echo-request -j ACCEPT #Ping

LIST="domain http 7844"
for service in $LIST; do
    echo " " $service
    $IPT -A trafego_output -p udp --sport $DYN --dport $service -j ACCEPT
done

LIST="http 443 22 9418 43 853"
for service in $LIST; do
    echo " " $service
    $IPT -A trafego_output -p tcp --sport $DYN --dport $service -j ACCEPT
done

########################################
######### REGRAS INPUT e OUTPUT ########
########################################
$IPT -A INPUT -m state --state NEW -j trafego_input 

$IPT -A OUTPUT -m state --state NEW -j trafego_output
