#!/bin/bash

##############################################################################################
##
## This script checks status of connection using ping and outputs to file if connection error
##
##############################################################################################

gitlab=gitlab.seakr.com
gitlab_ip="192.168.100.236"
nameserver1="192.168.100.1"
nameserver2="192.168.100.1"

gitlab_fail=/gitlab_fail.out
gitlab_ip_fail=/ipaddr_fail.out
nameserver1_fail=/nameserver1.out
nameserver2_fail=/nameserver2.out
while true
do
        ! ping -c1 $gitlab &> /dev/null && echo "gitlab ping fail at -->  $(date)" >> $gitlab_fail
        ! ping -c1 $gitlab_ip &> /dev/null && echo "gitlab ip fail at -->  $(date)" >> $gitlab_ip_fail
        ! ping -c1 $nameserver1 &> /dev/null && echo "nameserver1 fail at -->  $(date)" >> $nameserver1_fail
        ! ping -c1 $nameserver2 &> /dev/null && echo "nameserver2 fail at -->  $(date)" >> $nameserver2_fail
        sleep 1
done

