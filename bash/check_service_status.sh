#!/bin/bash

service_name="firewalld.service"

systemctl is-active --quiet $service_name && echo "Service is running" || systemctl start $service_name

