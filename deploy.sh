#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y install python3-flask git avahi-utils avahi-daemon
adduser --system tracevisor --home /var/lib/tracevisor
cd /var/lib/tracevisor
git clone https://github.com/jdesfossez/tracevisor.git
cp tracevisor/upstart/tracevisor.conf /etc/init/
sed -i 's#exec /opt/tracevisor/tracevisor.py#exec sudo -u tracevisor /var/lib/tracevisor/tracevisor/tracevisor.py#' /etc/init/tracevisor.conf
mkdir /var/lib/tracevisor/.ssh
ssh-keygen -t rsa -b 2048 -N "" -f /var/lib/tracevisor/.ssh/id_rsa_tracevisor
chown -R tracevisor:nogroup /var/lib/tracevisor/

start tracevisor
