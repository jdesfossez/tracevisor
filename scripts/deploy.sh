#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y install python3-flask git avahi-utils avahi-daemon
adduser --system tracevisor --home /var/lib/tracevisor
cd /var/lib/tracevisor
git clone https://github.com/jdesfossez/tracevisor.git
cp tracevisor/upstart/tracevisor.conf /etc/init/
mkdir /var/lib/tracevisor/.ssh
ssh-keygen -C tracevisor@tracevisor -t rsa -b 2048 -N "" -f /var/lib/tracevisor/.ssh/id_rsa_tracevisor
chown -R tracevisor:nogroup /var/lib/tracevisor/

start tracevisor
