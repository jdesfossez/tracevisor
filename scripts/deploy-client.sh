#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

source /etc/lsb-release
if [ "$DISTRIB_ID" != "Ubuntu" ]; then
	echo "ERROR: Only Ubuntu is supported."
	exit 1
fi

if test $# -lt 1; then
	echo "Usage : $0 <tracevisor hostname/ip>"
	exit 1
fi

TRACEVISORIP=$1
TRACEVISORPORT=5000

apt-get update
apt-get install -y software-properties-common curl

apt-add-repository -y ppa:lttng/ppa

apt-get update
apt-get -y install lttng-tools babeltrace avahi-utils avahi-daemon git make linux-headers-generic gcc

mkdir ~/src
cd ~/src
git clone https://github.com/jdesfossez/lttng-modules-dev.git
cd lttng-modules-dev
git checkout extended-network-fields
make
make modules_install
depmod -a

cat > /etc/init/lttng-sessiond.conf << EOF
description "LTTng 2.0 central tracing registry session daemon"
author "Stéphane Graber <stgraber@ubuntu.com>"

start on local-filesystems
stop on runlevel [06]

respawn
exec lttng-sessiond
EOF

cat > /etc/init/avahi-publish-lttng.conf << EOF
start on (started lttng-sessiond and started avahi-daemon)
stop on stopping lttng-sessiond
script
	HOSTNAME=\`hostname -s\`
	avahi-publish -s \$HOSTNAME _lttng._tcp 0
end script
EOF

restart avahi-daemon
restart lttng-sessiond

mkdir -p ~/.ssh
curl -s http://${TRACEVISORIP}:${TRACEVISORPORT}/trace/api/v1.0/ssh|grep tracevisor | cut -d '"' -f2 | cut -d "\\" -f1 >> ~/.ssh/authorized_keys2
# check if we have to use the gateway ("via" keyword)
ip -4 route get ${TRACEVISORIP} 2>/dev/null | grep via >/dev/null
if test $? = 0; then
	ipv4=$(ip -4 route get ${TRACEVISORIP} 2>/dev/null | grep dev | awk '{print $7}')
else
	ipv4=$(ip -4 route get ${TRACEVISORIP} 2>/dev/null | grep dev | awk '{print $5}')
fi

# check if we have to use the gateway ("via" keyword)
ip -6 route get ${TRACEVISORIP} 2>/dev/null | grep via >/dev/null
if test $? = 0; then
	ipv6=$(ip -6 route get ${TRACEVISORIP} 2>/dev/null | grep dev | awk '{print $7}')
else
	ipv6=$(ip -6 route get ${TRACEVISORIP} 2>/dev/null | grep dev | awk '{print $5}')
fi

curl -i -H "Content-Type: application/json" -X POST -d "{\"hostname\": \"$HOSTNAME\", \"ipv4\":\"$ipv4\", \"ipv6\":\"$ipv6\" }" http://${TRACEVISORIP}:${TRACEVISORPORT}/trace/api/v1.0/add_client
