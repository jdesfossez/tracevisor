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
apt-get -y install lttng-tools avahi-utils avahi-daemon

cat > /etc/init/lttng-relayd.conf << EOF
description "LTTng 2.x relay daemon"

start on local-filesystems
stop on runlevel [06]

respawn
exec lttng-relayd -o /root/lttng-traces
EOF

cat > /etc/init/avahi-publish-lttng-relayd.conf << EOF
start on (started lttng-relayd and started avahi-daemon)
stop on stopping lttng-relayd
script
	HOSTNAME=\`hostname -s\`
	avahi-publish -s \$HOSTNAME _lttng_relayd._tcp 0
end script
EOF

restart avahi-daemon
start lttng-relayd

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

curl -i -H "Content-Type: application/json" -X POST -d "{\"name\": \"$HOSTNAME\", \"ipv4\":\"$ipv4\", \"ipv6\":\"$ipv6\" }" http://${TRACEVISORIP}:${TRACEVISORPORT}/trace/api/v1.0/add_relay
