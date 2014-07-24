#!/bin/bash

echo -n "This will kill any tracevisor already running and trash the current database, continue (Y/n) ? "
read a
if test "$a" = 'n'; then
	exit 0
else
	pgrep tracevisor.py | xargs kill
	rm config.db
	./tracevisor.py &
	[ $? = 0 ] || exit 1
	echo "Arbitrary sleep before tracevisor is ready"
	sleep 3
fi

# Stateless requests
echo "GET INDEX"
curl -s -i http://localhost:5000/ | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "GET ANALYSES LIST"
curl -s -i http://localhost:5000/trace/api/v1.0/list | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "GET SSH KEYS"
curl -s -i http://localhost:5000/trace/api/v1.0/ssh | grep 200 >/dev/null
[ $? = 0 ] || exit 1



# Relay requests
echo "REGISTER A RELAY"
curl -s -i -H "Content-Type: application/json" -X POST -d '{"hostname": "myrelayhostname", "ipv6":"fe80::1" }' http://localhost:5000/trace/api/v1.0/relays | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "LIST RELAYS"
curl -i -s http://localhost:5000/trace/api/v1.0/relays | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "GET RELAY 1 DETAILS"
curl -i -s http://localhost:5000/trace/api/v1.0/relays/1 | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "UPDATE RELAY 1"
curl -i -s -H "Content-Type: application/json" -X PUT -d '{"hostname": "myrelayhostname2", "ipv6":"fe80::1" }' http://localhost:5000/trace/api/v1.0/relays/1 | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "DELETE RELAY 1"
curl -i -s -H "Content-Type: application/json" -X DELETE http://localhost:5000/trace/api/v1.0/relays/1 | grep 200 >/dev/null
[ $? = 0 ] || exit 1



# Client requests
echo "REGISTER A CLIENT"
curl -s -i -H "Content-Type: application/json" -X POST -d '{"hostname": "myclienthostname", "ipv6":"fe80::1" }' http://localhost:5000/trace/api/v1.0/clients | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "LIST CLIENTS"
curl -i -s http://localhost:5000/trace/api/v1.0/clients | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "GET CLIENT 1 DETAILS"
curl -i -s http://localhost:5000/trace/api/v1.0/clients/1 | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "UPDATE CLIENT 1"
curl -i -s -H "Content-Type: application/json" -X PUT -d '{"hostname": "myclienthostname2", "ipv6":"fe80::1" }' http://localhost:5000/trace/api/v1.0/clients/1 | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "DELETE CLIENT 1"
curl -i -s -H "Content-Type: application/json" -X DELETE http://localhost:5000/trace/api/v1.0/clients/1 | grep 200 >/dev/null
[ $? = 0 ] || exit 1


# Analyzes servers requests
echo "REGISTER A ANALYZES_SERVER"
curl -s -i -H "Content-Type: application/json" -X POST -d '{"hostname": "myanalyzes_serverhostname", "ipv6":"fe80::1" }' http://localhost:5000/trace/api/v1.0/analyzes_servers | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "LIST ANALYZES_SERVERS"
curl -i -s http://localhost:5000/trace/api/v1.0/analyzes_servers | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "GET ANALYZES_SERVER 1 DETAILS"
curl -i -s http://localhost:5000/trace/api/v1.0/analyzes_servers/1 | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "UPDATE ANALYZES_SERVER 1"
curl -i -s -H "Content-Type: application/json" -X PUT -d '{"hostname": "myanalyzes_serverhostname2", "ipv6":"fe80::1" }' http://localhost:5000/trace/api/v1.0/analyzes_servers/1 | grep 200 >/dev/null
[ $? = 0 ] || exit 1

echo "DELETE ANALYZES_SERVER 1"
curl -i -s -H "Content-Type: application/json" -X DELETE http://localhost:5000/trace/api/v1.0/analyzes_servers/1 | grep 200 >/dev/null
[ $? = 0 ] || exit 1

kill %1
wait
