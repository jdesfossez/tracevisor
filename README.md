# Tracevisor

Basic agent to control analyses on remote hosts over SSH:

## Requirements:
- python3-flask
- tracevisor host/user can access the remote host via SSH with a shared key
  with no password
- lttng-sessiond is started as root on the target machine
- the remote user is root or in tracing group

## Examples

### Start remote analysis

To start an I/O analysis on host `localhost` as user `root` for 2 seconds:

    $ curl -i -H "Content-Type: application/json" -X POST -d '{"host":"localhost", "duration":2, "type":"io", "username":"root"}' http://localhost:5000/trace/api/v1.0/analyses

Parameters: `host`, `duration`, `type`, `username`, `relay`, `analysis`, `mongohost`, `mongoport`

The request only returns when the trace is completed.

### List supported analyses

To get the list of supported analyses and the configuration:

    $ curl http://localhost:5000/trace/api/v1.0/analyses

### List tracesd servers

To get the list of servers running [tracesd](https://github.com/jdesfossez/tracesd.git) :

    $ curl http://localhost:5000/trace/api/v1.0/clients

### Get public keys

To get the public ssh keys of the user that runs tracevisor :

    $ curl http://localhost:5000/trace/api/v1.0/ssh

### List running sessions

To list the current running sessions (the status comes from `THREAD_*`) :

    $ curl http://localhost:5000/trace/api/v1.0/list

### Relays

To register a relay:

    $ curl -i -H "Content-Type: application/json" -X POST -d '{"hostname": "myrelayhostname", "ipv6":"fe80::1" }' http://localhost:5000/trace/api/v1.0/relays

Parameters: `hostname`, `ipv4`, `ipv6`, `ctrlport`, `dataport`

To list the relays registered :

    $ curl http://localhost:5000/trace/api/v1.0/relays

To delete the relay ID 1 :

    $ curl -i -H "Content-Type: application/json" -X DELETE http://localhost:5000/trace/api/v1.0/relays/1

To get the details of relay ID 1 :

    $ curl http://localhost:5000/trace/api/v1.0/relays/1

To update the details of relay ID 1 :

    $ curl -i -H "Content-Type: application/json" -X PUT -d '{"hostname": "myrelayhostname2", "ipv6":"fe80::1" }' http://localhost:5000/trace/api/v1.0/relays/1

### Clients

Same requests as the relay, base URL is `/trace/api/v1.0/clients`

Parameters: `hostname`, `ipv4`, `ipv6`, `sshport`, `sshuser`

### Analyses servers

Same requests as the relay, base URL is `/trace/api/v1.0/analyses_servers`

Parameters: `hostname`, `ipv4`, `ipv6`, `sshport`, `sshuser`
