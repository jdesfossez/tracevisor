#!/usr/bin/python3

import os
import subprocess
from flask import Flask
from flask import request
from flask import abort

app = Flask(__name__)
name = "Tracevisor"
version = "1.0-alpha0"

relay = "127.0.0.1"
ssh = "ssh -oBatchMode=yes -oStrictHostKeyChecking=no"

analyses = {}
analyses["cpu"] = [ "sched_switch", "sched_process_fork", "sched_process_exec",
        "lttng_statedump_process_state" ]
analyses["io"] = [ "sched_switch", "block_rq_complete", "block_rq_issue",
        "block_bio_remap", "block_bio_backmerge", "netif_receive_skb",
        "net_dev_xmit", "sched_process_fork", "sched_process_exec",
        "lttng_statedump_process_state", "lttng_statedump_file_descriptor",
        "lttng_statedump_block_device", "syscalls" ]

@app.route('/')
def index():
    return "%s %s" % (name, version)

def check_requirements(host, username):
    # check SSH connection
    try:
        ret = subprocess.check_output("%s %s@%s id" \
                % (ssh, username, host), shell=True)
    except subprocess.CalledProcessError:
        return "Cannot establish an ssh connection : %s %s@%s failed\n" \
                % (ssh, username, host), 503

    # check for a root sessiond
    try:
        ret = subprocess.check_output("%s %s@%s pgrep -u root lttng-sessiond" \
                % (ssh, username, host), shell=True)
    except subprocess.CalledProcessError:
        return "Root lttng-sessiond not started\n", 503

    # check tracing group or root
    if username != "root":
        try:
            ret = subprocess.check_output("%s %s@%s groups|grep tracing" \
                    % (ssh, username, host), shell=True)
        except subprocess.CalledProcessError:
            return "User not in tracing group", 503
    return 0


@app.route('/trace/api/v1.0/analyses', methods = ['POST'])
def start_analysis():
    params = ['type', 'duration', 'host', 'username']
    if not request.json:
        abort(400)
    for p in params:
        if not p in request.json:
            abort(400)
    type = request.json["type"]
    duration = request.json["duration"]
    host = request.json["host"]
    username = request.json["username"]

    ret = check_requirements(host, username)
    if ret != 0:
        return ret

    return "Started %s analysis for %d seconds on host %s\n" % \
            (type, duration, host)

if __name__ == '__main__':
    app.run(debug = True)
