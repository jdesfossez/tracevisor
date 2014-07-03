#!/usr/bin/python3

import os
import subprocess
import time
from flask import Flask
from flask import request
from flask import abort
from flask import jsonify
from cors import crossdomain

app = Flask(__name__)
appname = "Tracevisor"
appversion = "1.0-alpha0"

relay = "127.0.0.1"
ssh = "ssh -oBatchMode=yes -oStrictHostKeyChecking=no -i ~/.ssh/id_rsa_tracevisor"

analyses = {}

analyses["cpu"] = {}
analyses["cpu"]["kernel_events"] = "sched_switch,sched_process_fork,sched_process_exec," \
        "lttng_statedump_process_state"

analyses["io"] = {}
analyses["io"]["kernel_events"] = "sched_switch,block_rq_complete,block_rq_issue," \
        "block_bio_remap,block_bio_backmerge,netif_receive_skb," \
        "net_dev_xmit,sched_process_fork,sched_process_exec," \
        "lttng_statedump_process_state,lttng_statedump_file_descriptor," \
        "lttng_statedump_block_device"
analyses["io"]["syscalls"] = True

session_name = ""
# Temporarily hardcoded
PATH_ANALYSES = "/usr/local/src/lttng-analyses/"
PATH_TRACES = "/root/lttng-traces/tracesd-0/"

@app.route('/')
@crossdomain(origin='*')
def index():
    return "%s %s" % (appname, appversion)

@app.route('/trace/api/v1.0/analyses', methods = ['GET'])
@crossdomain(origin='*')
def get_analyses():
    return jsonify( { 'analyses': analyses } )

@app.route('/trace/api/v1.0/ssh', methods = ['GET'])
@crossdomain(origin='*')
def get_ssh_keys():
    path = os.path.join(os.environ["HOME"], ".ssh")
    l = os.listdir(path)
    keys = []
    for k in l:
        if ".pub" in k:
            f = open(os.path.join(path,k))
            keys.append(f.read())
    return jsonify({ 'keys': keys })

@app.route('/trace/api/v1.0/servers', methods = ['GET'])
@crossdomain(origin='*')
def get_server_list():
    try:
        ret = subprocess.check_output("avahi-browse _lttng._tcp -p -t -r", shell=True)
    except subprocess.CalledProcessError:
        return "Error running avahi-browse _lttng._tcp -p -t", 503

    servers = []
    lines = str(ret, encoding='utf8').split("\n")
    for entry in lines:
        l = entry.split(";")
        # only output "resolved" entries
        if l[0] != "=":
            continue
        d = {}
        d["hostname"] = l[3]
        if l[2] == "IPv4":
            d["ipv4"] = l[7]
        elif l[2] == "IPv6":
            d["ipv6"] = l[7]
        servers.append(d)
    return jsonify({ 'servers': servers })

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

def launch_trace(host, username, relay, type, duration):
    global session_name
    session_name = "%s-%s-%s" % (appname, type, str(int(time.time())))
    # create the session
    try:
        ret = subprocess.check_output("%s %s@%s lttng create %s -U %s" \
                % (ssh, username, host, session_name, "net://%s" % relay), shell=True)
    except subprocess.CalledProcessError:
        return "Session creation error\n", 503
    # enable events
    events = ""
    if "kernel_events" in analyses[type].keys() and \
            len(analyses[type]["kernel_events"]) > 0:
        try:
            ret = subprocess.check_output("%s %s@%s lttng enable-event -s %s -k %s" \
                    % (ssh, username, host, session_name,
                        analyses[type]["kernel_events"]), shell=True)
        except subprocess.CalledProcessError:
            return "Enabling kernel events failed\n", 503

    if "syscalls" in analyses[type].keys():
        try:
            ret = subprocess.check_output("%s %s@%s lttng enable-event -s %s -k --syscall -a" \
                    % (ssh, username, host, session_name), shell=True)
        except subprocess.CalledProcessError:
            return "Enabling syscalls failed\n", 503

    if "userspace_events" in analyses[type].keys() and \
            len(analyses[type]["userspace_events"]) > 0:
        try:
            ret = subprocess.check_output("%s %s@%s lttng enable-event -s %s -k %s" \
                    % (ssh, username, host, session_name,
                        analyses[type]["userspace_events"]), shell=True)
        except subprocess.CalledProcessError:
            return "Enabling userspace events failed\n", 503

    # start the session
    try:
        ret = subprocess.check_output("%s %s@%s lttng start %s" \
                % (ssh, username, host, session_name), shell=True)
    except subprocess.CalledProcessError:
        return "Session start error\n", 503

    time.sleep(duration)

    # stop the session
    try:
        ret = subprocess.check_output("%s %s@%s lttng stop %s" \
                % (ssh, username, host, session_name), shell=True)
    except subprocess.CalledProcessError:
        return "Session stop error\n", 503
    # destroy the session
    try:
        ret = subprocess.check_output("%s %s@%s lttng destroy %s" \
                % (ssh, username, host, session_name), shell=True)
    except subprocess.CalledProcessError:
        return "Session destroy error\n", 503

    return 0

def launch_analysis(host, username):
    global session_name
    # This will be specified in the request eventually
    script = "fd-info.py"
    # These should probably become the default behaviour,
    # or at least add some sort of daemon mode to analyses
    args = "--quiet --mongo"

    try:
        ret = subprocess.check_output("%s %s@%s python3 %s%s %s %s%s*/kernel" \
                % (ssh, username, host, PATH_ANALYSES, script, args,
                   PATH_TRACES, session_name), shell=True)
    except subprocess.CalledProcessError:
        return "Analysis python script error\n", 503

    return 0

@app.route('/trace/api/v1.0/analyses', methods = ['POST', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def start_analysis():
    params = ['type', 'duration', 'host', 'username']
    if not request.json:
        abort(400)
    # mandatory parameters
    for p in params:
        if not p in request.json:
            abort(400)

    # override the relay in the request
    if 'relay' in request.json:
        r = request.json["relay"]
    else:
        r = relay

    type = request.json["type"]
    duration = request.json["duration"]
    host = request.json["host"]
    username = request.json["username"]

    if not type in analyses.keys():
        return "Unknown analysis type\n", 503

    ret = check_requirements(host, username)
    if ret != 0:
        return ret
    ret = launch_trace(host, username, r, type, duration)
    if ret != 0:
        return ret
    ret = launch_analysis(r, username)
    if ret != 0:
        return ret

    return "Started %s analysis for %d seconds on host %s\n" % \
            (type, duration, host)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug = True)
