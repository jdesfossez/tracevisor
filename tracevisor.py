#!/usr/bin/python3

import os
import subprocess
import time
import threading
from flask import Flask
from flask import request
from flask import abort
from flask import jsonify
from cors import crossdomain

app = Flask(__name__)
appname = "Tracevisor"
appversion = "1.0-alpha0"

class Tracevisor:
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

    # Temporarily hardcoded
    PATH_ANALYSES = "/usr/local/src/lttng-analyses/"
    PATH_TRACES = "/root/lttng-traces/tracesd-0/"

    running_threads = {}
    jobid = 0
    THREAD_STARTED = 1
    THREAD_TRACE_RUNNING = 2
    THREAD_ANALYSIS_RUNNING = 3
    THREAD_COMPLETE = 4
    THREAD_ERROR = -1

tracevisor = Tracevisor()

@app.route('/')
@crossdomain(origin='*')
def index():
    return "%s %s" % (appname, appversion)

@app.route('/trace/api/v1.0/analyses', methods = ['GET'])
@crossdomain(origin='*')
def get_analyses():
    return jsonify( { 'analyses': tracevisor.analyses } )

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
                % (tracevisor.ssh, username, host), shell=True)
    except subprocess.CalledProcessError:
        return "Cannot establish an ssh connection : %s %s@%s failed\n" \
                % (tracevisor.ssh, username, host), 503

    # check for a root sessiond
    try:
        ret = subprocess.check_output("%s %s@%s pgrep -u root lttng-sessiond" \
                % (tracevisor.ssh, username, host), shell=True)
    except subprocess.CalledProcessError:
        return "Root lttng-sessiond not started\n", 503

    # check tracing group or root
    if username != "root":
        try:
            ret = subprocess.check_output("%s %s@%s groups|grep tracing" \
                    % (tracevisor.ssh, username, host), shell=True)
        except subprocess.CalledProcessError:
            return "User not in tracing group", 503
    return 0

def launch_trace(host, username, relay, type, duration, task):
    task["session_name"] = "%s-%s-%s" % (appname, type, task["jobid"])
    # create the session
    try:
        ret = subprocess.check_output("%s %s@%s lttng create %s -U %s" \
                % (tracevisor.ssh, username, host, task["session_name"], "net://%s" % relay), shell=True)
    except subprocess.CalledProcessError:
        return "Session creation error\n", 503
    # enable events
    events = ""
    if "kernel_events" in tracevisor.analyses[type].keys() and \
            len(tracevisor.analyses[type]["kernel_events"]) > 0:
        try:
            ret = subprocess.check_output("%s %s@%s lttng enable-event -s %s -k %s" \
                    % (tracevisor.ssh, username, host, task["session_name"],
                        tracevisor.analyses[type]["kernel_events"]), shell=True)
        except subprocess.CalledProcessError:
            return "Enabling kernel events failed\n", 503

    if "syscalls" in tracevisor.analyses[type].keys():
        try:
            ret = subprocess.check_output("%s %s@%s lttng enable-event -s %s -k --syscall -a" \
                    % (tracevisor.ssh, username, host, task["session_name"]), shell=True)
        except subprocess.CalledProcessError:
            return "Enabling syscalls failed\n", 503

    if "userspace_events" in tracevisor.analyses[type].keys() and \
            len(tracevisor.analyses[type]["userspace_events"]) > 0:
        try:
            ret = subprocess.check_output("%s %s@%s lttng enable-event -s %s -k %s" \
                    % (tracevisor.ssh, username, host, task["session_name"],
                        tracevisor.analyses[type]["userspace_events"]), shell=True)
        except subprocess.CalledProcessError:
            return "Enabling userspace events failed\n", 503

    task["lock"].acquire()
    task["status"] = tracevisor.THREAD_TRACE_RUNNING
    task["lock"].release()

    # start the session
    try:
        ret = subprocess.check_output("%s %s@%s lttng start %s" \
                % (tracevisor.ssh, username, host, task["session_name"]), shell=True)
    except subprocess.CalledProcessError:
        return "Session start error\n", 503

    time.sleep(duration)

    # stop the session
    try:
        ret = subprocess.check_output("%s %s@%s lttng stop %s" \
                % (tracevisor.ssh, username, host, task["session_name"]), shell=True)
    except subprocess.CalledProcessError:
        return "Session stop error\n", 503
    # destroy the session
    try:
        ret = subprocess.check_output("%s %s@%s lttng destroy %s" \
                % (tracevisor.ssh, username, host, task["session_name"]), shell=True)
    except subprocess.CalledProcessError:
        return "Session destroy error\n", 503

    task["lock"].acquire()
    task["status"] = tracevisor.THREAD_ANALYSIS_RUNNING
    task["lock"].release()

    ret = launch_analysis(task["relay"], username, task["session_name"])
    if ret != 0:
        task["lock"].acquire()
        task["status"] = tracevisor.THREAD_ERROR
        task["lock"].release()
        return ret

    task["lock"].acquire()
    task["status"] = tracevisor.THREAD_COMPLETE
    task["lock"].release()
    return 0

def launch_analysis(host, username, session_name):
    # This will be specified in the request eventually
    script = "fd-info.py"
    # These should probably become the default behaviour,
    # or at least add some sort of daemon mode to analyses
    args = "--quiet --mongo"

    try:
        ret = subprocess.check_output("%s %s@%s python3 %s%s %s %s%s*/kernel" \
                % (tracevisor.ssh, username, host, tracevisor.PATH_ANALYSES, script, args,
                   tracevisor.PATH_TRACES, session_name), shell=True)
    except subprocess.CalledProcessError:
        return "Analysis python script error\n", 503

    return 0

def cleanup_threads():
    # get rid of the completed threads
    # FIXME: only called from get_analyses_list for now, need a GC
    to_delete = []
    for s in tracevisor.running_threads.keys():
        t =  tracevisor.running_threads[s]
        t["lock"].acquire()
        if t["status"] == tracevisor.THREAD_COMPLETE or \
                t["status"] == tracevisor.THREAD_ERROR:
            t["thread"].join()
            to_delete.append(s)
        t["lock"].release()

    for d in to_delete:
        del tracevisor.running_threads[d]

@app.route('/trace/api/v1.0/list', methods = ['GET'])
@crossdomain(origin='*')
def get_analyses_list():
    sessions = []
    for s in tracevisor.running_threads.keys():
        sess = {}
        t =  tracevisor.running_threads[s]
        sess["jobid"] = t["jobid"]
        t["lock"].acquire()
        sess["status"] = t["status"]
        t["lock"].release()
        sessions.append(sess)

    cleanup_threads()
    return jsonify( { 'sessions': sessions } )


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
        r = tracevisor.relay

    type = request.json["type"]
    duration = request.json["duration"]
    host = request.json["host"]
    username = request.json["username"]

    if not type in tracevisor.analyses.keys():
        return "Unknown analysis type\n", 503

    ret = check_requirements(host, username)
    if ret != 0:
        return ret

    tracevisor.jobid += 1
    task = {}
    task["status"] = tracevisor.THREAD_STARTED
    task["lock"] = threading.Lock()
    task["relay"] = r
    task["jobid"] = tracevisor.jobid
    t = threading.Thread(name='trace', target=launch_trace,
            args=(host, username, r, type, duration, task))
    task["thread"] = t
    tracevisor.running_threads[tracevisor.jobid] = task
    t.start()

    return "Started %s analysis for %d seconds on host %s, jobid = %d\n" % \
            (type, duration, host, tracevisor.jobid)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug = True)
