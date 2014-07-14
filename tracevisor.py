#!/usr/bin/python3

import json
import os
import subprocess
import time
import threading
from flask import Flask
from flask import Response
from flask import request
from flask import abort
from flask import jsonify
from cors import crossdomain

class Tracevisor:
    THREAD_STARTED = 1
    THREAD_TRACE_RUNNING = 2
    THREAD_ANALYSIS_RUNNING = 3
    THREAD_COMPLETE = 4
    THREAD_ERROR = -1
    # Temporarily hardcoded
    PATH_ANALYSES = "/usr/local/src/lttng-analyses/"
    PATH_TRACES = "/root/lttng-traces/tracesd-0/"

    def __init__(self):
        self.relay = "127.0.0.1"
        self.ssh = "ssh -oBatchMode=yes -oStrictHostKeyChecking=no -i ~/.ssh/id_rsa_tracevisor"

        self.analyses = {}

        self.analyses["cpu"] = {}
        self.analyses["cpu"]["kernel_events"] = "sched_switch,sched_process_fork,sched_process_exec," \
                "lttng_statedump_process_state"

        self.analyses["io"] = {}
        self.analyses["io"]["kernel_events"] = "sched_switch,block_rq_complete,block_rq_issue," \
                "block_bio_remap,block_bio_backmerge,netif_receive_skb," \
                "net_dev_xmit,sched_process_fork,sched_process_exec," \
                "lttng_statedump_process_state,lttng_statedump_file_descriptor," \
                "lttng_statedump_block_device"
        self.analyses["io"]["syscalls"] = True

        self.running_threads = {}
        self.jobid = 0

    def get_analyses(self):
        analysesList = []

        for k in self.analyses:
            analysesList.append({
                "analysis": k
            })
        return Response(json.dumps(analysesList), mimetype="application/json")

    def get_ssh_keys(self):
        path = os.path.join(os.environ["HOME"], ".ssh")
        l = os.listdir(path)
        keys = []
        for k in l:
            if ".pub" in k:
                f = open(os.path.join(path,k))
                keys.append(f.read())
        return jsonify({ 'keys': keys })

    def get_server_list(self):
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
        return Response(json.dumps(servers), mimetype="application/json")

    def get_server_list(self):
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
        return Response(json.dumps(servers), mimetype="application/json")

    def check_requirements(self, host, username):
        # check SSH connection
        try:
            ret = subprocess.check_output("%s %s@%s id" \
                    % (self.ssh, username, host), shell=True)
        except subprocess.CalledProcessError:
            return "Cannot establish an ssh connection : %s %s@%s failed\n" \
                    % (self.ssh, username, host), 503

        # check for a root sessiond
        try:
            ret = subprocess.check_output("%s %s@%s pgrep -u root lttng-sessiond" \
                    % (self.ssh, username, host), shell=True)
        except subprocess.CalledProcessError:
            return "Root lttng-sessiond not started\n", 503

        # check tracing group or root
        if username != "root":
            try:
                ret = subprocess.check_output("%s %s@%s groups|grep tracing" \
                        % (self.ssh, username, host), shell=True)
            except subprocess.CalledProcessError:
                return "User not in tracing group", 503
        return 0

    def launch_trace(self, host, username, relay, type, duration, task):
        task["session_name"] = "%s-%s-%s" % (appname, type, task["jobid"])
        # create the session
        try:
            ret = subprocess.check_output("%s %s@%s lttng create %s -U %s" \
                    % (self.ssh, username, host, task["session_name"], "net://%s" % relay), shell=True)
        except subprocess.CalledProcessError:
            return "Session creation error\n", 503
        # enable events
        events = ""
        if "kernel_events" in self.analyses[type].keys() and \
                len(self.analyses[type]["kernel_events"]) > 0:
            try:
                ret = subprocess.check_output("%s %s@%s lttng enable-event -s %s -k %s" \
                        % (self.ssh, username, host, task["session_name"],
                            self.analyses[type]["kernel_events"]), shell=True)
            except subprocess.CalledProcessError:
                return "Enabling kernel events failed\n", 503

        if "syscalls" in self.analyses[type].keys():
            try:
                ret = subprocess.check_output("%s %s@%s lttng enable-event -s %s -k --syscall -a" \
                        % (self.ssh, username, host, task["session_name"]), shell=True)
            except subprocess.CalledProcessError:
                return "Enabling syscalls failed\n", 503

        if "userspace_events" in self.analyses[type].keys() and \
                len(self.analyses[type]["userspace_events"]) > 0:
            try:
                ret = subprocess.check_output("%s %s@%s lttng enable-event -s %s -k %s" \
                        % (self.ssh, username, host, task["session_name"],
                            self.analyses[type]["userspace_events"]), shell=True)
            except subprocess.CalledProcessError:
                return "Enabling userspace events failed\n", 503

        task["lock"].acquire()
        task["status"] = self.THREAD_TRACE_RUNNING
        task["lock"].release()

        # start the session
        try:
            ret = subprocess.check_output("%s %s@%s lttng start %s" \
                    % (self.ssh, username, host, task["session_name"]), shell=True)
        except subprocess.CalledProcessError:
            return "Session start error\n", 503

        time.sleep(duration)

        # stop the session
        try:
            ret = subprocess.check_output("%s %s@%s lttng stop %s" \
                    % (self.ssh, username, host, task["session_name"]), shell=True)
        except subprocess.CalledProcessError:
            return "Session stop error\n", 503
        # destroy the session
        try:
            ret = subprocess.check_output("%s %s@%s lttng destroy %s" \
                    % (self.ssh, username, host, task["session_name"]), shell=True)
        except subprocess.CalledProcessError:
            return "Session destroy error\n", 503

        task["lock"].acquire()
        task["status"] = self.THREAD_ANALYSIS_RUNNING
        task["lock"].release()

        ret = self.launch_analysis(task["relay"], username, task["session_name"])
        if ret != 0:
            task["lock"].acquire()
            task["status"] = self.THREAD_ERROR
            task["lock"].release()
            return ret

        task["lock"].acquire()
        task["status"] = self.THREAD_COMPLETE
        task["lock"].release()
        return 0

    def launch_analysis(self, host, username, session_name):
        # This will be specified in the request eventually
        script = "fd-info.py"
        # These should probably become the default behaviour,
        # or at least add some sort of daemon mode to analyses
        args = "--quiet --mongo"

        try:
            ret = subprocess.check_output("%s %s@%s python3 %s%s %s %s%s*/kernel" \
                    % (self.ssh, username, host, self.PATH_ANALYSES, script, args,
                       self.PATH_TRACES, session_name), shell=True)
        except subprocess.CalledProcessError:
            return "Analysis python script error\n", 503
        return 0

    def cleanup_threads(self):
        # get rid of the completed threads
        # FIXME: only called from get_analyses_list for now, need a GC
        to_delete = []
        for s in self.running_threads.keys():
            t =  self.running_threads[s]
            t["lock"].acquire()
            if t["status"] == self.THREAD_COMPLETE or \
                    t["status"] == self.THREAD_ERROR:
                t["thread"].join()
                to_delete.append(s)
            t["lock"].release()

        for d in to_delete:
            del self.running_threads[d]

    def get_analyses_list(self):
        self.cleanup_threads()
        sessions = []
        for s in self.running_threads.keys():
            sess = {}
            t =  self.running_threads[s]
            sess["jobid"] = t["jobid"]
            t["lock"].acquire()
            sess["status"] = t["status"]
            t["lock"].release()
            sessions.append(sess)
        return jsonify( { 'sessions': sessions } )

    def start_analysis(self):
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
            r = self.relay

        type = request.json["type"]
        duration = request.json["duration"]
        host = request.json["host"]
        username = request.json["username"]

        if not type in self.analyses.keys():
            return "Unknown analysis type\n", 503

        ret = self.check_requirements(host, username)
        if ret != 0:
            return ret

        self.jobid += 1
        task = {}
        task["status"] = self.THREAD_STARTED
        task["lock"] = threading.Lock()
        task["relay"] = r
        task["jobid"] = self.jobid
        t = threading.Thread(name='trace', target=self.launch_trace,
                args=(host, username, r, type, duration, task))
        task["thread"] = t
        self.running_threads[self.jobid] = task
        t.start()
        return "Started %s analysis for %d seconds on host %s, jobid = %d\n" % \
                (type, duration, host, self.jobid)

app = Flask(__name__)
appname = "Tracevisor"
appversion = "1.0-alpha0"

@app.route('/')
@crossdomain(origin='*')
def index():
    return "%s %s" % (appname, appversion)

@app.route('/trace/api/v1.0/analyses', methods = ['GET'])
@crossdomain(origin='*')
def get_analyses():
    return tracevisor.get_analyses()

@app.route('/trace/api/v1.0/ssh', methods = ['GET'])
@crossdomain(origin='*')
def get_ssh_keys():
    return tracevisor.get_ssh_keys()

@app.route('/trace/api/v1.0/servers', methods = ['GET'])
@crossdomain(origin='*')
def get_server_list():
    return tracevisor.get_server_list()

@app.route('/trace/api/v1.0/list', methods = ['GET'])
@crossdomain(origin='*')
def get_analyses_list():
    return tracevisor.get_analyses_list()

@app.route('/trace/api/v1.0/analyses', methods = ['POST', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def start_analysis():
    return tracevisor.start_analysis()

if __name__ == '__main__':
    tracevisor = Tracevisor()
    app.run(host='0.0.0.0', debug = True)
