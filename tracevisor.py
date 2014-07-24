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
import sqlite3

from relay import *

class Tracevisor:
    THREAD_STARTED = 1
    THREAD_TRACE_RUNNING = 2
    THREAD_ANALYSIS_RUNNING = 3
    THREAD_COMPLETE = 4
    THREAD_ERROR = -1
    # Temporarily hardcoded
    PATH_ANALYSES = "/usr/local/src/lttng-analyses/"
    PATH_TRACES = "/root/lttng-traces/"
    DBVERSION = 2

    def __init__(self):
        self.default_relay = "127.0.0.1"
        self.default_mongohost = "127.0.0.1"
        self.default_mongoport = 27017
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
        self.analyses["io"]["script"] = "fd-info.py"
        self.analyses["io"]["args"] = "--quiet --mongo"

        self.running_threads = {}
        self.jobid = 0
        self.relay = Relay()
        self.client = Client()
        self.analyzes_servers = AnalyzesServers()

    def connect_db(self):
        self.con = sqlite3.connect("config.db")

    def disconnect_db(self):
        self.con.close()

    def drop_all_tables(self, cur):
        try:
            cur.execute("DROP TABLE schema")
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("DROP TABLE relays")
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("DROP TABLE clients")
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("DROP TABLE analyzes")
        except sqlite3.OperationalError:
            pass

    def check_db(self):
        self.connect_db()
        with self.con:
            cur = self.con.cursor()
            try:
                cur.execute("SELECT version FROM schema")
            except sqlite3.OperationalError:
                print("Creating database")
                self.drop_all_tables(cur)
                cur.execute("CREATE TABLE schema (version INT)")
                cur.execute("INSERT INTO schema VALUES(:version)", ({"version": self.DBVERSION}))
            r = cur.fetchall()
            if r:
                if r[0][0] != self.DBVERSION:
                    print("Different DB version, resetting the database")
                    self.drop_all_tables(cur)
                    cur.execute("CREATE TABLE schema (version INT)")
                    cur.execute("INSERT INTO schema VALUES(:version)", ({"version": self.DBVERSION}))

            try:
                cur.execute("select * from relays")
            except sqlite3.OperationalError:
                print("Creating \"relays\" table")
                cur.execute("CREATE TABLE relays (id INTEGER PRIMARY KEY, hostname TEXT, ipv4 TEXT,"
                    "ipv6 TEXT, ctrlport INT, dataport INT)")

            try:
                cur.execute("select * from clients")
            except sqlite3.OperationalError:
                print("Creating \"clients\" table")
                cur.execute("CREATE TABLE clients (id INTEGER PRIMARY KEY, hostname TEXT, "
                    "ipv4 TEXT, ipv6 TEXT, sshport INT, sshuser TEXT)")

            try:
                cur.execute("select * from analyzes")
            except sqlite3.OperationalError:
                print("Creating \"analyzes\" table")
                cur.execute("CREATE TABLE analyzes (id INTEGER PRIMARY KEY, hostname TEXT, "
                    "ipv4 TEXT, ipv6 TEXT, sshport INT, sshuser TEXT)")
        self.disconnect_db()

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
        server_list = []
        servers = {}
        # get the list from the database
        registered_clients = tracevisor.client.get_clients_list()
        for i in registered_clients:
            servers[i["hostname"]] = i

        # get the list from DNS-SD
        try:
            ret = subprocess.check_output("avahi-browse _lttng._tcp -p -t -r", shell=True)
        except subprocess.CalledProcessError:
            return "Error running avahi-browse _lttng._tcp -p -t", 503

        lines = str(ret, encoding='utf8').split("\n")
        for entry in lines:
            l = entry.split(";")
            # only output "resolved" entries
            if l[0] != "=":
                continue
            # avoid duplicates based on the hostname
            if l[3] in servers.keys():
                continue
            d = {}
            d["hostname"] = l[3]
            if l[2] == "IPv4":
                d["ipv4"] = l[7]
            elif l[2] == "IPv6":
                d["ipv6"] = l[7]
            # the auto-discovered clients cannot be accessed with the REST URL
            d["id"] = -1
            servers[d["hostname"]] = d

        for i in servers.keys():
            server_list.append(servers[i])
        return Response(json.dumps(server_list), mimetype="application/json")

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
        task["session_name"] = "%s-%s-%s-%s" % (appname, type,
                str(int(time.time())), task["jobid"])
        # get the target hostname
        try:
            ret = subprocess.check_output("%s %s@%s hostname -s" \
                    % (self.ssh, username, host), shell=True)
        except subprocess.CalledProcessError:
            return "Failed to get the hostname\n", 503
        hostname = ret.decode().strip()

        # create the session
        try:
            ret = subprocess.check_output("%s %s@%s lttng create %s -U %s" \
                    % (self.ssh, username, host, task["session_name"],
                        "net://%s" % relay), shell=True)
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

        ret = self.launch_analysis(task["analysis"], username,  hostname,
                task["session_name"], type, task["mongohost"], task["mongoport"])
        if ret != 0:
            task["lock"].acquire()
            task["status"] = self.THREAD_ERROR
            task["lock"].release()
            return ret

        task["lock"].acquire()
        task["status"] = self.THREAD_COMPLETE
        task["lock"].release()
        return 0

    def launch_analysis(self, host, username, hostname, session_name, type, mongohost,
            mongoport):
        if not "script" in self.analyses[type].keys() or \
                not "args" in self.analyses[type].keys():
                    return "Missing analyses script or args\n", 503
        script = self.analyses[type]["script"]
        args = self.analyses[type]["args"]
        try:
            ret = subprocess.check_output("%s %s@%s python3 %s%s %s %s:%s %s/%s/%s*/kernel" \
                    % (self.ssh, username, host, self.PATH_ANALYSES, script, args,
                        mongohost, mongoport, self.PATH_TRACES, hostname, session_name),
                    shell=True)
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
            r = self.default_relay

        # override the analysis server in the request
        # by default, take the same address as the relay
        if 'analysis' in request.json:
            a = request.json["analysis"]
        else:
            a = r

        if 'mongohost' in request.json:
            mongohost = request.json["mongohost"]
        else:
            mongohost = self.default_mongohost

        if 'mongoport' in request.json:
            mongoport = request.json["mongoport"]
        else:
            mongoport = self.default_mongoport

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
        task["analysis"] = a
        task["mongohost"] = mongohost
        task["mongoport"] = mongoport
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

@app.route('/trace/api/v1.0/list', methods = ['GET'])
@crossdomain(origin='*')
def get_analyses_list():
    return tracevisor.get_analyses_list()

@app.route('/trace/api/v1.0/analyses', methods = ['POST', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def start_analysis():
    return tracevisor.start_analysis()

# relays
@app.route('/trace/api/v1.0/relays', methods = ['GET'])
@crossdomain(origin='*')
def get_relays_list():
    return tracevisor.relay.get_relays_list()

@app.route('/trace/api/v1.0/relays/<int:relay_id>', methods = ['GET'])
@crossdomain(origin='*')
def get_relay(relay_id):
    return tracevisor.relay.get_relay_id(relay_id)

@app.route('/trace/api/v1.0/relays/<int:relay_id>', methods = ['PUT'])
@crossdomain(origin='*')
def update_relay(relay_id):
    return tracevisor.relay.update_relay(relay_id)

@app.route('/trace/api/v1.0/relays', methods = ['POST', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def add_relay():
    return tracevisor.relay.add_relay()

@app.route('/trace/api/v1.0/relays/<int:relay_id>', methods = ['DELETE', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def delete_relay(relay_id):
    return tracevisor.relay.delete_relay(relay_id)

# clients
@app.route('/trace/api/v1.0/clients', methods = ['GET'])
@crossdomain(origin='*')
def get_server_list():
    return tracevisor.get_server_list()

@app.route('/trace/api/v1.0/clients/<int:client_id>', methods = ['GET'])
@crossdomain(origin='*')
def get_client(client_id):
    return tracevisor.client.get_client_id(client_id)

@app.route('/trace/api/v1.0/clients/<int:client_id>', methods = ['PUT'])
@crossdomain(origin='*')
def update_client(client_id):
    return tracevisor.client.update_client(client_id)

@app.route('/trace/api/v1.0/clients', methods = ['POST', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def add_client():
    return tracevisor.client.add_client()

@app.route('/trace/api/v1.0/clients/<int:client_id>', methods = ['DELETE', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def delete_client(client_id):
    return tracevisor.client.delete_client(client_id)

# analyzes_servers
@app.route('/trace/api/v1.0/analyzes_servers', methods = ['GET'])
@crossdomain(origin='*')
def get_analysis_list():
    return tracevisor.analyzes_servers.get_analysis_list()

@app.route('/trace/api/v1.0/analyzes_servers/<int:analyzes_id>', methods = ['GET'])
@crossdomain(origin='*')
def get_analysis(analyzes_id):
    return tracevisor.analyzes_servers.get_analysis_id(analyzes_id)

@app.route('/trace/api/v1.0/analyzes_servers/<int:analyzes_id>', methods = ['PUT'])
@crossdomain(origin='*')
def update_analyzes(analyzes_id):
    return tracevisor.analyzes_servers.update_analysis(analyzes_id)

@app.route('/trace/api/v1.0/analyzes_servers', methods = ['POST', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def add_analyzes():
    return tracevisor.analyzes_servers.add_analysis()

@app.route('/trace/api/v1.0/analyzes_servers/<int:analyzes_id>', methods = ['DELETE', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def delete_analyzes(analyzes_id):
    return tracevisor.analyzes_servers.delete_analysis(analyzes_id)

if __name__ == '__main__':
    tracevisor = Tracevisor()
    tracevisor.check_db()
    app.run(host='0.0.0.0', debug = True)
