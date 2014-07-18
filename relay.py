import sqlite3
from tracevisor import *
from client import *

class Relay(Tracevisor):
    def __init__(self):
        pass

    def get_relays_list(self):
        relays = []
        resp = None
        self.connect_db()
        cur = self.con.cursor()
        with self.con:
            cur.execute("SELECT * FROM relays")
            r = cur.fetchall()
            for i in r:
                relay = {}
                relay["hostname"] = i[0]
                relay["ipv4"] = i[1]
                relay["ipv6"] = i[2]
                relay["ctrlport"] = i[3]
                relay["dataport"] = i[4]
                relays.append(relay)
            resp = Response(json.dumps(relays), mimetype="application/json")
        self.disconnect_db()
        return resp

    def get_relay(self, cur, hostname):
        relay = {}
        cur.execute("SELECT * FROM relays WHERE hostname=:hostname", {"hostname": hostname})
        rq = cur.fetchall()
        if rq:
            relay["hostname"] = rq[0][0]
            relay["ipv4"] = rq[0][1]
            relay["ipv6"] = rq[0][2]
            relay["ctrlport"] = rq[0][3]
            relay["dataport"] = rq[0][4]
            return relay
        return None

    def insert_relay(self, cur, fields):
        cur.execute("SELECT * FROM relays WHERE hostname=:hostname", fields)
        rq = cur.fetchall()
        if rq:
            cur.execute("UPDATE relays SET ipv4=:ipv4, ipv6=:ipv6, "
                    "ctrlport=:ctrlport, dataport=:dataport WHERE hostname=:hostname", fields)
        else:
            cur.execute("INSERT INTO relays VALUES(?,?,?,?,?)",
                    (fields["hostname"], fields["ipv4"], fields["ipv6"], fields["ctrlport"],
                        fields["dataport"]))

    def delete_relay(self):
        params = ['hostname']
        if not request.json:
            abort(400)
        # mandatory parameters
        for p in params:
            if not p in request.json:
                abort(400)
        hostname = request.json["hostname"]

        self.connect_db()
        cur = self.con.cursor()
        with self.con:
            r = self.get_relay(cur, hostname)
            if r:
                cur.execute("DELETE FROM relays WHERE hostname=:hostname", {"hostname":hostname})
        self.disconnect_db()
        return "Done"

    def add_relay(self):
        params = ['hostname']
        if not request.json:
            abort(400)
        # mandatory parameters
        for p in params:
            if not p in request.json:
                abort(400)
        if not "ipv4" in request.json and not "ipv6" in request.json:
            return "Missing IPv4 or IPv6 address\n", 400

        self.connect_db()
        with self.con:
            cur = self.con.cursor()
            hostname = request.json["hostname"]
            rq = self.get_relay(cur, hostname)
            if not rq:
                rq = {}
                rq["hostname"] = hostname
                rq["ipv4"] = ""
                rq["ipv6"] = ""
                rq["ctrlport"] = 5342
                rq["dataport"] = 5343
            if "ipv4" in request.json:
                rq["ipv4"] = request.json["ipv4"]
            if "ipv6" in request.json:
                rq["ipv6"] = request.json["ipv6"]
            if "ctrlport" in request.json:
                rq["ctrlport"] = request.json["ctrlport"]
            if "dataport" in request.json:
                rq["dataport"] = request.json["dataport"]
            self.insert_relay(cur, rq)

        self.disconnect_db()
        return "Done\n"
