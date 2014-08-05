import sqlite3
from tracevisor import *
from client import *
from analyses_servers import *

class Relay(Tracevisor):
    def __init__(self):
        pass

    def rq_to_relay(self, rq):
        relay = {}
        relay["id"] = rq[0]
        relay["hostname"] = rq[1]
        relay["ipv4"] = rq[2]
        relay["ipv6"] = rq[3]
        relay["ctrlport"] = rq[4]
        relay["dataport"] = rq[5]
        return relay

    def get_relays_list(self):
        relays = []
        resp = None
        self.connect_db()
        cur = self.con.cursor()
        with self.con:
            cur.execute("SELECT * FROM relays")
            r = cur.fetchall()
            for i in r:
                relays.append(self.rq_to_relay(i))
            resp = Response(json.dumps(relays), mimetype="application/json")
        self.disconnect_db()
        return resp

    def get_relay(self, cur, hostname):
        cur.execute("SELECT * FROM relays WHERE hostname=:hostname", {"hostname": hostname})
        rq = cur.fetchall()
        if rq:
            return self.rq_to_relay(rq[0])
        return None

    def get_relay_id(self, relay_id):
        self.connect_db()
        with self.con:
            cur = self.con.cursor()
            cur.execute("SELECT * FROM relays WHERE id=:id", {"id": relay_id})
            rq = cur.fetchall()
            if rq:
                ret = Response(json.dumps(self.rq_to_relay(rq[0])), mimetype="application/json")
            else:
                ret = "Unknown relay ID %d\n" % relay_id, 503
        self.disconnect_db()
        return ret

    def insert_relay(self, cur, fields):
        ret = self.get_relay(cur, fields["hostname"])
        if ret:
            return -1
        cur.execute("INSERT INTO relays VALUES(NULL,?,?,?,?,?)",
                (fields["hostname"], fields["ipv4"], fields["ipv6"], fields["ctrlport"],
                    fields["dataport"]))
        cur.execute("SELECT MAX(ID) FROM relays WHERE hostname=:hostname", fields)
        r = cur.fetchall()
        return r[0][0]

    def delete_relay(self, relay_id):
        self.connect_db()
        cur = self.con.cursor()
        with self.con:
            cur.execute("DELETE FROM relays WHERE id=:id", {"id":relay_id})
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
            ret = self.insert_relay(cur, rq)
            if ret > 0:
                ret = "%s/%d" % (request.url, ret)
            else:
                ret = "Relay %s already exists\n" % hostname, 503
        self.disconnect_db()
        return ret

    def update_relay(self, relay_id):
        self.connect_db()
        cur = self.con.cursor()
        cur.execute("SELECT * FROM relays WHERE id=:id", {"id": relay_id})
        rq = cur.fetchall()
        if not rq:
            self.disconnect_db()
            # get rid of the bogus relay_id from the request
            request.url = "/".join(request.url.split("/")[:-1])
            return self.add_relay()

        relay = self.rq_to_relay(rq[0])
        if "hostname" in request.json:
            relay["hostname"] = request.json["hostname"]
        if "ipv4" in request.json:
            relay["ipv4"] = request.json["ipv4"]
        if "ipv6" in request.json:
            relay["ipv6"] = request.json["ipv6"]
        if "ctrlport" in request.json:
            relay["ctrlport"] = request.json["ctrlport"]
        if "dataport" in request.json:
            relay["dataport"] = request.json["dataport"]

        cur.execute("UPDATE relays SET hostname=:hostname, ipv4=:ipv4, ipv6=:ipv6,"
                "ctrlport=:ctrlport, dataport=:dataport WHERE id=:id", (relay))
        self.con.commit()
        self.disconnect_db()
        return "%s" % (request.url)
