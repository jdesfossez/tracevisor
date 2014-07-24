import sqlite3
from tracevisor import *

class Client(Tracevisor):
    def __init__(self):
        pass

    def rq_to_client(self, rq):
        client = {}
        client["id"] = rq[0]
        client["hostname"] = rq[1]
        client["ipv4"] = rq[2]
        client["ipv6"] = rq[3]
        client["sshport"] = rq[4]
        client["sshuser"] = rq[5]
        return client

    def get_clients_list(self):
        clients = []
        resp = None
        self.connect_db()
        cur = self.con.cursor()
        with self.con:
            cur.execute("SELECT * FROM clients")
            r = cur.fetchall()
            for i in r:
                clients.append(self.rq_to_client(i))
        self.disconnect_db()
        return clients

    def get_client(self, cur, hostname):
        cur.execute("SELECT * FROM clients WHERE hostname=:hostname", {"hostname": hostname})
        rq = cur.fetchall()
        if rq:
            return self.rq_to_client(rq[0])
        return None

    def get_client_id(self, client_id):
        self.connect_db()
        with self.con:
            cur = self.con.cursor()
            cur.execute("SELECT * FROM clients WHERE id=:id", {"id": client_id})
            rq = cur.fetchall()
            if rq:
                ret = Response(json.dumps(self.rq_to_client(rq[0])), mimetype="application/json")
            else:
                ret = "Unknown client ID %d\n" % client_id, 503
        self.disconnect_db()
        return ret

    def insert_client(self, cur, fields):
        ret = self.get_client(cur, fields["hostname"])
        if ret:
            return -1
        cur.execute("INSERT INTO clients VALUES(NULL,?,?,?,?,?)",
                (fields["hostname"], fields["ipv4"], fields["ipv6"], fields["sshport"],
                    fields["sshuser"]))
        cur.execute("SELECT MAX(ID) FROM clients WHERE hostname=:hostname", fields)
        r = cur.fetchall()
        return r[0][0]

    def delete_client(self, client_id):
        self.connect_db()
        cur = self.con.cursor()
        with self.con:
            cur.execute("DELETE FROM clients WHERE id=:id", {"id":client_id})
        self.disconnect_db()
        return "Done"

    def add_client(self):
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
            rq = self.get_client(cur, hostname)
            if not rq:
                rq = {}
                rq["hostname"] = hostname
                rq["ipv4"] = ""
                rq["ipv6"] = ""
                rq["sshport"] = 22
                rq["sshuser"] = "root"
            if "ipv4" in request.json:
                rq["ipv4"] = request.json["ipv4"]
            if "ipv6" in request.json:
                rq["ipv6"] = request.json["ipv6"]
            if "sshport" in request.json:
                rq["sshport"] = request.json["sshport"]
            if "sshuser" in request.json:
                rq["sshuser"] = request.json["sshuser"]
            ret = self.insert_client(cur, rq)
            if ret > 0:
                ret = "%s/%d" % (request.url, ret)
            else:
                ret = "Relay %s already exists\n" % hostname, 503

        self.disconnect_db()
        return ret

    def update_client(self, client_id):
        self.connect_db()
        cur = self.con.cursor()
        cur.execute("SELECT * FROM clients WHERE id=:id", {"id": client_id})
        rq = cur.fetchall()
        if not rq:
            self.disconnect_db()
            # get rid of the bogus client_id from the request
            request.url = "/".join(request.url.split("/")[:-1])
            return self.add_client()

        client = self.rq_to_client(rq[0])
        if "hostname" in request.json:
            client["hostname"] = request.json["hostname"]
        if "ipv4" in request.json:
            client["ipv4"] = request.json["ipv4"]
        if "ipv6" in request.json:
            client["ipv6"] = request.json["ipv6"]
        if "sshuser" in request.json:
            client["sshuser"] = request.json["sshuser"]
        if "sshport" in request.json:
            client["sshport"] = request.json["sshport"]

        cur.execute("UPDATE clients SET hostname=:hostname, ipv4=:ipv4, ipv6=:ipv6,"
                "sshuser=:sshuser, sshport=:sshport WHERE id=:id", (client))
        self.con.commit()
        self.disconnect_db()
        return "%s" % (request.url)
