import sqlite3
from tracevisor import *

class Client(Tracevisor):
    def __init__(self):
        pass

    def get_clients_list(self):
        clients = []
        resp = None
        self.connect_db()
        cur = self.con.cursor()
        with self.con:
            cur.execute("SELECT * FROM clients")
            r = cur.fetchall()
            for i in r:
                client = {}
                client["hostname"] = i[0]
                client["ipv4"] = i[1]
                client["ipv6"] = i[2]
                client["sshport"] = i[3]
                client["sshuser"] = i[4]
                clients.append(client)
        self.disconnect_db()
        return clients

    def get_client(self, cur, hostname):
        client = {}
        cur.execute("SELECT * FROM clients WHERE hostname=:hostname", {"hostname": hostname})
        rq = cur.fetchall()
        if rq:
            client["hostname"] = rq[0][0]
            client["ipv4"] = rq[0][1]
            client["ipv6"] = rq[0][2]
            client["sshport"] = rq[0][3]
            client["sshuser"] = rq[0][4]
            return client
        return None

    def insert_client(self, cur, fields):
        cur.execute("SELECT * FROM clients WHERE hostname=:hostname", fields)
        rq = cur.fetchall()
        if rq:
            cur.execute("UPDATE clients SET ipv4=:ipv4, ipv6=:ipv6, "
                    "sshport=:sshport, sshuser=:sshuser WHERE hostname=:hostname", fields)
        else:
            cur.execute("INSERT INTO clients VALUES(?,?,?,?,?)",
                    (fields["hostname"], fields["ipv4"], fields["ipv6"], fields["sshport"],
                        fields["sshuser"]))

    def delete_client(self):
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
            r = self.get_client(cur, hostname)
            if r:
                cur.execute("DELETE FROM clients WHERE hostname=:hostname", {"hostname":hostname})
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
            self.insert_client(cur, rq)

        self.disconnect_db()
        return "Done\n"
