import sqlite3
from tracevisor import *

class AnalysesServers(Tracevisor):
    def __init__(self):
        pass

    def rq_to_analysis(self, rq):
        analysis = {}
        analysis["id"] = rq[0]
        analysis["hostname"] = rq[1]
        analysis["ipv4"] = rq[2]
        analysis["ipv6"] = rq[3]
        analysis["sshport"] = rq[4]
        analysis["sshuser"] = rq[5]
        return analysis

    def get_analysis_list(self):
        analyses = []
        resp = None
        self.connect_db()
        cur = self.con.cursor()
        with self.con:
            cur.execute("SELECT * FROM analyses")
            r = cur.fetchall()
            for i in r:
                analyses.append(self.rq_to_analysis(i))
            resp = Response(json.dumps(analyses), mimetype="application/json")
        self.disconnect_db()
        return resp

    def get_analysis(self, cur, hostname):
        cur.execute("SELECT * FROM analyses WHERE hostname=:hostname", {"hostname": hostname})
        rq = cur.fetchall()
        if rq:
            return self.rq_to_analysis(rq[0])
        return None

    def get_analysis_id(self, analysis_id):
        self.connect_db()
        with self.con:
            cur = self.con.cursor()
            cur.execute("SELECT * FROM analyses WHERE id=:id", {"id": analysis_id})
            rq = cur.fetchall()
            if rq:
                ret = Response(json.dumps(self.rq_to_analysis(rq[0])), mimetype="application/json")
            else:
                ret = "Unknown analysis ID %d\n" % analysis_id, 503
        self.disconnect_db()
        return ret

    def insert_analysis(self, cur, fields):
        ret = self.get_analysis(cur, fields["hostname"])
        if ret:
            return -1
        cur.execute("INSERT INTO analyses VALUES(NULL,?,?,?,?,?)",
                (fields["hostname"], fields["ipv4"], fields["ipv6"], fields["sshport"],
                    fields["sshuser"]))
        cur.execute("SELECT MAX(ID) FROM analyses WHERE hostname=:hostname", fields)
        r = cur.fetchall()
        return r[0][0]

    def delete_analysis(self, analysis_id):
        self.connect_db()
        cur = self.con.cursor()
        with self.con:
            cur.execute("DELETE FROM analyses WHERE id=:id", {"id":analysis_id})
        self.disconnect_db()
        return "Done"

    def add_analysis(self):
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
            rq = self.get_analysis(cur, hostname)
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
            ret = self.insert_analysis(cur, rq)
            if ret > 0:
                ret = "%s/%d" % (request.url, ret)
            else:
                ret = "Relay %s already exists\n" % hostname, 503

        self.disconnect_db()
        return ret

    def update_analysis(self, analysis_id):
        self.connect_db()
        cur = self.con.cursor()
        cur.execute("SELECT * FROM analyses WHERE id=:id", {"id": analysis_id})
        rq = cur.fetchall()
        if not rq:
            self.disconnect_db()
            # get rid of the bogus analysis_id from the request
            request.url = "/".join(request.url.split("/")[:-1])
            return self.add_analysis()

        analysis = self.rq_to_analysis(rq[0])
        if "hostname" in request.json:
            analysis["hostname"] = request.json["hostname"]
        if "ipv4" in request.json:
            analysis["ipv4"] = request.json["ipv4"]
        if "ipv6" in request.json:
            analysis["ipv6"] = request.json["ipv6"]
        if "sshuser" in request.json:
            analysis["sshuser"] = request.json["sshuser"]
        if "sshport" in request.json:
            analysis["sshport"] = request.json["sshport"]

        cur.execute("UPDATE analyses SET hostname=:hostname, ipv4=:ipv4, ipv6=:ipv6,"
                "sshuser=:sshuser, sshport=:sshport WHERE id=:id", (analysis))
        self.con.commit()
        self.disconnect_db()
        return "%s" % (request.url)
