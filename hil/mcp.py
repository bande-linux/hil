import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL_VERSION = "2025-06-18"

TOOLS = [
    {
        "name": "hil_lease",
        "description": "Take the exclusive lease on the Mac attached to the HIL host. Returns a token.",
        "inputSchema": {"type": "object", "properties": {"owner": {"type": "string"}},
                        "required": ["owner"]},
    },
    {
        "name": "hil_boot",
        "description": "Boot a kernel on the leased Mac through unboot's USB proxy. Paths are on the HIL host. "
                       "Writes to power, PMU, SMC, voltage, fan, thermal, NVRAM and boot policy MMIO are blocked "
                       "and end the run. Returns a run id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "kernel": {"type": "string"},
                "dtb": {"type": "string"},
                "initramfs": {"type": "string"},
                "bootargs": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["token", "kernel", "dtb"],
        },
    },
    {
        "name": "hil_log",
        "description": "Status and log lines of a run: which is proxy, serial or meta.",
        "inputSchema": {
            "type": "object",
            "properties": {"run": {"type": "string"}, "which": {"type": "string"},
                           "tail": {"type": "integer"}},
            "required": ["run"],
        },
    },
    {
        "name": "hil_release",
        "description": "Give the lease back.",
        "inputSchema": {"type": "object", "properties": {"token": {"type": "string"}},
                        "required": ["token"]},
    },
]


class Client:
    def __init__(self, url):
        self.url = url.rstrip("/")

    def _send(self, req):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r), False
        except urllib.error.HTTPError as e:
            return json.load(e), True

    def post(self, path, body):
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        return self._send(req)

    def get(self, path, query):
        return self._send(self.url + path + "?" + urllib.parse.urlencode(query))

    def call(self, name, args):
        if name == "hil_lease":
            return self.post("/lease", {"owner": args["owner"]})
        if name == "hil_boot":
            keys = ("token", "kernel", "dtb", "initramfs", "bootargs", "timeout")
            return self.post("/boot", {k: args[k] for k in keys if k in args})
        if name == "hil_log":
            return self.get("/log", {"run": args["run"], "which": args.get("which", "proxy"),
                                     "tail": args.get("tail", 200)})
        if name == "hil_release":
            return self.post("/release", {"token": args["token"]})
        raise KeyError(name)


def handle(client, msg):
    method = msg.get("method")
    if method == "initialize":
        return {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                "serverInfo": {"name": "unbound-hil", "version": "0.1.0"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = msg.get("params", {})
        try:
            body, failed = client.call(params.get("name"), params.get("arguments", {}))
        except KeyError as e:
            raise LookupError("unknown tool or missing argument %s" % e)
        except OSError as e:
            body, failed = {"error": "HIL daemon unreachable: %s" % e}, True
        return {"content": [{"type": "text", "text": json.dumps(body)}], "isError": failed}
    raise NotImplementedError(method)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:7340")
    args = parser.parse_args()
    client = Client(args.url)
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        if "id" not in msg:
            continue
        try:
            out = {"jsonrpc": "2.0", "id": msg["id"], "result": handle(client, msg)}
        except NotImplementedError as e:
            out = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "method not found: %s" % e}}
        except LookupError as e:
            out = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32602, "message": str(e)}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
