import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .service import Config, HilError, Service


def make_handler(service):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def reply(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def dispatch(self, fn, **kwargs):
            try:
                self.reply(200, fn(**kwargs))
            except HilError as e:
                self.reply(409, {"error": str(e)})
            except (TypeError, ValueError) as e:
                self.reply(400, {"error": str(e)})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self.reply(400, {"error": "body is not JSON"})
            routes = {"/lease": service.acquire, "/boot": service.boot, "/release": service.release}
            fn = routes.get(urlparse(self.path).path)
            if fn is None:
                return self.reply(404, {"error": "not found"})
            self.dispatch(fn, **body)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path != "/log":
                return self.reply(404, {"error": "not found"})
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            self.dispatch(service.log, run_id=q.get("run", ""), which=q.get("which", "proxy"),
                          tail=int(q.get("tail", 200)))

    return Handler


def serve(service, port):
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(service))
    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--port", type=int, default=7340)
    args = parser.parse_args()
    serve(Service(Config.load(args.config)), args.port).serve_forever()


if __name__ == "__main__":
    main()
