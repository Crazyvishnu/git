"""Single-device secure command relay for an LG webOS TV. Python 3.8+; no dependencies."""
import os, json, time, secrets, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from collections import deque
from hmac import compare_digest

PHONE_TOKEN = os.getenv("PHONE_TOKEN", "")
TV_TOKEN = os.getenv("TV_TOKEN", "")
if min(len(PHONE_TOKEN), len(TV_TOKEN)) < 32 or PHONE_TOKEN == TV_TOKEN:
    raise SystemExit("Set distinct high-entropy PHONE_TOKEN and TV_TOKEN in environment")

COMMANDS = frozenset(("HOME","BACK","UP","DOWN","LEFT","RIGHT","ENTER",
                      "VOLUMEUP","VOLUMEDOWN","MUTE","PLAY","PAUSE"))
queue = deque()
receipts = {}
condition = threading.Condition()
last_seen = 0.0
requests_window = deque()

def clean(now):
    while queue and now-queue[0]["created"] > 40:
        item = queue.popleft()
        receipts[item["id"]] = {"status":"expired", "ts":now}
    for ident, item in list(receipts.items()):
        if now-item["ts"] > 180:
            del receipts[ident]

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args):
        pass
    def response(self, status, data, mimetype="application/json"):
        if isinstance(data, str):
            body = data.encode("utf-8")
        else:
            body = json.dumps(data, separators=(",",":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", mimetype)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def authorized(self, token):
        value = self.headers.get("Authorization", "")
        return compare_digest(value, "Bearer "+token)
    def posted(self):
        if self.headers.get("Content-Type","").split(";")[0].strip() != "application/json":
            return None
        try:
            length = int(self.headers.get("Content-Length","0"))
            if length < 2 or length > 1024:
                return None
            return json.loads(self.rfile.read(length))
        except (ValueError, TypeError, UnicodeError):
            return None
    def do_GET(self):
        global last_seen
        parsed = urlsplit(self.path)
        p = parsed.path
        if p == "/":
            with open("remote.html","rb") as f:
                return self.response(200, f.read().decode("utf-8"), "text/html; charset=utf-8")
        if p == "/health":
            return self.response(200, {"ok":True})
        if p == "/state":
            if not self.authorized(PHONE_TOKEN):
                return self.response(401, {"error":"Unauthorized"})
            with condition:
                connected = time.time() - last_seen < 48
                clean(time.time())
            return self.response(200, {"tv_online":connected})
        if p == "/receipt":
            if not self.authorized(PHONE_TOKEN):
                return self.response(401, {"error":"Unauthorized"})
            ident = parse_qs(parsed.query).get("id",[""])[0][:48]
            with condition:
                item = receipts.get(ident)
                return self.response(200, item or {"status":"unknown"})
        if p == "/next":
            if not self.authorized(TV_TOKEN):
                return self.response(401, {"error":"Unauthorized"})
            end = time.time()+18
            with condition:
                last_seen = time.time()
                clean(time.time())
                while not queue:
                    left = end-time.time()
                    if left <= 0:
                        return self.response(200, {"command":None})
                    condition.wait(left)
                    last_seen = time.time()
                    clean(time.time())
                item = queue.popleft()
                receipts[item["id"]] = {"status":"delivered","ts":time.time()}
            return self.response(200, {"command":item["key"],"id":item["id"]})
        return self.response(404, {"error":"Not found"})
    def do_POST(self):
        global last_seen
        p = urlsplit(self.path).path
        if p == "/command":
            if not self.authorized(PHONE_TOKEN):
                return self.response(401, {"error":"Unauthorized"})
            data = self.posted()
            if not isinstance(data, dict) or data.get("key") not in COMMANDS:
                return self.response(400, {"error":"Unsupported command"})
            now = time.time()
            with condition:
                clean(now)
                while requests_window and now-requests_window[0] > 10:
                    requests_window.popleft()
                if len(requests_window) >= 30 or len(queue) >= 25:
                    return self.response(429, {"error":"Too many commands"})
                if now-last_seen > 48:
                    return self.response(503, {"error":"TV agent offline"})
                requests_window.append(now)
                ident = secrets.token_hex(9)
                queue.append({"id":ident,"key":data["key"],"created":now})
                receipts[ident] = {"status":"queued","ts":now}
                condition.notify_all()
            return self.response(202, {"id":ident,"status":"queued"})
        if p == "/ack":
            if not self.authorized(TV_TOKEN):
                return self.response(401, {"error":"Unauthorized"})
            data = self.posted()
            if not isinstance(data,dict) or not isinstance(data.get("id"),str):
                return self.response(400,{"error":"Invalid receipt"})
            status = "done" if data.get("ok") is True else "failed"
            with condition:
                ident = data["id"]
                if ident in receipts and receipts[ident]["status"] == "delivered":
                    receipts[ident] = {"status":status,"ts":time.time()}
                    return self.response(200, {"ok":True})
            return self.response(404, {"error":"Unknown command"})
        return self.response(404,{"error":"Not found"})

if __name__ == "__main__":
    port = int(os.getenv("PORT","8080"))
    ThreadingHTTPServer(("0.0.0.0",port),Handler).serve_forever()
