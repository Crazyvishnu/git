"""Private, outbound-only LG webOS remote relay. Python 3.8+ standard library."""
import os
import json
import time
import secrets
import threading
from collections import deque
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

PHONE_TOKEN = os.getenv("PHONE_TOKEN", "")
TV_TOKEN = os.getenv("TV_TOKEN", "")
if min(len(PHONE_TOKEN), len(TV_TOKEN)) < 32 or PHONE_TOKEN == TV_TOKEN:
    raise SystemExit("Distinct private tokens of 32+ characters are required")

BASIC = frozenset(("HOME","BACK","UP","DOWN","LEFT","RIGHT","ENTER",
                   "VOLUMEUP","VOLUMEDOWN","MUTE","PLAY","PAUSE"))
SPECIAL = frozenset(("MOUSE_MOVE","MOUSE_CLICK","MOUSE_SCROLL",
                     "TEXT","BACKSPACE","TEXT_ENTER","GET_APPS","LAUNCH_APP"))
VALID = BASIC | SPECIAL
queue = deque()
receipts = {}
requests_window = deque()
condition = threading.Condition()
last_seen = 0.0
apps_cache = []
apps_updated = 0.0

def clean(now):
    while queue and now - queue[0]["created"] > 40:
        item = queue.popleft()
        receipts[item["id"]] = {"status":"expired","ts":now}
    for ident, item in list(receipts.items()):
        if now - item["ts"] > 180:
            del receipts[ident]

def valid_command(data):
    if not isinstance(data, dict) or data.get("key") not in VALID:
        return None
    key = data["key"]
    c = {"key":key}
    if key in ("MOUSE_MOVE","MOUSE_SCROLL"):
        dx, dy = data.get("dx", 0), data.get("dy", 0)
        if type(dx) is not int or type(dy) is not int:
            return None
        if abs(dx)>200 or abs(dy)>200 or (dx == 0 and dy == 0):
            return None
        c.update(dx=dx,dy=dy)
    elif key == "TEXT":
        message = data.get("text")
        if not isinstance(message,str) or not (1 <= len(message) <= 240):
            return None
        if any(ord(x)<32 and x not in "\n\t" for x in message):
            return None
        c["text"] = message
    elif key == "LAUNCH_APP":
        ident = data.get("app_id")
        if not isinstance(ident,str) or len(ident)>128:
            return None
        with condition:
            allowed = {app["id"] for app in apps_cache}
        if ident not in allowed:
            return None
        c["app_id"] = ident
    return c

def scrub_apps(value):
    result = []
    seen = set()
    for app in value[:180]:
        if not isinstance(app,dict):
            continue
        ident,title=app.get("id"),app.get("title")
        if not isinstance(ident,str) or not isinstance(title,str):
            continue
        if not ident or len(ident)>128 or not title.strip():
            continue
        if ident in seen:
            continue
        seen.add(ident)
        result.append({"id":ident,"title":title.strip()[:100]})
    return sorted(result,key=lambda x:x["title"].casefold())[:160]

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args):
        pass

    def response(self,status,data,mimetype="application/json"):
        body = data.encode("utf-8") if isinstance(data,str) else json.dumps(data,separators=(",",":")).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type",mimetype)
            self.send_header("Content-Length",str(len(body)))
            self.send_header("Cache-Control","no-store")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("X-Frame-Options","DENY")
            self.send_header("Content-Security-Policy","default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def authorized(self,token):
        return compare_digest(self.headers.get("Authorization",""),"Bearer "+token)

    def posted(self):
        if self.headers.get("Content-Type","").split(";")[0].strip() != "application/json":
            return None
        try:
            n=int(self.headers.get("Content-Length","0"))
            if not 2<=n<=4096:
                return None
            return json.loads(self.rfile.read(n))
        except (ValueError,TypeError,UnicodeError):
            return None

    def do_GET(self):
        global last_seen
        parsed=urlsplit(self.path)
        p=parsed.path
        if p=="/":
            with open("remote.html","r",encoding="utf-8") as f:
                return self.response(200,f.read(),"text/html; charset=utf-8")
        if p=="/health":
            return self.response(200,{"ok":True})
        if p in ("/state","/receipt","/apps") and not self.authorized(PHONE_TOKEN):
            return self.response(401,{"error":"Unauthorized"})
        if p=="/state":
            with condition:
                clean(time.time())
                connected=time.time()-last_seen<48
            return self.response(200,{"tv_online":connected})
        if p=="/apps":
            with condition:
                return self.response(200,{"apps":apps_cache,"updated_at":apps_updated})
        if p=="/receipt":
            ident=parse_qs(parsed.query).get("id",[""])[0][:48]
            with condition:
                return self.response(200,receipts.get(ident,{"status":"unknown"}))
        if p=="/next":
            if not self.authorized(TV_TOKEN):
                return self.response(401,{"error":"Unauthorized"})
            end=time.time()+18
            with condition:
                last_seen=time.time()
                clean(time.time())
                while not queue:
                    left=end-time.time()
                    if left<=0:
                        return self.response(200,{"command":None})
                    condition.wait(left)
                    last_seen=time.time()
                    clean(time.time())
                item=queue.popleft()
                receipts[item["id"]]={"status":"delivered","ts":time.time()}
                return self.response(200,{"command":item["key"],"id":item["id"],"params":item["params"]})
        return self.response(404,{"error":"Not found"})

    def do_POST(self):
        global last_seen,apps_cache,apps_updated
        p=urlsplit(self.path).path
        if p=="/command":
            if not self.authorized(PHONE_TOKEN):
                return self.response(401,{"error":"Unauthorized"})
            data=self.posted()
            command=valid_command(data)
            if not command:
                return self.response(400,{"error":"Unsupported or invalid command"})
            now=time.time()
            with condition:
                clean(now)
                while requests_window and now-requests_window[0]>10:
                    requests_window.popleft()
                limit=100 if command["key"] in ("MOUSE_MOVE","MOUSE_SCROLL") else 40
                if len(requests_window)>=limit or len(queue)>=35:
                    return self.response(429,{"error":"Too many commands"})
                if now-last_seen>48:
                    return self.response(503,{"error":"TV agent offline"})
                requests_window.append(now)
                ident=secrets.token_hex(9)
                if command["key"]=="MOUSE_MOVE" and queue and queue[-1]["key"]=="MOUSE_MOVE":
                    previous=queue[-1]
                    previous["params"]["dx"]=max(-400,min(400,previous["params"]["dx"]+command["dx"]))
                    previous["params"]["dy"]=max(-400,min(400,previous["params"]["dy"]+command["dy"]))
                    receipts[ident]={"status":"done","ts":now}
                    return self.response(202,{"id":ident,"status":"coalesced"})
                queue.append({"id":ident,"key":command["key"],"params":command,"created":now})
                receipts[ident]={"status":"queued","ts":now}
                condition.notify_all()
            return self.response(202,{"id":ident,"status":"queued"})
        if p=="/ack":
            if not self.authorized(TV_TOKEN):
                return self.response(401,{"error":"Unauthorized"})
            data=self.posted()
            if not isinstance(data,dict) or not isinstance(data.get("id"),str):
                return self.response(400,{"error":"Invalid receipt"})
            with condition:
                ident=data["id"]
                item=receipts.get(ident)
                if not item or item["status"]!="delivered":
                    return self.response(404,{"error":"Unknown command"})
                status="done" if data.get("ok") is True else "failed"
                receipts[ident]={"status":status,"ts":time.time()}
                if status=="done" and isinstance(data.get("apps"),list):
                    apps_cache=scrub_apps(data["apps"])
                    apps_updated=time.time()
            return self.response(200,{"ok":True})
        return self.response(404,{"error":"Not found"})

if __name__=="__main__":
    ThreadingHTTPServer(("0.0.0.0",int(os.getenv("PORT","8080"))),Handler).serve_forever()
