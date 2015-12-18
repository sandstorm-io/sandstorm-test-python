#!/usr/bin/env python3

import base64
import json
import os
import socket
import sys

from flask import Flask
from flask import request
from flask import render_template
from flask import make_response
import capnp

# Hack to make RPC work in Flask worker threads
capnp.remove_event_loop()
capnp.create_event_loop(threaded=True)

# Load the relevant interface descriptors from the current sandstorm bundle.
bridge = capnp.load("/opt/sandstorm/latest/usr/include/sandstorm/sandstorm-http-bridge.capnp",
            imports=[
                "/opt/sandstorm/latest/usr/include",
            ]
        )
grain = capnp.load("/opt/sandstorm/latest/usr/include/sandstorm/grain.capnp",
            imports=[
                "/opt/sandstorm/latest/usr/include",
            ]
        )

hack_session = capnp.load("/opt/sandstorm/latest/usr/include/sandstorm/hack-session.capnp",
            imports=[
                "/opt/sandstorm/latest/usr/include",
            ]
        )

sealed = capnp.load("/opt/sandstorm/latest/usr/include/sandstorm/sealed.capnp",
            imports=[
                "/opt/sandstorm/latest/usr/include",
            ]
        )

pkgdef = capnp.load("/sandstorm-pkgdef.capnp",
            imports=[
                "/opt/sandstorm/latest/usr/include",
            ]
        )
CODE_DIR = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)

caps_file = '/var/cap-info.json'

def get_bridge_cap():
    # Connect to the socket exposed by sandstorm-http-bridge
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect("/tmp/sandstorm-api")
    client = capnp.TwoPartyClient(sock)
    bridge_cap = client.bootstrap().cast_as(bridge.SandstormHttpBridge)
    return bridge_cap

def write_state(newState):
    with open("/var/state", "wb") as f:
        f.write(newState)

def read_state():
    with open("/var/state") as f:
        return f.read()

@app.route('/', methods=["GET", "POST"])
def index():
    if request.method == "POST":
        newState = request.form.get("state", "").encode('utf-8')
        write_state(newState)
    content = read_state()
    # Load app version from sandstorm-pkgdef.capnp
    manifest = pkgdef.pkgdef.manifest
    return render_template("index.html",
            content=content,
            session_id=request.headers.get("X-Sandstorm-Session-Id", ""),
            user_id=request.headers.get("X-Sandstorm-User-Id", ""),
            username=request.headers.get("X-Sandstorm-Username", ""),
            handle=request.headers.get("X-Sandstorm-Preferred-Handle", ""),
            permissions=request.headers.get("X-Sandstorm-Permissions", ""),
            pronouns=request.headers.get("X-Sandstorm-User-Pronouns", ""),
            app_version=manifest.appVersion,
            saved_caps=get_saved_caps(),
            )

@app.route('/reflect')
def reflect():
    # Reflects the headers from a request as a JSON object.
    # Useful for seeing what permissions/handle/etc were seen by the app after e.g. changing handle,
    # pronouns, switching identity, etc.
    headers = {}
    for (key, value) in request.headers:
        if not key in headers:
            headers[key] = []
        headers[key].append(value)
    # Future: reflect the POST body? path info? query string? anything else useful?
    reply = json.dumps({"headers": headers}, sort_keys=True)
    return make_response(reply, 200)

def get_saved_caps():
    if os.path.exists(caps_file):
        with open(caps_file) as f:
            return json.load(f)
    return []

@app.route('/caps', methods=['POST'])
def savecap():
    token = request.form.get('token')
    print("should save", token)
    sys.stdout.flush()
    caps = get_saved_caps()
    caps.append({"token": token})
    with open(caps_file, "wb") as f:
        contents = json.dumps(caps)
        f.write(contents.encode('utf-8'))
    return make_response("", 200)

@app.route('/caps/<cap_id>', methods=['POST'])
def offer_cap(cap_id):
    print("should offer", cap_id)
    sys.stdout.flush()
    # Restore the sturdyref into a liveref
    bridge_cap = get_bridge_cap()
    liveref_promise = bridge_cap.getSandstormApi().then(
        lambda res: res.api.cast_as(grain.SandstormApi).restore(cap_id)
    )

    # Then, offer that liveref to the requesting user's session context
    session_id = request.headers["X-Sandstorm-Session-Id"]
    session_ctx_promise = bridge_cap.getSessionContext(session_id)

    def offerCap(res):
        session_ctx_resp, liveref_resp = res
        session_ctx = session_ctx_resp.context.cast_as(hack_session.HackSessionContext)
        liveref = liveref_resp.cap
        return session_ctx.offer(cap=liveref)

    capnp.join_promises([session_ctx_promise, liveref_promise]).then(
        offerCap
    ).wait()

    return make_response("", 200)

@app.route('/api')
def api():
    body = json.dumps({"state": read_state()})
    return make_response(body, 200)

if __name__ == "__main__":
    app.run('0.0.0.0', 8000, debug=True)
