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
util = capnp.load("/opt/sandstorm/latest/usr/include/sandstorm/util.capnp",
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

pkgdef = capnp.load("/sandstorm-pkgdef.capnp",
            imports=[
                "/opt/sandstorm/latest/usr/include",
            ]
        )

capnpip = capnp.load("/opt/sandstorm/latest/usr/include/sandstorm/ip.capnp",
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
    saved_caps = get_saved_caps()
    return render_template("index.html",
            content=content,
            session_id=request.headers.get("X-Sandstorm-Session-Id", ""),
            user_id=request.headers.get("X-Sandstorm-User-Id", ""),
            username=request.headers.get("X-Sandstorm-Username", ""),
            handle=request.headers.get("X-Sandstorm-Preferred-Handle", ""),
            permissions=request.headers.get("X-Sandstorm-Permissions", ""),
            pronouns=request.headers.get("X-Sandstorm-User-Pronouns", ""),
            app_version=manifest.appVersion,
            saved_caps=saved_caps,
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
    """
    Save a sturdyref from the client in durable storage.

    Arguably, we should save the PowerboxDescriptor from the client here too,
    and pass that on when we later do an offer_cap(), rather than forging a
    new PowerboxDescriptor from whole cloth.
    """
    token = request.form.get('token')
    descriptor = json.loads(request.form.get('descriptor'))
    print("should save", token)
    print("descriptor: ", descriptor)
    sys.stdout.flush()
    caps = get_saved_caps()
    caps.append({"token": token, "descriptor": descriptor})
    with open(caps_file, "wb") as f:
        contents = json.dumps(caps)
        f.write(contents.encode('utf-8'))
    return make_response("", 200)

class HttpDownstream(util.ByteStream.Server):
    def __init__(self):
        self._buf = b""
        self._state = "READ_HEADERS" # other states: READ_BODY, DONE
        self._headers_data = b""
        self._headers = None
        self._header_promises = []
        self._response_promises = []
        self._page = b""
        self._sep = b'\r\n\r\n'

    def write(self, data, **kwargs):
        self._buf = self._buf + data
        # TODO: push bytes to protocol parser, rather than buffering the whole page
        # TODO: use a real parser, not this questionable hand-rolled thing
        if self._state == "READ_HEADERS":
            sep_index = self._buf.find(self._sep)
            if sep_index != -1:
                self._headers_data = self._buf[:sep_index]
                self._buf = self._buf[sep_index+len(self._sep):]
                self._state = "READ_BODY"
                self.fulfill_header_promises()

    def done(self, **kwargs):
        print("done() called")
        sys.stdout.flush()
        if self._state != "READ_BODY":
            raise Exception("Never received page body")
        self._page = self._buf
        self._state = "DONE"
        self.fulfill_response_promises()

    def fulfill_header_promises(self):
        for f in self._header_promises:
            f.fulfill()

    def fulfill_response_promises(self):
        for f in self._response_promises:
            f.fulfill()

    def expectSize(self, size, **kwargs):
        # ignore this for now
        print("stream should expect size", size)
        sys.stdout.flush()
        pass

    def await_headers(self):
        promise = capnp.PromiseFulfillerPair()
        if self._state == "READ_BODY" or self._state == "DONE":
            promise.fulfill()
        self._header_promises.append(promise)
        return promise.promise

    def await_response(self):
        promise = capnp.PromiseFulfillerPair()
        if self._state == "DONE":
            promise.fulfill()
        self._response_promises.append(promise)
        return promise.promise

    def get_parsed_headers(self):
        if self._headers == None:
            pass
            # parse and save self._headers
            #self._headers
        return self._headers

    def get_raw_headers(self):
        return self._headers_data

    def get_page_contents(self):
        return self._page


@app.route('/test_ip_interface_cap', methods=['POST'])
def test_ip_interface_cap():
    # TODO: test an IpInterface somehow.
    return make_response("", 200)

@app.route('/test_ip_network_cap', methods=['POST'])
def test_ip_network_cap():
    """
    Tests an IpNetwork capability by connecting to zarvox.org on port 80, sending an HTTP request,
    and reading the response.
    """
    token = request.form.get('token')
    print("testing ipnetwork token", token)
    sys.stdout.flush()

    bridge_cap = get_bridge_cap()
    liveref_promise = bridge_cap.getSandstormApi().then(
        lambda res: res.api.cast_as(grain.SandstormApi).restore(token=token)
    )
    liveref = liveref_promise.wait().cap

    remotehost_promise = liveref.as_interface(capnpip.IpNetwork).getRemoteHostByName(address="zarvox.org")
    remotehost = remotehost_promise.wait().host

    http_port_promise = remotehost.cast_as(capnpip.IpRemoteHost).getTcpPort(portNum=80)
    http_port = http_port_promise.wait().port

    reply_stream = HttpDownstream()
    stream_promise = http_port.connect(reply_stream)
    request_stream = stream_promise.wait().upstream
    # N.B. get this future before
    request_stream.write("GET / HTTP/1.0\n\n").wait()

    request_stream.done().wait()
    print("sent request")
    sys.stdout.flush()
    reply_stream_done_future = reply_stream.await_response()
    reply_stream_done_future.wait()
    page = reply_stream.get_page_contents()
    print(page)
    sys.stdout.flush()

    return make_response(page, 200)

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
        uiViewTag = grain.PowerboxDescriptor.Tag.new_message(id=grain.UiView.schema.node.id)
        descriptor = grain.PowerboxDescriptor.new_message(tags=[uiViewTag])
        displayInfo = grain.PowerboxDisplayInfo.new_message(
            title=util.LocalizedText.new_message(defaultText="some title"),
            verbPhrase=util.LocalizedText.new_message(defaultText="some verbPhrase"),
            description=util.LocalizedText.new_message(defaultText="some description"),
        )
        # PowerboxDescriptor is:
        # tags: List(Tag)
        #   tag is:
        #     id uint64 (capnproto type id of an interface or capnproto type id of a struct type)
        #     value AnyPointer (optional, if struct type id above, an instance of that struct)

        # PowerboxDisplayInfo is
        # title
        # verbPhrase
        # description
        # all three are Util.LocalizedText
        return session_ctx.offer(cap=liveref, descriptor=descriptor, displayInfo=displayInfo)

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
