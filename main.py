#!/usr/bin/env python3

import base64
import binascii
import json
import os
import socket
import sys
from urllib.parse import urlparse

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

powerbox = capnp.load("/opt/sandstorm/latest/usr/include/sandstorm/powerbox.capnp",
            imports=[
                "/opt/sandstorm/latest/usr/include",
            ]
        )

identity = capnp.load("/opt/sandstorm/latest/usr/include/sandstorm/identity.capnp",
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

def debug(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()

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
    request_token = request.form.get('token')
    descriptor = json.loads(request.form.get('descriptor'))

    # Pad out the base64'd descriptor.
    len_mod_4 = len(descriptor) % 4
    if len_mod_4 != 0:
        descriptor = descriptor + ((4 - len_mod_4) * "=")

    # Parse, and JSONify, the powerbox descriptor as encoded by the Sandstorm frontend.
    # We ignore the AnyPointer tag value that may exist.  In practice, apps would need to know the
    # schema to compare them in a content-aware fashion.  And we're not requesting anything with a
    # tag, so we don't really care.
    blob = base64.urlsafe_b64decode(descriptor)
    powerbox_descriptor = powerbox.PowerboxDescriptor.from_bytes_packed(blob)
    dict_descriptor = {
        "quality": powerbox_descriptor.quality.raw,
        # We stringify tag IDs because JSON can't handle numbers this big.
        "tags": [ {
                "id": str(t.id),
                "value": None,
            } for t in powerbox_descriptor.tags
        ],
    }


    bridge_cap = get_bridge_cap()
    session_id = request.headers.get("X-Sandstorm-Session-Id", "")
    context_response = bridge_cap.getSessionContext(id=session_id).wait()
    context = context_response.context
    liveref_response = context.claimRequest(requestToken=request_token).wait()
    liveref = liveref_response.cap

    token_promise = bridge_cap.getSandstormApi().then(
        lambda res: res.api.save(liveref)
    )
    btoken = token_promise.wait().token
    token = base64.urlsafe_b64encode(btoken).decode("ascii")

    debug("should save", token)
    debug("descriptor: ", dict_descriptor)
    caps = get_saved_caps()
    caps.append({"token": token, "descriptor": dict_descriptor})
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
        debug("done() called")
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
        debug("stream should expect size", size)
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


class DiscardByteStream(util.ByteStream.Server):
    def __init__(self):
        debug("Constructed DiscardByteStream")
        pass

    def write(self, data, **kwargs):
        debug("Ignored data from socket:", data)
        pass

    def done(self, **kwargs):
        debug("Ignored close from socket")
        pass

    def expectSize(self, size, **kwargs):
        pass

class TcpPortImpl(capnpip.TcpPort.Server):
    def __init__(self):
        #self._connections = []
        self._connection_promises = []
        self._fulfilled_connections = False

    def connect(self, downstream, _context, **kwargs):
        debug(_context)
        debug("accepting connection: downstream is", downstream)
        # write some bytes to downstream.  Ignore everything
        future = downstream.write("tcptest").then(
          lambda x: downstream.done()
        ).then(
          lambda x: self.fulfill_connection_promises()
        )
        _context.results.upstream = DiscardByteStream()
        return future

    def fulfill_connection_promises(self):
        debug("Fulfilling all promises...")
        self._fulfilled_connections = True
        for p in self._connection_promises:
            p.fulfill()

    def await_serviced_connection(self):
        promise = capnp.PromiseFulfillerPair()
        if self._fulfilled_connections:
            promise.fulfill()
        self._connection_promises.append(promise)
        return promise.promise

ip_interface_ongoing_tests = {}

@app.route('/start_test_ip_interface_cap', methods=['POST'])
def start_test_ip_interface_cap():
    token = base64.urlsafe_b64decode(request.form.get('token'))
    portNum = int(request.form.get('port'), 10)
    debug("testing ipinterface token", token, "port", portNum)

    if not portNum:
        return make_response("Port required.", 400)

    bridge_cap = get_bridge_cap()
    liveref_promise = bridge_cap.getSandstormApi().then(
        lambda res: res.api.cast_as(grain.SandstormApi).restore(token=token)
    )
    liveref = liveref_promise.wait().cap

    debug("liveref:", liveref)

    port = TcpPortImpl()
    port_serviced_promise = port.await_serviced_connection()
    ipinterface = liveref.as_interface(capnpip.IpInterface)
    debug("ipinterface:", ipinterface)
    listen_future = ipinterface.listenTcp(portNum=portNum, port=port)
    debug("listen_future:", listen_future)
    server_handle = listen_future.wait().handle
    debug("server_handle:", server_handle)
    debug("port_serviced_promise:", port_serviced_promise)

    handle_id = base64.b64encode(os.urandom(8)).decode('utf-8');
    ip_interface_ongoing_tests[handle_id] = {
        "promise": port_serviced_promise,
        "bridge_cap": bridge_cap, # We need to keep the bridge cap around, since it owns the socket
        "server_handle": server_handle,
    }

    return make_response(json.dumps({ "handleId": handle_id }), 200)

@app.route('/complete_test_ip_interface_cap', methods=['POST'])
def complete_test_ip_interface_cap():
    handle_id = request.form.get('handleId')
    debug("awaiting ipinterface token usage completion")

    if handle_id not in ip_interface_ongoing_tests:
        raise Exception("Invalid handle id for awaiting IP network test completion")

    ongoing_test = ip_interface_ongoing_tests[handle_id]
    del ip_interface_ongoing_tests[handle_id]

    debug("waiting for connection...")
    port_serviced_promise = ongoing_test["promise"]
    server_handle = ongoing_test["server_handle"]
    bridge_cap = ongoing_test["bridge_cap"]
    del ongoing_test

    debug(port_serviced_promise)
    debug(server_handle)

    port_serviced_promise.wait()
    debug("serviced promise, shutting TCP listener down")
    del port_serviced_promise
    del server_handle
    del bridge_cap

    return make_response("", 200)

@app.route('/test_ip_network_cap', methods=['POST'])
def test_ip_network_cap():
    """
    Tests an IpNetwork capability by connecting to the requested host on the requested port, sending
    an HTTP request, and reading the response.
    """
    token = base64.urlsafe_b64decode(request.form.get('token'))
    urlstring = request.form.get('url')
    url = urlparse(urlstring)
    debug("testing ipnetwork token", token, "url", url)

    if url.scheme != "http":
        return make_response("URL scheme must be http.", 400)

    bridge_cap = get_bridge_cap()
    liveref_promise = bridge_cap.getSandstormApi().then(
        lambda res: res.api.cast_as(grain.SandstormApi).restore(token=token)
    )
    liveref = liveref_promise.wait().cap

    host = url.netloc.split(":")[0]
    remotehost_promise = liveref.as_interface(capnpip.IpNetwork).getRemoteHostByName(address=host)
    remotehost = remotehost_promise.wait().host

    http_port_promise = remotehost.cast_as(capnpip.IpRemoteHost).getTcpPort(portNum=url.port or 80)
    http_port = http_port_promise.wait().port

    reply_stream = HttpDownstream()
    stream_promise = http_port.connect(reply_stream)
    request_stream = stream_promise.wait().upstream
    # N.B. get this future before
    path = url.path or "/"
    if url.query:
        path += "?" + url.query

    request_text = "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n".format(path=path, host=url.netloc)
    request_stream.write(request_text).wait()

    debug("sent request")
    reply_stream_done_future = reply_stream.await_response()
    reply_stream_done_future.wait()
    page = reply_stream.get_page_contents()
    # only close output stream once we've read the response
    request_stream.done().wait()
    debug(page)

    return make_response(page, 200)

@app.route('/test_identity_cap', methods=['POST'])
def test_identity_cap():
    token = base64.urlsafe_b64decode(request.form.get('token'))
    print("testing identity token", token)
    sys.stderr.flush()
    bridge_cap = get_bridge_cap()
    api = bridge_cap.getSandstormApi().api.cast_as(grain.SandstormApi)

    liveref_promise = api.restore(token=token)
    liveref = liveref_promise.wait().cap

    identity_cap = liveref.as_interface(identity.Identity)
    profile = identity_cap.getProfile().wait().profile
    picture_url = profile.picture.getUrl().wait();

    identity_id = api.getIdentityId(identity=identity_cap).wait().id;

    response = json.dumps({
        "id": binascii.hexlify(identity_id).decode('utf8'),
        "displayName": profile.displayName.defaultText,
        "preferredHandle": profile.preferredHandle,
        "pictureUrl": "{}://{}".format(picture_url.protocol, picture_url.hostPath),
    })
    return make_response(response, 200)

@app.route('/caps/<cap_id>', methods=['POST'])
def offer_cap(cap_id):
    debug("should offer", cap_id)
    cap_id = base64.urlsafe_b64decode(cap_id)

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
        uiViewTag = powerbox.PowerboxDescriptor.Tag.new_message(id=grain.UiView.schema.node.id)
        descriptor = powerbox.PowerboxDescriptor.new_message(tags=[uiViewTag])
        displayInfo = powerbox.PowerboxDisplayInfo.new_message(
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
