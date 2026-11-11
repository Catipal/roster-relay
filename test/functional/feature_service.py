#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test services over the overlay: programs on a host's loopback, reached as streams (design note §11·6).

Eight nodes. Nodes 0 to 5 are relays listed with an endpoint; node 0 also runs
a public service. Node 6 is listed through the overlay, with no address, and
runs a hidden one: an echo server on its own 127.0.0.1. Node 7 is a visitor,
listed nowhere, that carries a port of its own computer to each service.

What the test is about:

  * a program's bytes cross the overlay whole and in order, both ways, on a
    stream of their own per connection, several at once;
  * a hidden service keeps its host registered at its meeting points, and is
    met there; a public one is reached through relays;
  * closing one side reaches the other;
  * a service that does not exist, or no longer does, closes the visitor's
    connection rather than leaving it hanging;
  * the host connects to nothing but the port its owner published;
  * a host with no pages but a service named web is a web application in a
    browser, through the visitor's site proxy, any method, with the proxy's
    own headers on every answer;
  * the host's node gives the web application one request per stream, with
    its own label for the visitor and nothing the request claimed about
    where it came from, and turns away a request the application might read
    differently than it did;
  * services are kept across a restart.
"""

import base64
import http.client
import http.server
import re
import socket
import threading

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
)

EPOCH = 480
RELAYS = 6
HIDDEN = 6
VISITOR = 7


def pattern(n, seed):
    return bytes((i * 7 + seed) & 0xff for i in range(n))


class Echo:
    """A program on a host's loopback: sends back whatever it is sent, then closes."""

    def __init__(self, port):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(16)
        self.srv.settimeout(0.5)
        self.running = True
        self.connections = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while self.running:
            try:
                c, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    @staticmethod
    def serve(c):
        try:
            while True:
                data = c.recv(65536)
                if not data:
                    break
                c.sendall(data)
            c.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        c.close()

    def stop(self):
        self.running = False
        self.srv.close()


class WebApp(http.server.BaseHTTPRequestHandler):
    """A web application on a host's loopback."""

    seen = []  # (path, headers) of every request that reached it

    def do_GET(self):
        WebApp.seen.append((self.path, self.headers))
        body = ("web application at %s" % self.path).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        # The proxy keeps its own policy on top of the program's.
        self.send_header("Referrer-Policy", "unsafe-url")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        WebApp.seen.append((self.path, self.headers))
        data = self.rfile.read(int(self.headers["Content-Length"]))
        body = data[::-1]
        self.send_response(201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def roundtrip(port, payload, timeout=240):
    """Send `payload` to 127.0.0.1:`port`, close the sending side, and read until the far end closes."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)

    def send():
        try:
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    t = threading.Thread(target=send)
    t.start()
    got = bytearray()
    while True:
        try:
            data = s.recv(65536)
        except ConnectionResetError:
            # Closed with our bytes unread: as closed as a clean end.
            break
        if not data:
            break
        got += data
    t.join()
    s.close()
    return bytes(got)


class ServiceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 8
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        self.common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0", "-gateway=0"]
        self.extra_args = [list(self.common) for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # Ports no node uses, known once the framework has chosen this run's.
        self.hidden_port = p2p_port(self.num_nodes + 1)
        self.public_port = p2p_port(self.num_nodes + 2)
        self.web_port = p2p_port(self.num_nodes + 3)
        self.proxy_port = p2p_port(self.num_nodes + 4)
        self.extra_args[VISITOR] += ["-siteproxy", "-siteproxyport=%d" % self.proxy_port]
        super().setup_network()

    def http(self, host, target, method="GET", body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=180)
        conn.request(method, target, body=body, headers={"Host": host})
        r = conn.getresponse()
        data = r.read()
        headers = dict(r.getheaders())
        conn.close()
        return r.status, headers, data

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def mine_to(self, height):
        node = self.nodes[0]
        while node.getblockcount() < height:
            node.generatetoaddress(min(200, height - node.getblockcount()), node.getnewaddress())
        self.sync_all()
        for n in self.nodes:
            self.wait_until(lambda: n.getrosterinfo()["best_block_height"] == height, timeout=60)

    def run_test(self):
        payer = self.nodes[0]
        host = self.nodes[HIDDEN]
        visitor = self.nodes[VISITOR]
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list six relays with endpoints, node 6 through the overlay, the visitor nowhere")
        for n in range(RELAYS):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            payer.publishrecord(record["hex"])
        payer.publishrecord(host.createannouncement({})["hex"])
        self.mine_to(2 * EPOCH + 10)

        self.log.info("node 6 publishes the echo program on its loopback as a service, and is met for it")
        echo = Echo(self.hidden_port)
        pub = host.publishservice("echo", self.hidden_port)
        assert_equal(pub["key"], self.key(HIDDEN))
        assert_equal(pub["hidden"], True)
        self.wait_until(lambda: host.getserviceinfo().get("registrations", 0) == 3, timeout=180)

        self.log.info("the visitor carries a port of its own to it, and bytes cross whole both ways")
        local = visitor.connectservice(self.key(HIDDEN), "echo")
        assert_equal(local["address"], "127.0.0.1:%d" % local["port"])
        payload = pattern(200 * 1024, 1)
        assert_equal(roundtrip(local["port"], payload), payload)

        self.log.info("several connections at once, each on a stream of its own")
        results = {}

        def one(i):
            data = pattern(48 * 1024, 10 + i)
            results[i] = roundtrip(local["port"], data) == data

        threads = [threading.Thread(target=one, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert_equal(results, {0: True, 1: True, 2: True})
        assert_equal(echo.connections, 4)
        info = host.getserviceinfo()
        assert info["bytes_out"] >= 200 * 1024 + 3 * 48 * 1024, info
        self.wait_until(lambda: host.getserviceinfo()["streams"] == 0, timeout=60)
        assert_equal(visitor.getserviceinfo()["forwards"][0]["port"], local["port"])

        self.log.info("a service that is not there closes the visitor's connection")
        missing = visitor.connectservice(self.key(HIDDEN), "nope")
        assert_equal(roundtrip(missing["port"], b"hello", timeout=120), b"")
        assert host.getserviceinfo()["refused"] >= 1

        self.log.info("a public service is reached through relays")
        public_echo = Echo(self.public_port)
        payer.publishservice("echo", self.public_port)
        assert_equal(payer.getserviceinfo()["hidden"], False)
        public = visitor.connectservice(self.key(0), "echo")
        data = pattern(64 * 1024, 3)
        assert_equal(roundtrip(public["port"], data), data)
        assert_equal(public_echo.connections, 1)

        self.log.info("unpublished, it is gone; the program is not reached")
        assert_equal(payer.unpublishservice("echo"), True)
        assert_equal(roundtrip(public["port"], b"hello", timeout=120), b"")
        assert_equal(public_echo.connections, 1)
        assert_equal(visitor.disconnectservice(public["port"]), True)

        self.log.info("node 6, with no pages, runs a web application: a browser reaches it through the proxy")
        web = http.server.ThreadingHTTPServer(("127.0.0.1", self.web_port), WebApp)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        host.publishservice("web", self.web_port)
        label = base64.b32encode(bytes.fromhex(self.key(HIDDEN))).decode().lower().rstrip("=")
        site = "%s.bps.localhost:%d" % (label, self.proxy_port)
        status, headers, body = self.http(site, "/hello?x=1")
        assert_equal((status, body), (200, b"web application at /hello?x=1"))
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert_equal(headers["Referrer-Policy"], "no-referrer")
        assert_equal(headers["Connection"], "close")
        status, _, body = self.http(site, "/form", method="POST", body=b"posted over BPS")
        assert_equal((status, body), (201, b"SPB revo detsop"))

        self.log.info("the host's node labels the visitor, the same on every request along one path")
        assert_equal([path for path, _ in WebApp.seen], ["/hello?x=1", "/form"])
        label = WebApp.seen[0][1]["X-BPS-Visitor"]
        assert re.fullmatch("[0-9a-f]{16}", label), label
        assert_equal(WebApp.seen[1][1]["X-BPS-Visitor"], label)

        self.log.info("a visitor that writes its own request cannot say who it is, or slip a second request in")
        own = visitor.connectservice(self.key(HIDDEN), "web")
        answer = roundtrip(own["port"],
                           b"GET /own HTTP/1.1\r\nHost: x\r\nCF-Connecting-IP: 203.0.113.9\r\n"
                           b"X-Forwarded-For: 203.0.113.9\r\nX-BPS-Visitor: ffffffffffffffff\r\n"
                           b"Connection: keep-alive\r\n\r\n"
                           b"GET /second HTTP/1.1\r\nHost: x\r\nCF-Connecting-IP: 198.51.100.1\r\n\r\n", timeout=120)
        assert b" 200 " in answer.split(b"\r\n")[0], answer[:80]
        assert answer.endswith(b"web application at /own"), answer[-80:]
        assert_equal(len(WebApp.seen), 3)
        path, headers = WebApp.seen[2]
        assert_equal(path, "/own")
        assert_equal(headers["CF-Connecting-IP"], None)
        assert_equal(headers["X-Forwarded-For"], None)
        assert re.fullmatch("[0-9a-f]{16}", headers["X-BPS-Visitor"]), headers["X-BPS-Visitor"]
        assert headers["X-BPS-Visitor"] != "ffffffffffffffff"
        assert_equal(headers["Connection"], "close")

        self.log.info("a request the application might read differently never reaches it")
        refused = host.getserviceinfo()["refused"]
        for bad in (b"POST /chunked HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                    b"GET /fold HTTP/1.1\r\nX-A: 1\nCF-Connecting-IP: 203.0.113.9\r\n\r\n"):
            assert_equal(roundtrip(own["port"], bad, timeout=120), b"")
        assert_equal(len(WebApp.seen), 3)
        assert_equal(host.getserviceinfo()["refused"], refused + 2)
        assert_equal(visitor.disconnectservice(own["port"]), True)
        web.shutdown()

        self.log.info("services are kept across a restart")
        self.restart_node(HIDDEN, self.common)
        for n in range(self.num_nodes):
            if n != HIDDEN:
                self.connect_nodes(HIDDEN, n)
        host = self.nodes[HIDDEN]
        assert_equal(host.getserviceinfo()["services"], [{"name": "echo", "port": self.hidden_port},
                                                         {"name": "web", "port": self.web_port}])
        self.wait_until(lambda: host.getserviceinfo().get("registrations", 0) == 3, timeout=180)
        payload = pattern(32 * 1024, 4)
        self.wait_until(lambda: roundtrip(local["port"], payload, timeout=120) == payload, timeout=240)

        echo.stop()
        public_echo.stop()


if __name__ == '__main__':
    ServiceTest().main()
