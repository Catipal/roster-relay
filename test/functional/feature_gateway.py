#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the gateway: BPS Relay's way out to the internet (design note §8·7).

Nine nodes. Nodes 0 to 5 are relays listed with an endpoint. Nodes 6 and 7
are gateways: listed with the gateway bit and no address, met only at their
meeting points. Node 8 is a visitor running the local proxy (-gatewayproxy);
it is listed as a gateway too, since a node uses the network's internet only
while it shares its own. An HTTP server on 127.0.0.1 stands in for the
internet, which the gateways may reach here only because of
-gatewayallowlocal (regtest).

What the test is about:

  * a program on the visitor's computer reaches the "internet" through the
    proxy - small and large answers arrive intact, and the connection closes
    cleanly at the end;
  * connections are spread over both gateways, one after the other;
  * a port no gateway carries is refused at the visitor, and a .bps or home-
    network name is refused there too, without being sent to any gateway;
  * a gateway switched off is let go, and the visitor carries on through the
    other; switched on again, it is met again;
  * a gateway whose day's budget is spent says so, takes nothing new, and the
    visitor carries on through the other.
"""

import hashlib
import http.server
import random
import socket
import struct
import threading
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port

EPOCH = 480
BIG = bytes(random.Random(7).getrandbits(8) for _ in range(1536 * 1024))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        body = BIG if self.path == "/big" else b"hello from the internet\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def recv_exact(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed after %d of %d bytes" % (len(data), n))
        data += chunk
    return data


class GatewayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 9
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        self.http_port = free_port()
        self.other_port = free_port()
        self.proxy_port = free_port()
        common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0"]
        self.gateway_args = common + ["-gatewayallowlocal", "-gatewayports=%d" % self.http_port]
        self.extra_args = [list(common) for _ in range(6)] + [list(self.gateway_args), list(self.gateway_args)] + [
            common + ["-gatewayproxy", "-gatewayproxyport=%d" % self.proxy_port, "-gatewayallowlocal"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # helpers

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def mine_to(self, height):
        node = self.nodes[0]
        while node.getblockcount() < height:
            node.generatetoaddress(min(200, height - node.getblockcount()), node.getnewaddress())
        self.sync_all()
        for n in self.nodes:
            self.wait_until(lambda: n.getrosterinfo()["best_block_height"] == height, timeout=60)

    def visitor(self):
        return self.nodes[8].getgatewayinfo()["visitor"]

    def open_gateways(self):
        return sorted(g["key"] for g in self.visitor()["gateways"] if g["state"] == "open")

    def socks(self, host, port, domain=False):
        """Open a connection through the visitor's proxy. Returns (socket, reply code)."""
        s = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=90)
        s.sendall(b"\x05\x01\x00")
        assert_equal(recv_exact(s, 2), b"\x05\x00")
        if domain:
            addr = b"\x03" + bytes([len(host)]) + host.encode()
        else:
            addr = b"\x01" + socket.inet_aton(host)
        s.sendall(b"\x05\x01\x00" + addr + struct.pack(">H", port))
        reply = recv_exact(s, 10)
        assert_equal(reply[0], 5)
        return s, reply[1]

    def fetch(self, path):
        s, code = self.socks("127.0.0.1", self.http_port)
        assert_equal(code, 0)
        s.sendall(b"GET " + path.encode() + b" HTTP/1.0\r\nHost: test\r\n\r\n")
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.0 200"), head[:40]
        return body

    def fetch_works(self, path):
        try:
            return self.fetch(path) is not None
        except (AssertionError, ConnectionError, OSError):
            return False

    # the test

    def run_test(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", self.http_port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        payer = self.nodes[0]
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list six relays with addresses, and nodes 6, 7 and 8 as gateways with none")
        for n in range(6):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            payer.publishrecord(record["hex"])
        for n in (6, 7, 8):
            payer.publishrecord(self.nodes[n].createannouncement({"gateway": True})["hex"])
        payer.generatetoaddress(1, payer.getnewaddress())
        self.sync_all()
        gateways = sorted(self.key(n) for n in (6, 7, 8))
        assert_equal(sorted(e["key"] for e in self.nodes[0].getroster(0) if e["gateway"]), gateways)

        self.log.info("relays are not gateways: their keys carry an address")
        for n in range(6):
            self.wait_until(lambda: self.nodes[n].getgatewayinfo()["state"] == "off", timeout=90)

        self.log.info("into the next epoch, whose anchor lists every relay: the gateways register")
        self.mine_to(2 * EPOCH + 10)
        for n in (6, 7):
            self.wait_until(lambda: self.nodes[n].getgatewayinfo()["listed"], timeout=90)
            self.wait_until(lambda: self.nodes[n].getgatewayinfo()["registrations"] == 3, timeout=180)
            info = self.nodes[n].getgatewayinfo()
            assert_equal(info["state"], "open")
            assert_equal(info["policy"], str(self.http_port))
            assert_equal(info["allow_local"], True)

        self.log.info("the visitor may use gateways, and meets both others - never itself")
        self.wait_until(lambda: self.visitor()["allowed"], timeout=90)
        self.wait_until(lambda: self.open_gateways() == sorted([self.key(6), self.key(7)]), timeout=300)
        assert_equal(self.visitor()["proxy"], "127.0.0.1:%d" % self.proxy_port)

        self.log.info("a program reaches the internet through the proxy")
        assert_equal(self.fetch("/small"), b"hello from the internet\n")
        start = time.time()
        body = self.fetch("/big")
        took = time.time() - start
        assert_equal(len(body), len(BIG))
        assert_equal(hashlib.sha256(body).hexdigest(), hashlib.sha256(BIG).hexdigest())
        self.log.info("  %d KiB in %.1f s through two relays and a gateway, on one computer (regtest)", len(BIG) // 1024, took)

        self.log.info("one connection after another goes through the other gateway")
        for _ in range(6):
            assert_equal(self.fetch("/small"), b"hello from the internet\n")
        for n in (6, 7):
            assert self.nodes[n].getgatewayinfo()["opened"] >= 3, n
        self.wait_until(lambda: self.visitor()["connections"] == 0, timeout=60)

        self.log.info("a port no gateway carries is refused at the visitor")
        opened = [self.nodes[n].getgatewayinfo()["opened"] for n in (6, 7)]
        s, code = self.socks("127.0.0.1", self.other_port)
        s.close()
        assert_equal(code, 2)  # not allowed by ruleset
        assert_equal([self.nodes[n].getgatewayinfo()["opened"] for n in (6, 7)], opened)

        self.log.info("a .bps or home-network name never leaves the visitor")
        lookups = [self.nodes[n].getgatewayinfo()["lookups"] for n in (6, 7)]
        for name in ("someone.bps", "printer.lan", "router"):
            s, code = self.socks(name, self.http_port, domain=True)
            s.close()
            assert_equal(code, 4)  # host unreachable
        assert_equal([self.nodes[n].getgatewayinfo()["lookups"] for n in (6, 7)], lookups)

        self.log.info("a gateway switched off is let go, and connections go through the other")
        self.restart_node(7, self.gateway_args + ["-gateway=0"])
        self.connect_nodes(6, 7)
        self.connect_nodes(7, 8)
        assert_equal(self.nodes[7].getgatewayinfo()["enabled"], False)
        # Connections sent its way fail until the visitor notices it is silent.
        self.wait_until(lambda: self.fetch_works("/small") and self.key(7) not in self.open_gateways(), timeout=240)
        for _ in range(4):
            assert_equal(self.fetch("/small"), b"hello from the internet\n")

        self.log.info("switched on again, it is met again")
        self.restart_node(7, self.gateway_args)
        self.connect_nodes(6, 7)
        self.connect_nodes(7, 8)
        self.wait_until(lambda: self.nodes[7].getgatewayinfo()["registrations"] == 3, timeout=240)
        self.wait_until(lambda: self.open_gateways() == sorted([self.key(6), self.key(7)]), timeout=300)
        assert_equal(self.fetch("/small"), b"hello from the internet\n")

        self.log.info("a gateway whose day is spent says so, and the other carries on")
        self.restart_node(6, self.gateway_args + ["-gatewaybandwidth=1"])
        self.connect_nodes(5, 6)
        self.connect_nodes(6, 7)
        self.wait_until(lambda: self.nodes[6].getgatewayinfo()["registrations"] == 3, timeout=240)
        self.wait_until(lambda: self.open_gateways() == sorted([self.key(6), self.key(7)]), timeout=300)
        # Large answers until node 6's mebibyte is gone.
        deadline = time.time() + 300
        while self.nodes[6].getgatewayinfo()["state"] != "closed for today":
            assert time.time() < deadline, "node 6 never spent its budget"
            self.fetch_works("/big")
        info = self.nodes[6].getgatewayinfo()
        assert info["today_bytes"] >= 1 << 20
        self.wait_until(lambda: self.key(6) not in self.open_gateways(), timeout=180)
        for _ in range(4):
            assert_equal(self.fetch("/small"), b"hello from the internet\n")
        self.log.info("  node 6 refused %d connection(s) for its budget", self.nodes[6].getgatewayinfo()["refused_limits"])

        server.shutdown()


if __name__ == '__main__':
    GatewayTest().main()
