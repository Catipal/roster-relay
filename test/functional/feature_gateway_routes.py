#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test routing a whole computer through the system-wide interface.

Design note 001 section 8.7: on Linux the
node, given the right to manage the network, routes the computer's traffic
through its interface itself (-gatewayroutes), keeps the computer's own
networks and its own connections off it, and takes the routes down when it
stops.

The visitor node runs as a computer of its own: a network namespace joined to
the rest of this machine by a virtual cable, its only way out. The other
seven nodes - five relays and two gateways - and an HTTP server standing in
for a website are on this machine's side of the cable, at addresses the
visitor reaches only through its default route. So:

  * the node's own traffic - the overlay to its relays, peer-to-peer to the
    others - has to pass the interface by, or the node would lose the
    network it carries the computer's traffic over: it stays in sync and
    meets gateways with the routes on from its first packet. The relays are
    listed at an address their route back to the visitor does not answer
    from, so this also needs them to answer from the address written to
    (feature_overlay_second_address.py);
  * a plain program in the namespace, with no proxy setting, reaches the
    website through a gateway: the website sees the gateway's address, not
    the namespace's;
  * a lookup sent to any resolver is answered through the interface;
  * the node's local network (the cable's own subnet) stays reachable;
  * when the node stops, the routes go and the computer is on its own line:
    the website sees the namespace's address again.

Needs root, the ip tool and /dev/net/tun: Linux only.
"""

import http.server
import os
import shutil
import socket
import stat
import subprocess
import sys
import threading

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

EPOCH = 480
OTHERS = "198.51.100.8"   # this machine's side: relays, gateways
WEBSITE = "198.51.100.7"  # the "internet"
CABLE_OUT, CABLE_IN = "10.201.0.1", "10.201.0.2"

CLIENT = r'''
import socket, sys
mode = sys.argv[1]
if mode == "get":
    host, port, path = sys.argv[2], int(sys.argv[3]), sys.argv[4]
    s = socket.create_connection((host, port), timeout=60)
    s.sendall(b"GET " + path.encode() + b" HTTP/1.0\r\nHost: test\r\n\r\n")
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    sys.stdout.buffer.write(data.partition(b"\r\n\r\n")[2])
elif mode == "dns":
    server, name, qtype = sys.argv[2], sys.argv[3], int(sys.argv[4])
    q = bytes([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(30)
    s.sendto(q, (server, 53))
    a, src = s.recvfrom(4096)
    print(src[0], a[3] & 15)
'''


def free_port():
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        # Who connected: a gateway, or the namespace itself.
        body = ("from %s\n" % self.client_address[0]).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def ip(*args, check=True):
    return subprocess.run(["ip"] + list(args), check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True)


class GatewayRoutesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 8
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False
        self.rpc_timeout = 300
        self.http_port = free_port()
        tag = os.getpid() % 100000
        self.netns = "bpsrt%d" % tag
        self.cable_out, self.cable_in = "bpsro%d" % tag, "bpsri%d" % tag
        self.device = "bpstun%d" % tag
        common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0", "-gatewayproxy=0"]
        gateway = common + ["-gatewayallowlocal", "-gatewayports=%d" % self.http_port]
        visitor = common + ["-gatewayallowlocal", "-gatewayinterface=%s" % self.device, "-gatewayroutes",
                            "-bind=%s" % CABLE_IN, "-rpcbind=%s" % CABLE_IN, "-rpcallowip=%s" % CABLE_OUT]
        self.extra_args = [list(common) for _ in range(5)] + [list(gateway), list(gateway), visitor]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not sys.platform.startswith("linux"):
            raise SkipTest("routes are set with Linux's ip tool here")
        if os.geteuid() != 0 or not shutil.which("ip") or not os.path.exists("/dev/net/tun"):
            raise SkipTest("needs root, the ip tool and /dev/net/tun")

    def make_computer(self):
        """The visitor's computer: a namespace whose only way out is a cable to this machine."""
        ip("netns", "add", self.netns)
        ip("link", "add", self.cable_out, "type", "veth", "peer", "name", self.cable_in)
        ip("link", "set", self.cable_in, "netns", self.netns)
        ip("addr", "add", CABLE_OUT + "/24", "dev", self.cable_out)
        ip("link", "set", self.cable_out, "up")
        ip("-n", self.netns, "addr", "add", CABLE_IN + "/24", "dev", self.cable_in)
        ip("-n", self.netns, "link", "set", self.cable_in, "up")
        ip("-n", self.netns, "link", "set", "lo", "up")
        ip("-n", self.netns, "route", "add", "default", "via", CABLE_OUT)
        for a in (OTHERS, WEBSITE):
            ip("addr", "add", a + "/32", "dev", "lo")

    def remove_computer(self):
        ip("netns", "del", self.netns, check=False)
        ip("link", "del", self.cable_out, check=False)
        for a in (OTHERS, WEBSITE):
            ip("addr", "del", a + "/32", "dev", "lo", check=False)

    def setup_network(self):
        self.make_computer()
        self.setup_nodes()
        for i in range(6):
            self.connect_nodes(i + 1, i)
        peer = "%s:%d" % (OTHERS, p2p_port(0))
        self.nodes[7].addnode(peer, "add")
        self.nodes[7].addnode(peer, "onetry")
        self.wait_until(lambda: len(self.nodes[7].getpeerinfo()) > 0, timeout=60)

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        wrapper = os.path.join(self.options.tmpdir, "in-netns.sh")
        with open(wrapper, "w", encoding="utf8") as f:
            f.write("#!/bin/sh\nexec ip netns exec %s %s \"$@\"\n" % (self.netns, self.options.bitcoind))
        os.chmod(wrapper, os.stat(wrapper).st_mode | stat.S_IEXEC)
        visitor = self.nodes[7]
        visitor.args[0] = wrapper
        visitor.rpchost = CABLE_IN
        self.start_nodes()
        if self.is_wallet_compiled():
            self.import_deterministic_coinbase_privkeys()

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
        return self.nodes[7].getgatewayinfo()["visitor"]

    def open_gateways(self):
        return sorted(g["key"] for g in self.visitor()["gateways"] if g["state"] == "open")

    def on_computer(self, *args):
        out = subprocess.run(["ip", "netns", "exec", self.netns, sys.executable, self.client] + [str(a) for a in args],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        assert out.returncode == 0, out.stderr.decode(errors="replace")
        return out.stdout.decode()

    def rules(self):
        return ip("-n", self.netns, "rule", "show").stdout

    def run_test(self):
        server = http.server.ThreadingHTTPServer(("0.0.0.0", self.http_port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.client = os.path.join(self.options.tmpdir, "client.py")
        with open(self.client, "w", encoding="utf8") as f:
            f.write(CLIENT)
        try:
            self.run_scenario()
        finally:
            server.shutdown()
            self.stop_node(7)
            self.remove_computer()

    def run_scenario(self):
        self.log.info("the routes are up from the visitor's first packet")
        rules = self.rules()
        assert "25200:" in rules and "25201:" in rules, rules
        assert "fwmark 0x6270" in rules, rules
        assert self.device in ip("-n", self.netns, "route", "show", "table", "25200").stdout

        payer = self.nodes[0]
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.log.info("the visitor's own peer-to-peer traffic passes the interface by: it follows the chain")
        self.sync_all()

        self.log.info("list five relays at this machine's address, and nodes 5, 6 and 7 as gateways with none")
        for n in range(5):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": OTHERS, "port": p2p_port(n)}]})
            payer.publishrecord(record["hex"])
        for n in (5, 6, 7):
            payer.publishrecord(self.nodes[n].createannouncement({"gateway": True})["hex"])
        payer.generatetoaddress(1, payer.getnewaddress())
        self.sync_all()
        self.mine_to(2 * EPOCH + 10)

        self.log.info("and so does its overlay traffic: it meets both gateways")
        for n in (5, 6):
            self.wait_until(lambda: self.nodes[n].getgatewayinfo()["registrations"] == 3, timeout=180)
        self.wait_until(lambda: self.visitor()["allowed"], timeout=90)
        self.wait_until(lambda: self.open_gateways() == sorted([self.key(5), self.key(6)]), timeout=300)

        self.log.info("a plain program on the computer reaches the website through a gateway")
        for _ in range(3):
            seen = self.on_computer("get", WEBSITE, self.http_port, "/")
            self.log.info("  the website saw a connection %s", seen.strip())
            assert seen.startswith("from ") and CABLE_IN not in seen, seen
        assert self.visitor()["interface"]["packets_out"] > 0

        self.log.info("a lookup sent to any resolver is answered through the interface")
        src, rcode = self.on_computer("dns", "9.9.9.9", "pilot.bps", 1).split()
        assert_equal((src, int(rcode)), ("9.9.9.9", 3))

        self.log.info("the computer's own network stays off the interface")
        before = self.visitor()["interface"]["packets_out"]
        assert_equal(self.on_computer("get", CABLE_OUT, self.http_port, "/").strip(), "from %s" % CABLE_IN)
        assert_equal(self.visitor()["interface"]["packets_out"], before)

        self.log.info("when the node stops, the routes go, and the computer is on its own line again")
        self.stop_node(7)
        rules = self.rules()
        assert "25200:" not in rules and "25201:" not in rules, rules
        assert_equal(self.on_computer("get", WEBSITE, self.http_port, "/").strip(), "from %s" % CABLE_IN)


if __name__ == '__main__':
    GatewayRoutesTest().main()
