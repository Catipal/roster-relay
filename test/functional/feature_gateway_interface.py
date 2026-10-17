#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the system-wide interface: a computer's own packets through gateways.

Design note 001 section 8.7: the overlay runs at the operating system's level,
and a computer's traffic goes to the network's gateways as IP packets. On
Linux the interface is a TUN device. Here the visitor node opens one, and the
test moves it into a network namespace of its own, so that whatever runs in
that namespace has no way out but the interface - which is how a program sees
the network once the interface carries all of a computer's traffic.

Eight nodes. Nodes 0 to 4 are relays listed with an endpoint; 5 and 6 are
gateways; 7 is the visitor, with -gatewayinterface and no proxy, its own
gateway switched on and no listing at all. An HTTP server on this machine's own address stands in for the
internet, which the gateways reach only because of -gatewayallowlocal
(regtest).

What the test is about:

  * a program in the namespace reaches the "internet" by its plain address,
    with no proxy setting - the packets go out through the interface, across
    a meeting, and the gateway opens the connection;
  * the interface's resolver answers: a .bps name is never sent anywhere, and
    other names are looked up at a gateway;
  * a port no gateway carries is refused at once, with a reset, rather than
    left to time out.

Needs root, the ip tool and /dev/net/tun: Linux only.
"""

import http.server
import os
import shutil
import socket
import subprocess
import sys
import threading

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

EPOCH = 480

CLIENT = r'''
import socket, sys
mode = sys.argv[1]
if mode == "get":
    host, port, path = sys.argv[2], int(sys.argv[3]), sys.argv[4]
    try:
        s = socket.create_connection((host, port), timeout=60)
    except ConnectionRefusedError:
        print("REFUSED")
        sys.exit(0)
    s.sendall(b"GET " + path.encode() + b" HTTP/1.0\r\nHost: test\r\n\r\n")
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    sys.stdout.buffer.write(body)
elif mode == "dns":
    name, qtype = sys.argv[2], int(sys.argv[3])
    q = bytes([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(30)
    s.sendto(q, ("10.77.1.53", 53))
    a, _ = s.recvfrom(4096)
    print(a[3] & 15, int.from_bytes(a[6:8], "big"))
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
        body = b"hello from the internet\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def ip(*args, check=True):
    return subprocess.run(["ip"] + list(args), check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True)


class GatewayInterfaceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 8
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        self.http_port = free_port()
        self.device = "bpsgw%d" % (os.getpid() % 100000)
        self.netns = "bpsgwt%d" % (os.getpid() % 100000)
        common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0", "-gatewayproxy=0"]
        gateway = common + ["-gatewayallowlocal", "-gatewayports=%d" % self.http_port]
        self.extra_args = [list(common) for _ in range(5)] + [list(gateway), list(gateway)] + [
            common + ["-gatewayallowlocal", "-gatewayinterface=%s" % self.device]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not sys.platform.startswith("linux"):
            raise SkipTest("the interface is a Linux TUN device here")
        if os.geteuid() != 0 or not shutil.which("ip") or not os.path.exists("/dev/net/tun"):
            raise SkipTest("needs root, the ip tool and /dev/net/tun")

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

    def in_netns(self, *args):
        out = subprocess.run(["ip", "netns", "exec", self.netns, sys.executable, self.client] + [str(a) for a in args],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        assert out.returncode == 0, out.stderr.decode(errors="replace")
        return out.stdout

    def run_test(self):
        # "The internet": an address of this machine's own, which from inside
        # the namespace is somewhere else.
        addrs = ip("-4", "-o", "addr", "show", "scope", "global").stdout.split()
        host = next((w.split("/")[0] for w in addrs if "/" in w), None)
        self.added = None
        if host is None:
            host = "198.51.100.7"
            ip("addr", "add", host + "/32", "dev", "lo")
            self.added = host
        self.log.info("the internet stands in at %s:%d", host, self.http_port)
        server = http.server.ThreadingHTTPServer(("0.0.0.0", self.http_port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.client = os.path.join(self.options.tmpdir, "client.py")
        with open(self.client, "w", encoding="utf8") as f:
            f.write(CLIENT)

        try:
            self.run_scenario(host)
        finally:
            server.shutdown()
            ip("netns", "del", self.netns, check=False)
            if self.added:
                ip("addr", "del", self.added + "/32", "dev", "lo", check=False)

    def run_scenario(self, host):
        payer = self.nodes[0]
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list five relays with addresses, and nodes 5 and 6 as gateways with none; the visitor not at all")
        for n in range(5):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            payer.publishrecord(record["hex"])
        for n in (5, 6):
            payer.publishrecord(self.nodes[n].createannouncement({"gateway": True})["hex"])
        payer.generatetoaddress(1, payer.getnewaddress())
        self.sync_all()
        self.mine_to(2 * EPOCH + 10)
        for n in (5, 6):
            self.wait_until(lambda: self.nodes[n].getgatewayinfo()["registrations"] >= 3, timeout=180)
        self.wait_until(lambda: self.visitor()["allowed"], timeout=90)
        self.wait_until(lambda: self.open_gateways() == sorted([self.key(5), self.key(6)]), timeout=300)
        info = self.visitor()["interface"]
        assert_equal(info["name"], self.device)
        assert_equal(info["address"], "10.77.1.2")
        assert_equal(info["resolver"], "10.77.1.53")

        self.log.info("give the interface a namespace of its own, with no other way out")
        ip("netns", "add", self.netns)
        ip("link", "set", self.device, "netns", self.netns)
        ip("-n", self.netns, "link", "set", "lo", "up")
        ip("-n", self.netns, "addr", "add", "10.77.1.2/32", "dev", self.device)
        ip("-n", self.netns, "link", "set", self.device, "mtu", "1280", "up")
        ip("-n", self.netns, "route", "add", "default", "dev", self.device)

        self.log.info("a program there reaches the internet by its plain address")
        for _ in range(4):
            assert_equal(self.in_netns("get", host, self.http_port, "/small"), b"hello from the internet\n")
        info = self.visitor()["interface"]
        self.log.info("  %s", info)
        assert info["packets_out"] > 0 and info["packets_in"] > 0
        opened = sum(self.nodes[n].getgatewayinfo()["opened"] for n in (5, 6))
        assert opened >= 4, opened

        self.log.info("a port no gateway carries is refused at once")
        assert_equal(self.in_netns("get", host, 9, "/"), b"REFUSED\n")
        assert self.visitor()["interface"]["refused"] >= 1

        self.log.info("names: a .bps name is never sent out; others are looked up at a gateway")
        before = self.visitor()["lookups"]
        rcode, answers = self.in_netns("dns", "pilot.bps", 1).split()
        assert_equal((int(rcode), int(answers)), (3, 0))
        assert_equal(self.visitor()["lookups"], before)
        assert_equal(self.visitor()["interface"]["kept_local"], 1)
        rcode, answers = self.in_netns("dns", "nothing.invalid", 1).split()
        assert int(rcode) in (2, 3), rcode
        assert_equal(self.visitor()["lookups"], before + 1)
        # Types other than addresses have no records here.
        rcode, answers = self.in_netns("dns", "example.com", 65).split()
        assert_equal((int(rcode), int(answers)), (0, 0))


if __name__ == '__main__':
    GatewayInterfaceTest().main()
