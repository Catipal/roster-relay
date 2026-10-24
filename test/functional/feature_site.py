#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test hosting sites over the overlay, public and hidden (design note §11·6).

Eight nodes. Nodes 0 to 5 are relays listed with an endpoint; node 0 also
hosts a public site. Node 6 is listed through the overlay, with no address,
and hosts a hidden site: nothing tells it to be met but the site itself, so
it registers at its meeting points only because it publishes one. Node 7 is a
visitor, listed nowhere.

What the test is about:

  * a public site is reached through three relays, so its host never sees the
    visitor; a hidden one is met at one of the points anyone computes from its
    key, so neither sees the other;
  * every file comes back whole, several pieces asked for at once, each
    checked against the signed manifest;
  * a site with no address keeps its host registered while it publishes;
  * a missing file, an unlisted key and a key that is not 32 bytes fail
    cleanly;
  * republishing replaces what is served, and a visitor holding the old
    manifest moves to the new one;
  * a site is published again after a restart, until unpublishsite.
"""

import base64
import http.client
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
)

EPOCH = 480
RELAYS = 6
HIDDEN = 6
VISITOR = 7


def pattern(n, seed):
    return bytes((i * 7 + seed) & 0xff for i in range(n))


class SiteTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 8
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        # No gateway, no -meetable: what registers node 6 is its site alone.
        self.common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0", "-gateway=0"]
        self.extra_args = [list(self.common) for _ in range(self.num_nodes)]

    def setup_network(self):
        # The visitor runs the site proxy for browsers, on a port no node uses
        # (known only once the framework has chosen this run's ports).
        self.proxy_port = p2p_port(self.num_nodes + 3)
        self.extra_args[VISITOR] += ["-siteproxy", "-siteproxyport=%d" % self.proxy_port]
        super().setup_network()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def mine_to(self, height):
        node = self.nodes[0]
        while node.getblockcount() < height:
            node.generatetoaddress(min(200, height - node.getblockcount()), node.getnewaddress())
        self.sync_all()
        for n in self.nodes:
            self.wait_until(lambda: n.getrosterinfo()["best_block_height"] == height, timeout=60)

    def make_site(self, n, name, files):
        site = os.path.join(self.nodes[n].datadir, name)
        for path, data in files.items():
            full = os.path.join(site, *path.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as f:
                f.write(data)
        return site

    def http(self, host, target, method="GET"):
        """One request to the visitor's site proxy, with the Host header given."""
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=120)
        conn.request(method, target, headers={"Host": host})
        r = conn.getresponse()
        body = r.read()
        headers = dict(r.getheaders())
        conn.close()
        return r.status, headers, body

    def fetch(self, n, path):
        got = self.nodes[VISITOR].getsite(self.key(n), path)
        return bytes.fromhex(got["hex"]), got["route"]

    def run_test(self):
        payer = self.nodes[0]
        visitor = self.nodes[VISITOR]
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list six relays with endpoints, node 6 through the overlay, the visitor nowhere")
        for n in range(RELAYS):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            payer.publishrecord(record["hex"])
        payer.publishrecord(self.nodes[HIDDEN].createannouncement({})["hex"])
        # Into an epoch whose anchor lists every relay, so meeting points exist.
        self.mine_to(2 * EPOCH + 10)

        self.log.info("node 0, a relay, publishes a public site")
        index = b"<!doctype html><title>BPS</title><h1>Hosted over the overlay.</h1>\n"
        big = pattern(40000, 3)  # three pieces: two whole and one short
        public = self.make_site(0, "public", {"index.html": index, "assets/app.bin": big})
        pub = payer.publishsite(public)
        assert_equal(pub["key"], self.key(0))
        assert_equal(pub["files"], 2)
        assert_equal(pub["bytes"], len(index) + len(big))
        assert_equal(pub["hidden"], False)

        self.log.info("the visitor fetches it by key, through three relays")
        data, route = self.fetch(0, "index.html")
        assert_equal(data, index)
        assert_equal(route["hidden"], False)
        assert_equal(route["hops"], 3)
        data, _ = self.fetch(0, "assets/app.bin")
        assert_equal(data, big)
        info = payer.gethostinginfo()
        assert_equal(info["publishing"], True)
        assert info["pieces_sent"] >= 4, info

        self.log.info("node 6, listed with no address, publishes a hidden site and is met for it")
        assert_equal(self.nodes[HIDDEN].getmeetinginfo()["meetable"], False)
        page = b"<!doctype html><title>hidden</title><p>Nobody knows where this is.</p>\n"
        photo = pattern(200000, 9)  # thirteen pieces, several asked for at once
        hidden = self.make_site(HIDDEN, "hidden", {"index.html": page, "img/photo.jpg": photo})
        pub = self.nodes[HIDDEN].publishsite(hidden)
        assert_equal(pub["hidden"], True)
        self.wait_until(lambda: self.nodes[HIDDEN].gethostinginfo().get("registrations", 0) == 3, timeout=180)
        points = self.nodes[HIDDEN].getoverlayinfo()["rendezvous"]

        self.log.info("the visitor meets it at one of the points anyone computes from its key")
        data, route = self.fetch(HIDDEN, "index.html")
        assert_equal(data, page)
        assert_equal(route["hidden"], True)
        assert route["point"] in points, (route, points)
        assert route["point"] != self.key(HIDDEN)
        data, _ = self.fetch(HIDDEN, "img/photo.jpg")
        assert_equal(data, photo)
        assert self.nodes[HIDDEN].gethostinginfo()["pieces_sent"] >= 14

        self.log.info("an ordinary browser reads the same site through the visitor's site proxy")
        label = base64.b32encode(bytes.fromhex(self.key(HIDDEN))).decode().lower().rstrip("=")
        address = visitor.getsiteaddress(self.key(HIDDEN))
        assert_equal(address["browser_key"], "http://%s.bps.localhost:%d/" % (label, self.proxy_port))
        host = "%s.bps.localhost:%d" % (label, self.proxy_port)
        status, headers, body = self.http(host, "/")
        assert_equal(status, 200)
        assert_equal(body, page)
        assert_equal(headers["Content-Type"], "text/html; charset=utf-8")
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert_equal(headers["Referrer-Policy"], "no-referrer")
        status, headers, body = self.http(host, "/img/photo.jpg")
        assert_equal((status, body), (200, photo))
        assert_equal(headers["Content-Type"], "image/jpeg")
        status, _, body = self.http(host, "/", method="HEAD")
        assert_equal((status, body), (200, b""))
        assert_equal(self.http(host, "/nope.html")[0], 404)
        self.log.info("as a proxy for .bps names too")
        status, _, body = self.http("%s.bps" % label, "http://%s.bps/" % label)
        assert_equal((status, body), (200, page))
        self.log.info("and nothing but a .bps name on its own port")
        assert_equal(self.http("evil.example:%d" % self.proxy_port, "/")[0], 403)
        assert_equal(self.http("%s.bps.localhost:%d" % (label, self.proxy_port + 1), "/")[0], 403)
        assert_equal(self.http("127.0.0.1:%d" % self.proxy_port, "/")[0], 403)

        self.log.info("a missing file, an unlisted key and a short key fail cleanly")
        assert_raises_rpc_error(-1, "no file at that path", visitor.getsite, self.key(HIDDEN), "nope.html")
        # The curve's generator: a valid key nobody lists.
        assert_raises_rpc_error(-1, "does not list that key", visitor.getsite,
                                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "index.html")
        assert_raises_rpc_error(-8, "32 bytes", visitor.getsite, "00" * 31, "index.html")

        self.log.info("republishing replaces what is served, and the visitor follows")
        with open(os.path.join(hidden, "index.html"), "wb") as f:
            f.write(page + b"<p>v2</p>\n")
        self.nodes[HIDDEN].publishsite(hidden)
        data, _ = self.fetch(HIDDEN, "index.html")
        assert_equal(data, page + b"<p>v2</p>\n")

        self.log.info("the site is published again after a restart")
        self.restart_node(HIDDEN, self.common)
        for n in range(self.num_nodes):
            if n != HIDDEN:
                self.connect_nodes(HIDDEN, n)
        info = self.nodes[HIDDEN].gethostinginfo()
        assert_equal(info["publishing"], True)
        assert_equal(info["files"], 2)
        self.wait_until(lambda: self.nodes[HIDDEN].gethostinginfo().get("registrations", 0) == 3, timeout=180)
        data, _ = self.fetch(HIDDEN, "index.html")
        assert_equal(data, page + b"<p>v2</p>\n")

        self.log.info("until it is unpublished: a visitor is told there is no site, and a restart keeps it so")
        assert_equal(payer.unpublishsite(), True)
        assert_equal(payer.gethostinginfo()["publishing"], False)
        assert_raises_rpc_error(-1, "no site under that key", visitor.getsite, self.key(0), "index.html")
        self.restart_node(0, self.common)
        assert_equal(self.nodes[0].gethostinginfo()["publishing"], False)


if __name__ == '__main__':
    SiteTest().main()
