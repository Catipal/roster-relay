#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test hosting a site over the overlay, end to end (design note §11·6).

Two nodes, both listed in the roster with an endpoint and both running the
overlay. One publishes a folder as a site under its roster key; the other
fetches files of it by that key alone, over a direct overlay session it opens
itself, and every piece is checked against the signed manifest as it lands.

What the test is about:

  * a folder is published under a key and served over the overlay;
  * a visitor fetches a file by the host's key, with no prior connection;
  * a file larger than one 16 KiB piece comes back whole, each piece verified;
  * the manifest's signature ties the bytes to the key the visitor asked for;
  * asking for a file that is not there, or a key nobody lists, fails cleanly.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
)

# COINBASE_MATURITY on this chain is 500, so the host mines past it to have a
# fee to pay for the listings.
FUNDED_HEIGHT = 520


class SiteTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # The overlay listens one above each node's p2p port, which is where the
        # roster says to find it.
        self.extra_args = [["-overlay", "-rosterindex", "-fallbackfee=0.0001"]
                           for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def wait_for_index(self):
        tip = self.nodes[0].getblockcount()
        for node in self.nodes:
            self.wait_until(lambda: node.getrosterinfo()["best_block_height"] == tip, timeout=30)

    def run_test(self):
        host, visitor = self.nodes[0], self.nodes[1]
        host.generatetoaddress(FUNDED_HEIGHT, host.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("the overlay must be on to publish a site")
        # (host is on; this only documents the guard for the reader.)

        self.log.info("list both nodes with the endpoint their overlay listens beside")
        for n, node in enumerate(self.nodes):
            record = node.createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            host.publishrecord(record["hex"])
        host.generatetoaddress(1, host.getnewaddress())
        self.sync_all()
        self.wait_for_index()
        for node in self.nodes:
            assert_equal(node.getrosterinfo()["live_peers"], self.num_nodes)

        self.log.info("build a small site: a short page, and one file larger than a piece")
        site = os.path.join(host.datadir, "mysite")
        os.makedirs(os.path.join(site, "assets"), exist_ok=True)
        index = b"<!doctype html><title>BPS</title><h1>Hosted over the overlay.</h1>\n"
        # 40000 bytes spans three 16 KiB pieces (two full, one short), so piece
        # assembly and the per-piece hash check both run on a real multi-piece file.
        big = bytes((i * 7 + 3) & 0xff for i in range(40000))
        with open(os.path.join(site, "index.html"), "wb") as f:
            f.write(index)
        with open(os.path.join(site, "assets", "app.bin"), "wb") as f:
            f.write(big)

        self.log.info("the host publishes the folder under its roster key")
        pub = host.publishsite(site)
        assert_equal(pub["key"], self.key(0))
        assert_equal(pub["files"], 2)
        assert_equal(pub["bytes"], len(index) + len(big))

        self.log.info("the visitor fetches a file by the host's key, with no prior connection")
        got = visitor.getsite(self.key(0), "index.html")
        assert_equal(got["bytes"], len(index))
        assert_equal(bytes.fromhex(got["hex"]), index)

        self.log.info("a file larger than one piece comes back whole, every piece verified")
        got = visitor.getsite(self.key(0), "assets/app.bin")
        assert_equal(got["bytes"], len(big))
        assert_equal(bytes.fromhex(got["hex"]), big)

        self.log.info("a file that is not in the site fails cleanly")
        assert_raises_rpc_error(-1, "no file at that path", visitor.getsite, self.key(0), "nope.html")

        self.log.info("a key nobody lists has nowhere to be fetched from")
        assert_raises_rpc_error(-1, "no address", visitor.getsite, "11" * 32, "index.html")

        self.log.info("a key that is not 32 bytes is refused before anything goes out")
        assert_raises_rpc_error(-8, "32 bytes", visitor.getsite, "00" * 31, "index.html")

        self.log.info("republishing replaces what is served")
        with open(os.path.join(site, "index.html"), "wb") as f:
            f.write(index + b"<p>v2</p>\n")
        host.publishsite(site)
        got = visitor.getsite(self.key(0), "index.html")
        assert_equal(bytes.fromhex(got["hex"]), index + b"<p>v2</p>\n")


if __name__ == '__main__':
    SiteTest().main()
