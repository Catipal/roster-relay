#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test relays reached at an address other than the one their routes answer from.

The overlay listens on every address of a computer. A relay listed at one of
several addresses must answer each peer from the address that peer wrote to:
from any other, the peer has never written there and drops the answer, and
its handshake never completes. Found 2026-10-17 by feature_gateway_routes.py.

Here every relay is listed at 127.0.0.2. On Linux and Windows the whole of
127.0.0.0/8 is this computer, but the route back to a peer at 127.0.0.1 names
127.0.0.1 as the source, so without answering from the address written to,
no handshake with any relay would complete.

Seven nodes, as in feature_meeting.py: six relays and node 6, listed with no
address and -meetable. Node 6 registers at its meeting points through a relay
of its own, and visitors meet it through one relay and through three - every
hop a relay written to at 127.0.0.2.
"""

import sys

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

EPOCH = 480
SECOND = "127.0.0.2"


class OverlaySecondAddressTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 7
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0"]
        self.extra_args = [list(common) for _ in range(6)] + [common + ["-meetable"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if sys.platform == "darwin":
            raise SkipTest("macOS sets up only 127.0.0.1 on its loopback")

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
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list six relays at %s, and node 6 with no address", SECOND)
        for n in range(6):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": SECOND, "port": p2p_port(n)}]})
            payer.publishrecord(record["hex"])
        payer.publishrecord(self.nodes[6].createannouncement({})["hex"])
        payer.generatetoaddress(1, payer.getnewaddress())
        self.sync_all()
        self.mine_to(2 * EPOCH + 10)

        self.log.info("node 6 registers at its points through a relay written to at %s", SECOND)
        self.wait_until(lambda: len(self.nodes[6].getmeetinginfo()["registrations"]) == 3, timeout=180)

        self.log.info("visitors meet it through one relay and through three")
        met = self.nodes[1].meet(self.key(6))
        assert_equal(met["hops"], 1)
        met = self.nodes[2].meet(self.key(6), 3)
        assert_equal(met["hops"], 3)


if __name__ == '__main__':
    OverlaySecondAddressTest().main()
