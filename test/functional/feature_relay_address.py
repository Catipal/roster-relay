#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test relays that announce their address instead of writing it to the chain.

A relay listed with the "relay" option carries no endpoint: the chain says
it is a relay, and the relay says where it is in short announcements signed
with its key, which peers pass on and which count for three hours
(roster/relayaddr.h). So no relay's address is on the chain, and one can
change without a transaction.

Seven nodes, as in feature_meeting.py: six relays listed with no address and
announcing 127.0.0.1 (-relayaddress), and node 6, listed with no address and
-meetable.

 - every node learns every relay's address, though no record carries one;
 - node 6 registers at its meeting points, and visitors meet it through one
   relay and through three: every hop dialled at an announced address;
 - relay 2 comes back at 127.0.0.2 and on another port, minutes after its
   last announcement: every node has the new address with no block mined,
   and paths run through it there - where nothing listens at the old one,
   so any path through it was dialled at the announced address.
"""

import sys

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

EPOCH = 480
MOVED = "127.0.0.2"


class RelayAddressTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 7
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        self.common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0", "-debug=net"]
        self.extra_args = [self.common + ["-relay", "-relayaddress=127.0.0.1"] for _ in range(6)] + [self.common + ["-meetable"]]

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

    def announced(self, node, n):
        """Where `node` holds relay n to be, or None."""
        for entry in self.nodes[node].getroster(0):
            if entry["key"] == self.keys[n]:
                return entry.get("announced")
        return None

    def run_test(self):
        self.keys = [self.key(n) for n in range(7)]
        payer = self.nodes[0]
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list six relays with no address, announcing it instead, and node 6 with none")
        for n in range(6):
            record = self.nodes[n].createannouncement({"relay": True})
            assert "warnings" not in record
            payer.publishrecord(record["hex"])
        payer.publishrecord(self.nodes[6].createannouncement({})["hex"])
        payer.generatetoaddress(1, payer.getnewaddress())
        self.sync_all()

        self.log.info("every node learns where every relay is, from the relays, not the chain")
        for node in self.nodes:
            self.wait_until(lambda: node.getrosterinfo()["relay_addresses"] == 6, timeout=120)
        for entry in self.nodes[6].getroster(0):
            assert_equal(entry["endpoints"], [])
            assert_equal(entry["dialable"], False)
        for n in range(6):
            here = self.announced(6, n)
            assert_equal(here["endpoints"], [{"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}])
            assert here["age_seconds"] < 600
            assert_equal(self.nodes[n].getrosterinfo()["announcing"]["endpoints"], here["endpoints"])
        assert "announcing" not in self.nodes[6].getrosterinfo()

        self.mine_to(2 * EPOCH + 10)
        self.log.info("node 6 registers at its points through relays it found by their announcements")
        self.wait_until(lambda: len(self.nodes[6].getmeetinginfo()["registrations"]) == 3, timeout=180)
        self.log.info("visitors meet it through one relay and through three")
        assert_equal(self.nodes[1].meet(self.keys[6])["hops"], 1)
        assert_equal(self.nodes[2].meet(self.keys[6], 3)["hops"], 3)

        self.log.info("relay 2 moves to %s and another port: everyone has it with no block mined", MOVED)
        height = payer.getblockcount()
        # A port slot no node of this test uses, for TCP and, one above, UDP.
        port = p2p_port(8)
        self.restart_node(2, self.common + ["-relay", "-relayaddress=" + MOVED, "-port=%d" % port])
        self.connect_nodes(2, 1)
        self.connect_nodes(2, 3)
        moved = [{"network": "ipv4", "address": MOVED, "port": port}]
        for node in range(7):
            self.wait_until(lambda: (self.announced(node, 2) or {}).get("endpoints") == moved, timeout=120)
        assert_equal(payer.getblockcount(), height)
        # Dated after the one before it, which the network still held.
        assert_equal(self.nodes[2].getrosterinfo()["announcing"]["endpoints"], moved)

        self.log.info("paths run through it at its new address, the only one it answers at")
        # A registration node 6 made through relay 2 before it moved died with
        # it, and node 6 notices at its next refresh (MEET_REFRESH, 4 minutes):
        # until then a visitor may find no answer there. What is tested here is
        # that paths reach relay 2 where it is now.
        def met_through_moved_relay():
            for visitor in (0, 1, 3, 4, 5):
                try:
                    assert_equal(self.nodes[visitor].meet(self.keys[6], 3)["hops"], 3)
                except JSONRPCException as e:
                    self.log.info("  not yet: %s", e.error["message"])
                    return False
            return self.nodes[2].getoverlayinfo()["carried"]["today_bytes"] > 0
        self.wait_until(met_through_moved_relay, timeout=900)

        self.log.info("relaying is a setting of the node: switched off, it announces nothing")
        self.restart_node(5, self.common + ["-relay=0", "-relayaddress=127.0.0.1"])
        info = self.nodes[5].getrosterinfo()
        assert_equal(info["relay"], False)
        assert "announcing" not in info
        assert_equal(self.nodes[4].getrosterinfo()["relay"], True)

if __name__ == '__main__':
    RelayAddressTest().main()
