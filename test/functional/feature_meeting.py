#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test meeting a node that publishes no address (-meetable, design note §8·7, §11·6).

Seven nodes. Nodes 0 to 5 are relays listed with an endpoint. Node 6 is listed
with no endpoint at all and runs with -meetable: it keeps itself registered at
its meeting points, through a relay of its own.

What the test is really about:

  * the meeting points are computed, not looked up: the relays node 6 registers
    at are exactly the ones anyone derives from its key and the roster at the
    epoch's anchor, and they are the relays holding its registration;

  * a visitor reaches node 6 by its key alone, through a relay of its own and
    one of those points, and gets an answer across the meeting - with one relay
    on its side, and with three;

  * a key with no registration cannot be met, and says so;

  * near the end of an epoch node 6 registers at the next epoch's points too,
    and a while into the new epoch it lets the old ones go.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, p2p_port

EPOCH = 480
ANCHOR_DEPTH = 6
OVERLAP = 30


class MeetingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 7
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0"]
        self.extra_args = [list(common) for _ in range(6)] + [common + ["-meetable"]]

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

    def registered(self):
        return sorted(r["point"] for r in self.nodes[6].getmeetinginfo()["registrations"])

    def holders(self):
        return sorted(self.key(n) for n in range(6) if self.nodes[n].getmeetinginfo()["held"] > 0)

    def run_test(self):
        payer = self.nodes[0]
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list six relays with endpoints, and node 6 with none")
        for n in range(6):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            payer.publishrecord(record["hex"])
        record = self.nodes[6].createannouncement({})
        payer.publishrecord(record["hex"])
        payer.generatetoaddress(1, payer.getnewaddress())
        self.sync_all()

        self.log.info("until an epoch's anchor lists them, there is nowhere to meet")
        info = self.nodes[6].getmeetinginfo()
        assert_equal(info["meetable"], True)
        assert_equal(info["hops"], 1)
        assert_equal(info["registrations"], [])

        self.log.info("into the next epoch, whose anchor lists every relay")
        self.mine_to(2 * EPOCH + 10)
        self.wait_until(lambda: len(self.registered()) == 3, timeout=180)
        reg = self.nodes[6].getmeetinginfo()["registrations"]
        for r in reg:
            assert_equal(r["epochs"], [2])
            # One relay of its own in front of it, never the point itself.
            assert_equal(len(r["through"]), 1)
            assert r["through"][0] != r["point"]

        self.log.info("the points are the ones anyone computes, and they hold the registration")
        expected = sorted(self.nodes[6].getoverlayinfo()["rendezvous"])
        assert_equal(self.registered(), expected)
        self.wait_until(lambda: self.holders() == expected, timeout=60)
        assert self.key(6) not in expected

        self.log.info("a visitor meets node 6 by its key alone, through one relay of its own")
        met = self.nodes[1].meet(self.key(6))
        self.log.info("  %s", met)
        assert met["point"] in expected
        assert_equal(met["epoch"], 2)
        assert_equal(met["hops"], 1)

        self.log.info("and through three")
        met = self.nodes[2].meet(self.key(6), 3)
        assert_equal(met["hops"], 3)
        assert met["point"] in expected

        self.log.info("a key with no registration cannot be met")
        assert_raises_rpc_error(-1, "Could not meet it", self.nodes[1].meet, self.key(5))

        self.log.info("from the next epoch's anchor, its points too")
        self.mine_to(3 * EPOCH - ANCHOR_DEPTH)
        def for_epoch(e):
            return [r for r in self.nodes[6].getmeetinginfo()["registrations"] if e in r["epochs"]]
        self.wait_until(lambda: len(for_epoch(3)) == 3 and len(for_epoch(2)) == 3, timeout=180)
        assert all(set(r["epochs"]) <= {2, 3} for r in self.nodes[6].getmeetinginfo()["registrations"])

        self.log.info("a while into the new epoch, the old points are let go")
        self.mine_to(3 * EPOCH + OVERLAP)
        self.wait_until(lambda: all(r["epochs"] == [3] for r in self.nodes[6].getmeetinginfo()["registrations"]) and
                        len(self.registered()) == 3, timeout=180)
        new_points = sorted(self.nodes[6].getoverlayinfo()["rendezvous"])
        assert_equal(self.registered(), new_points)
        met = self.nodes[3].meet(self.key(6))
        assert met["point"] in new_points
        assert_equal(met["epoch"], 3)


if __name__ == '__main__':
    MeetingTest().main()
