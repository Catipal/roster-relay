#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a node's own transactions leaving through a path (design note §8·7, stage 1).

Seven nodes. Nodes 0 to 5 are relays listed with an endpoint. Node 6 is a user
with coins, listed nowhere.

What the test is about:

  * the user's own transaction reaches the network with the user's
    peer-to-peer networking switched off: only a path carried it;
  * the relay that announced it is not one of the user's entry relays, which
    see where the user is;
  * the relay counts it as announced for another, and the user as taken.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
)

RELAYS = 6
USER = 6


class TxPathTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 7
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0", "-gateway=0"]
        self.extra_args = [list(common) for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def run_test(self):
        payer = self.nodes[0]
        user = self.nodes[USER]
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list six relays with endpoints; give the user coins")
        for n in range(RELAYS):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            payer.publishrecord(record["hex"])
        payer.sendtoaddress(user.getnewaddress("", "legacy"), 10)
        payer.generatetoaddress(1, payer.getnewaddress())
        self.sync_all()
        tip = payer.getblockcount()
        for n in self.nodes:
            self.wait_until(lambda: n.getrosterinfo()["best_block_height"] == tip, timeout=60)
        assert_equal(user.getbalance(), 10)
        assert_equal(user.gettxpathinfo()["enabled"], True)

        self.log.info("the listings' part of the chain's growth is counted (design note section 4)")
        growth = payer.getrostergrowth(10)
        assert_equal(growth["roster_transactions"], RELAYS)
        assert_equal(growth["live_peers"], RELAYS)
        assert 0 < growth["share"] < 1, growth
        assert growth["roster_bytes"] < growth["chain_bytes"]
        assert_equal(growth["blocks"], 10)

        self.log.info("the user switches its peer-to-peer networking off and pays")
        user.setnetworkactive(False)
        self.wait_until(lambda: user.getconnectioncount() == 0, timeout=30)
        txid = user.sendtoaddress(payer.getnewaddress(), 1)
        assert txid in user.getrawmempool()

        self.log.info("the payment reaches the network all the same: a path carried it")
        self.wait_until(lambda: txid in payer.getrawmempool(), timeout=120)
        self.wait_until(lambda: user.gettxpathinfo()["through_path"] == 1, timeout=60)
        assert_equal(user.gettxpathinfo()["over_p2p"], 0)

        self.log.info("announced by one relay, which is not one of the user's entry relays")
        announced = [n for n in range(RELAYS) if self.nodes[n].gettxpathinfo()["for_others"] == 1]
        assert_equal(len(announced), 1)
        guards = user.getoverlayinfo()["guards"]
        assert self.key(announced[0]) not in guards, (announced, guards)

        self.log.info("it confirms like any other")
        payer.generatetoaddress(1, payer.getnewaddress())
        user.setnetworkactive(True)
        for n in range(RELAYS):
            self.connect_nodes(USER, n)
        self.sync_all()
        assert_equal(user.gettransaction(txid)["confirmations"], 1)


if __name__ == '__main__':
    TxPathTest().main()
