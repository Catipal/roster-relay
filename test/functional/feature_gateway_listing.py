#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a relay getting its gateway key listed without saying where it is.

A relay's own listing carries its address, so it serves as a gateway under a
second key listed with none (design note 001 section 8.7). Paying for that
listing from the relay's own wallet would tie the two together on the chain -
its coins paid for the relay's own listing too - and so say where the gateway
is. Asking a relay directly would tell that relay. So the listing is asked for
through a path whose session proves the gateway key and nothing else, from a
relay that is not one of the asker's entry relays, and that relay pays.

Five nodes, all listed relays with addresses:

  0-3  relays that pay for listings (-acceptlistings), with coins, staking
  4    a relay that lists its gateway key

What the test is about:

  * the gateway key is listed with the gateway bit and no address, paid for
    by another relay, in a block staked by this version;

  * the relay asked is never one of the asker's entry relays, which know
    where it is, and naming one is refused;

  * the relay that paid counts the gateway key among its users, as for any
    listing it pays for.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
)

# As in feature_roster_listing.py: regtest needs proof of stake switched on,
# at a height every node agrees on.
LAST_POW_BLOCK = 620
PAYERS = 4


class GatewayListingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = PAYERS + 1
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        common = ["-overlay", "-rosterindex", "-lastpowblock=%d" % LAST_POW_BLOCK, "-fallbackfee=0.0001",
                  "-mailpoll=0", "-mail=0"]
        self.extra_args = [common + ["-acceptlistings", "-staking=1"] for _ in range(PAYERS)] + [
            common + ["-staking=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def run_test(self):
        asker = self.nodes[PAYERS]

        self.log.info("give each paying relay coins old enough to stake by the last proof-of-work block")
        for n in range(PAYERS):
            self.nodes[n].generatetoaddress(30, self.nodes[n].getnewaddress("", "legacy"))
            self.sync_all()

        # Coins pay fees once 500 blocks deep, so the records go out near the
        # end of proof of work.
        self.nodes[0].generatetoaddress(LAST_POW_BLOCK - 20 - self.nodes[0].getblockcount(), self.nodes[0].getnewaddress())
        self.sync_all()

        self.log.info("list all five relays with their addresses")
        for n in range(self.num_nodes):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            self.nodes[0].publishrecord(record["hex"])
        self.nodes[0].generatetoaddress(LAST_POW_BLOCK - self.nodes[0].getblockcount(), self.nodes[0].getnewaddress())
        self.sync_all()
        listed = {e["key"]: e for e in asker.getroster(0)}
        assert all(self.key(n) in listed for n in range(self.num_nodes))

        self.log.info("wait for the paying relays to stake")
        for n in range(PAYERS):
            self.wait_until(lambda: self.nodes[n].getstakinginfo()["staking"], timeout=300)

        gateway_key = asker.createannouncement({"key": "gateway"})["key"]
        assert gateway_key != self.key(PAYERS)

        self.log.info("the asker's entry relays know where it is, so naming one is refused")
        # Entry relays are chosen when the first path is built; asking without
        # naming anyone builds one.
        res = asker.requestlisting({"key": "gateway"})
        self.log.info("  %s", res)
        guards = asker.getoverlayinfo()["guards"]
        assert len(guards) >= 1
        assert_raises_rpc_error(-8, "entry relays", asker.requestlisting, {"key": "gateway"}, {"key": guards[0]})

        self.log.info("another relay pays for the gateway's listing, asked through a path")
        if res["status"] != "published":
            # A relay that had just paid for something else, or whose staking
            # needed a longer window than the one retry allows: ask again.
            res = asker.requestlisting({"key": "gateway"})
            self.log.info("  %s", res)
        assert_equal(res["status"], "published")
        assert_equal(res["key"], gateway_key)
        assert "relay_address" not in res
        assert res["relay"] not in guards
        assert res["relay"] != self.key(PAYERS)
        payer = [n for n in range(PAYERS) if self.key(n) == res["relay"]][0]
        self.log.info("  paid for by node %d", payer)
        assert self.nodes[payer].gettransaction(res["txid"])["fee"] < 0

        self.log.info("it confirms in a staked block, with the gateway bit and no address")
        self.wait_until(lambda: self.nodes[payer].gettransaction(res["txid"])["confirmations"] >= 1, timeout=600)
        block = self.nodes[payer].getblock(self.nodes[payer].gettransaction(res["txid"])["blockhash"])
        assert_equal(block["flags"], "proof-of-stake")
        self.sync_all()
        roster = {e["key"]: e for e in asker.getroster(0)}
        assert_equal(roster[gateway_key]["gateway"], True)
        assert_equal(roster[gateway_key]["endpoints"], [])
        assert_equal(roster[self.key(PAYERS)]["gateway"], False)
        assert_equal(len(roster[self.key(PAYERS)]["endpoints"]), 1)

        self.log.info("and the relay that paid counts the gateway among its users")
        assert_equal(self.nodes[payer].getrelaypayout()["users"], 1)

        self.log.info("over a path, a relay pays for nothing but a gateway's listing")
        # The asker's own key, asked for the same way, would be refused; the
        # RPC only ever sends a gateway record through a path, so this is the
        # relay's rule (rosterlisting_tests), and here the second request is a
        # renewal asked for too early.
        again = asker.requestlisting({"key": "gateway"}, {"key": res["relay"]})
        assert_equal(again["status"], "refused")
        assert "listed until block" in again["reason"], again["reason"]


if __name__ == '__main__':
    GatewayListingTest().main()
