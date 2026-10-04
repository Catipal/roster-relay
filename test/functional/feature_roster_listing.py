#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a peer with no coins getting listed by a relay that pays for it.

Design note 001 section 8 settles that the user signs its own listing and the
relay it uses pays. This is the delivery: the signed record travels over the
overlay session the user has with the relay, and the relay publishes it.

Three nodes:

  0  a relay that pays for listings (-acceptlistings) and has coins
  1  a user with an empty wallet
  2  a relay that does not pay for listings

What the test is really about:

  * the user is listed without spending anything, and becomes one of the
    relay's users, so the relay's reward sharing reaches it;

  * a relay pays once - a second request while the listing is fresh is
    refused rather than paid again;

  * a relay that has not opted in says so instead of spending;

  * the user cannot be fooled into handing its record to a different key
    than the one it meant to ask: a relay is reached by key, not by address.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
)


class RosterListingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def setup_nodes(self):
        # Ports are known only once the framework has seeded them. The overlay
        # is UDP, so it can share each node's p2p port number without
        # colliding with the TCP listener on it.
        self.extra_args = [
            ["-overlay", "-overlayport=%d" % p2p_port(0), "-acceptlistings", "-rosterindex", "-fallbackfee=0.0001"],
            ["-overlay", "-overlayport=%d" % p2p_port(1), "-rosterindex"],
            ["-overlay", "-overlayport=%d" % p2p_port(2), "-rosterindex"],
        ]
        super().setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def relay(self, n):
        return {"key": self.nodes[n].getrosterinfo()["operational_key"],
                "address": "127.0.0.1:%d" % p2p_port(n)}

    def run_test(self):
        relay, user, other = self.nodes

        self.log.info("fund the relay; the user stays empty")
        funds = relay.getnewaddress()
        relay.generatetoaddress(510, funds)  # past COINBASE_MATURITY
        self.sync_all()
        assert_equal(user.getbalance(), 0)

        user_key = user.getrosterinfo()["operational_key"]
        assert_equal(relay.getrelaypayout()["users"], 0)

        self.log.info("the user asks the relay to publish its listing")
        res = user.requestlisting({}, self.relay(0))
        self.log.info("  %s", res)
        assert_equal(res["status"], "published")
        assert_equal(res["key"], user_key)
        assert_equal(res["relay"], self.relay(0)["key"])
        txid = res["txid"]
        assert txid in relay.getrawmempool()

        self.log.info("it is the relay's coins that paid")
        assert_equal(user.getbalance(), 0)
        assert relay.gettransaction(txid)["fee"] < 0

        self.log.info("once mined, the user is in the roster")
        relay.generatetoaddress(1, funds)
        self.sync_all()
        listed = [e["key"] for e in user.getroster(0)]
        assert user_key in listed

        self.log.info("and is now one of the relay's users")
        assert_equal(relay.getrelaypayout()["users"], 1)

        self.log.info("a second request while the listing is fresh is not paid")
        again = user.requestlisting({}, self.relay(0))
        assert_equal(again["status"], "refused")
        assert "listed until block" in again["reason"], again["reason"]
        assert_equal(relay.getrawmempool(), [])

        self.log.info("a relay that has not opted in says so")
        no = user.requestlisting({}, self.relay(2))
        assert_equal(no["status"], "refused")
        assert "does not pay for listings" in no["reason"], no["reason"]

        self.log.info("a relay is reached by key: another key at its address gets nothing")
        wrong = {"key": self.relay(0)["key"], "address": self.relay(2)["address"]}
        lost = user.requestlisting({}, wrong)
        assert_equal(lost["status"], "unanswered")
        assert_equal(other.getrawmempool(), [])
        assert_equal(relay.getrawmempool(), [])


if __name__ == '__main__':
    RosterListingTest().main()
