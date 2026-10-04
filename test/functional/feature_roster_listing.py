#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a peer with no coins getting listed by a relay that pays for it.

Design note 001 section 8 settles that the user signs its own listing and the
relay it uses pays. How the listing then reaches a block was settled on
2026-09-07: a record is larger than the 83 bytes a 0.21 node will relay, so
until most nodes upgrade a listing confirms only through a staker that runs
this version - and a relay is a staking node by construction. The listing it
pays for sits in its own mempool and goes into the next block it stakes.

Three nodes:

  0  a relay that pays for listings (-acceptlistings), has coins and stakes
  1  a user with an empty wallet
  2  a node that accepts listings but is not staking, later restarted
     without -acceptlistings

What the test is really about:

  * the user is listed without spending anything, in a block the relay staked
    itself, and becomes one of the relay's users, so the relay's reward
    sharing reaches it;

  * a relay that is not staking will not pay, since nothing would get the
    listing into a block;

  * a relay pays once - a second request while the listing is fresh is
    refused rather than paid again;

  * a relay that has not opted in says so instead of spending, and is reached
    with a fresh handshake even though it restarted since the last request;

  * the user cannot be fooled into handing its record to a different key
    than the one it meant to ask: a relay is reached by key, not by address.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
)

# Regtest ships nLastPOWBlock = INT_MAX, so proof-of-stake is rejected at every
# height unless it is lowered - and every node has to agree on it. The chain
# is mined to this height, which also clears COINBASE_MATURITY (500).
LAST_POW_BLOCK = 620


class RosterListingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def node_args(self, n, extra):
        # Ports are known only once the framework has seeded them. The overlay
        # is UDP, so it can share each node's p2p port number without
        # colliding with the TCP listener on it.
        return ["-overlay", "-overlayport=%d" % p2p_port(n), "-rosterindex",
                "-lastpowblock=%d" % LAST_POW_BLOCK, "-fallbackfee=0.0001"] + extra

    def setup_nodes(self):
        self.extra_args = [
            self.node_args(0, ["-acceptlistings", "-staking=1"]),
            self.node_args(1, ["-staking=0"]),
            self.node_args(2, ["-acceptlistings", "-staking=0"]),
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
        funds = relay.getnewaddress("", "legacy")  # a coinstake kernel must be P2PK or P2PKH
        relay.generatetoaddress(LAST_POW_BLOCK, funds)
        self.sync_all()
        assert_equal(user.getbalance(), 0)
        user_key = user.getrosterinfo()["operational_key"]
        assert_equal(relay.getrelaypayout()["users"], 0)

        self.log.info("a relay that is not staking will not pay")
        no_stake = user.requestlisting({}, self.relay(2))
        assert_equal(no_stake["status"], "refused")
        assert "not staking" in no_stake["reason"], no_stake["reason"]

        self.log.info("wait for the relay's staker to start")
        self.wait_until(lambda: relay.getstakinginfo()["staking"], timeout=300)

        self.log.info("the user asks the relay to publish its listing")
        self.sync_all()
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

        self.log.info("and the relay confirms it in a block it stakes itself")
        self.wait_until(lambda: relay.gettransaction(txid)["confirmations"] >= 1, timeout=600)
        block = relay.getblock(relay.gettransaction(txid)["blockhash"])
        assert_equal(block["flags"], "proof-of-stake")
        self.log.info("  confirmed in proof-of-stake block %d", block["height"])

        self.log.info("the user is now in the roster, and one of the relay's users")
        self.sync_all()
        listed = [e["key"] for e in user.getroster(0)]
        assert user_key in listed
        assert_equal(relay.getrelaypayout()["users"], 1)

        self.log.info("a second request while the listing is fresh is not paid")
        again = user.requestlisting({}, self.relay(0))
        assert_equal(again["status"], "refused")
        assert "listed until block" in again["reason"], again["reason"]

        self.log.info("a relay is reached by key: another key at its address gets nothing")
        wrong = {"key": self.relay(0)["key"], "address": self.relay(2)["address"]}
        lost = user.requestlisting({}, wrong)
        assert_equal(lost["status"], "unanswered")
        assert_equal(other.getrawmempool(), [])

        self.log.info("a relay that has not opted in says so, even after restarting")
        self.restart_node(2, self.node_args(2, ["-staking=0"]))
        self.connect_nodes(1, 2)
        no = user.requestlisting({}, self.relay(2))
        assert_equal(no["status"], "refused")
        assert "does not pay for listings" in no["reason"], no["reason"]


if __name__ == '__main__':
    RosterListingTest().main()
