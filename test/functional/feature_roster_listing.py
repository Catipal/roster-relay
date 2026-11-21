#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a peer with no coins getting listed by a relay that pays for it.

Design note 001 section 8 settles that the user signs its own listing and a
relay pays. How the listing then reaches a block was settled on 2026-09-07: a
record is larger than the 83 bytes a 0.21 node will relay, so until most
nodes upgrade a listing confirms only through a staker that runs this
version - and a relay is a staking node by construction. The listing it pays
for sits in its own mempool and goes into the next block it stakes.

Since 2026-10-18 the request goes through a path. A node that is not a relay
shows the relays it connects to a key made for each connection, so the relay
it enters through sees its address and not who it is; the path proves its
roster key to the relay asked, and to nobody on the way. So the relay asked is
never one of the node's entry relays, which would learn both.

Seven nodes, the first six listed relays with addresses:

  0-2  relays that pay for listings (-acceptlistings), with coins, staking
  3-5  relays that accept listings but are not staking
  6    a user with an empty wallet, listed nowhere

What the test is about:

  * the user shows its relays a throwaway key, and the relays their own;
  * naming one of the user's entry relays is refused, and one is never chosen,
    nor asked directly while another relay could be;
  * a relay that is not staking will not pay, since nothing would get the
    listing into a block;
  * the user is listed without spending anything, in a block the relay staked
    itself, and becomes one of the relay's users;
  * a relay pays once - a second request while the listing is fresh is
    refused rather than paid again;
  * a relay that has not opted in says so, even after restarting.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
)

# Regtest ships nLastPOWBlock = INT_MAX, so proof-of-stake is rejected at every
# height unless it is lowered - and every node has to agree on it. The chain
# is mined to this height, which also clears COINBASE_MATURITY (500).
LAST_POW_BLOCK = 620
PAYERS = 3
USER = 6


class RosterListingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = USER + 1
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        self.common = ["-overlay", "-rosterindex", "-lastpowblock=%d" % LAST_POW_BLOCK, "-fallbackfee=0.0001",
                       "-mailpoll=0", "-mail=0"]
        self.extra_args = ([self.common + ["-acceptlistings", "-staking=1"] for _ in range(PAYERS)] +
                           [self.common + ["-acceptlistings", "-staking=0"] for _ in range(PAYERS, USER)] +
                           [self.common + ["-staking=0"]])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def ask(self, n):
        return self.nodes[USER].requestlisting({}, {"key": self.key(n)})

    def run_test(self):
        user = self.nodes[USER]

        self.log.info("give each paying relay coins old enough to stake by the last proof-of-work block")
        for n in range(PAYERS):
            self.nodes[n].generatetoaddress(30, self.nodes[n].getnewaddress("", "legacy"))
            self.sync_all()
        # Coins pay fees once 500 blocks deep, so the records go out near the
        # end of proof of work.
        self.nodes[0].generatetoaddress(LAST_POW_BLOCK - 20 - self.nodes[0].getblockcount(), self.nodes[0].getnewaddress())
        self.sync_all()
        assert_equal(user.getbalance(), 0)
        user_key = self.key(USER)

        self.log.info("list six relays with their addresses; the user not at all")
        for n in range(USER):
            record = self.nodes[n].createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            self.nodes[0].publishrecord(record["hex"])
        self.nodes[0].generatetoaddress(LAST_POW_BLOCK - self.nodes[0].getblockcount(), self.nodes[0].getnewaddress())
        self.sync_all()
        listed = [e["key"] for e in user.getroster(0)]
        assert all(self.key(n) in listed for n in range(USER))
        assert user_key not in listed

        self.log.info("the user shows its relays a key made for each connection; relays show their own")
        assert_equal(user.getoverlayinfo()["hop_keys"], "throwaway")
        for n in range(USER):
            self.wait_until(lambda: self.nodes[n].getoverlayinfo()["hop_keys"] == "roster", timeout=90)

        self.log.info("the user's entry relays see where it is, so they are never asked")
        # Entry relays are drawn the first time a path needs one; asking a
        # relay nobody lists draws them and reaches nothing.
        # The curve's generator: a valid key nobody lists.
        nowhere = user.requestlisting({}, {"key": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"})
        assert_equal(nowhere["status"], "unanswered")
        guards = user.getoverlayinfo()["guards"]
        assert_equal(len(guards), 2)
        assert_raises_rpc_error(-8, "entry relays", user.requestlisting, {}, {"key": guards[0]})
        # Asking one directly is only for a roster with no other relay.
        assert_raises_rpc_error(-8, "Another relay can be asked", user.requestlisting, {},
                                {"key": guards[0], "entry": True})
        payers = [n for n in range(PAYERS) if self.key(n) not in guards]
        idle = [n for n in range(PAYERS, USER) if self.key(n) not in guards]
        assert payers and idle

        self.log.info("a relay that is not staking will not pay, and answers through the path")
        no_stake = self.ask(idle[0])
        self.log.info("  %s", no_stake)
        assert_equal(no_stake["status"], "refused")
        assert "not staking" in no_stake["reason"], no_stake["reason"]
        assert "relay_address" not in no_stake

        self.log.info("wait for the paying relays to stake")
        for n in range(PAYERS):
            self.wait_until(lambda: self.nodes[n].getstakinginfo()["staking"], timeout=300)

        self.log.info("the user asks a paying relay to publish its listing")
        payer = payers[0]
        res = self.ask(payer)
        if res["status"] != "published":
            # A relay whose staking needed a longer window than the one retry
            # allows: ask again.
            res = self.ask(payer)
        self.log.info("  %s", res)
        assert_equal(res["status"], "published")
        assert_equal(res["key"], user_key)
        assert_equal(res["relay"], self.key(payer))
        txid = res["txid"]
        assert txid in self.nodes[payer].getrawmempool()

        self.log.info("it is the relay's coins that paid")
        assert_equal(user.getbalance(), 0)
        assert self.nodes[payer].gettransaction(txid)["fee"] < 0

        self.log.info("and the relay confirms it in a block it stakes itself")
        self.wait_until(lambda: self.nodes[payer].gettransaction(txid)["confirmations"] >= 1, timeout=600)
        block = self.nodes[payer].getblock(self.nodes[payer].gettransaction(txid)["blockhash"])
        assert_equal(block["flags"], "proof-of-stake")
        self.log.info("  confirmed in proof-of-stake block %d", block["height"])

        self.log.info("the user is now in the roster, with no address, and one of the relay's users")
        self.sync_all()
        entry = [e for e in user.getroster(0) if e["key"] == user_key][0]
        assert_equal(entry["endpoints"], [])
        assert entry["meeting_point"] not in guards
        assert_equal(self.nodes[payer].getrelaypayout()["users"], 1)

        self.log.info("a second request while the listing is fresh is not paid")
        again = self.ask(payer)
        assert_equal(again["status"], "refused")
        assert "listed until block" in again["reason"], again["reason"]

        self.log.info("asked with no relay named, a relay that is not an entry relay answers")
        anyone = user.requestlisting()
        assert anyone["relay"] not in guards
        assert anyone["relay"] != user_key

        self.log.info("a relay that has not opted in says so, even after restarting")
        quiet = idle[0]
        self.restart_node(quiet, self.common + ["-staking=0"])
        for n in range(USER + 1):
            if n != quiet:
                self.connect_nodes(quiet, n)
        self.wait_until(lambda: self.nodes[quiet].getoverlayinfo()["hop_keys"] == "roster", timeout=90)
        no = self.ask(quiet)
        if no["status"] == "unanswered":
            # The path's relays may still hold sessions from before the restart.
            no = self.ask(quiet)
        assert_equal(no["status"], "refused")
        assert "does not pay for listings" in no["reason"], no["reason"]


if __name__ == '__main__':
    RosterListingTest().main()
