#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test paying a roster peer by delegating stake to the key it published.

This is the payment path of design note 001 section 8, and the thing it has to
get right is unusual enough to be worth a test of its own: a relay works out
where to pay a peer WITHOUT ASKING IT. It reads 32 bytes off the chain and
derives an address; the peer derives the same address from its own private key;
neither ever speaks to the other about it. If the two derivations ever disagree,
a relay would delegate stake to an address nobody holds the key for, and the
coins would sit there until the relay withdrew them.

They can disagree easily, which is why this exists. A record publishes only the
x coordinate of the key, so the parity byte is gone, and two private keys share
every x. The convention is even-Y, applied when the key is created and again
when it is loaded - and since negating a key leaves x alone, applying it changes
nothing about the node's published identity.

What the delegation then buys is the property that makes the whole arrangement
safe without trusting anyone: consensus restricts a staking key to producing
coinstakes that pay back to the owner, so a relay can hand a stranger staking
power over its coins and cannot lose the principal.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

# src/roster/record.h
RECORD_KEY_SIZE = 32


class RosterDelegationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # -coldstakeheight: regtest gates cold staking at 2000 otherwise, and
        # this test has no reason to mine that far.
        args = ["-rosterindex", "-coldstakeheight=1", "-fallbackfee=0.0001"]
        self.extra_args = [args, args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        relay, user = self.nodes[0], self.nodes[1]
        relay.createwallet("relay")
        user.createwallet("user")
        relay_w = relay.get_wallet_rpc("relay")
        user_w = user.get_wallet_rpc("user")

        funds = relay_w.getnewaddress()
        # Past COINBASE_MATURITY, so the relay has something to delegate.
        relay.generatetoaddress(620, funds)
        self.sync_all()

        self.log.info("a peer with no coins is listed, and the relay pays for it")
        tip = relay.getblockcount()
        record = user.createannouncement({"expiry_height": tip + 30000})
        assert_equal(user_w.getbalance(), 0)
        relay_w.publishrecord(record["hex"])
        relay.generatetoaddress(2, funds)
        self.sync_all()
        assert_equal(relay.getrosterinfo()["live_peers"], 1)

        self.log.info("both sides derive the same staking address from the published key")
        listed = relay.getroster(1)[0]
        published_key = listed["key"]
        assert_equal(len(published_key), RECORD_KEY_SIZE * 2)
        assert_equal(published_key, record["key"])

        # The relay has only the chain to go on. The peer has only its own key.
        from_chain = relay.getrosterstaker(published_key)
        from_key = user.dumprosterkey()
        assert_equal(from_chain["staker_address"], from_key["staker_address"])
        assert_equal(from_chain["key"], from_key["key"])
        # Even-Y is the convention, so the derived pubkey always starts 02.
        assert_equal(from_chain["staker_pubkey"][:2], "02")
        assert_equal(from_chain["staker_pubkey"][2:], published_key)

        self.log.info("  %s, derived by both and agreed by neither",
                      from_chain["staker_address"])

        self.log.info("asking about this node's own key needs no argument")
        assert_equal(relay.getrosterstaker()["key"], relay.getrosterinfo()["operational_key"])

        self.log.info("32 bytes that name no key are refused")
        # Above the field prime, so not an x coordinate at all. Roughly half of
        # the values below it are, which is why this picks one that cannot be.
        assert_raises_rpc_error(-8, "not a point on the curve",
                                relay.getrosterstaker, "ff" * RECORD_KEY_SIZE)
        assert_raises_rpc_error(-8, "32 bytes of hex", relay.getrosterstaker, "abcd")

        self.log.info("the relay delegates stake to it, keeping ownership")
        owner = relay_w.getnewaddress()
        delegation = relay_w.delegatestake(from_chain["staker_address"], owner, 500)
        assert_equal(delegation["staker_address"], from_chain["staker_address"])
        assert_equal(delegation["owner_address"], owner)
        relay.generatetoaddress(1, funds)
        self.sync_all()

        # The output is a cold stake, not an ordinary payment: that is what
        # stops the peer spending the principal.
        raw = relay_w.gettransaction(delegation["txid"], True, True)
        cold = [v for v in raw["decoded"]["vout"]
                if v["scriptPubKey"]["type"] == "coldstake"]
        assert_equal(len(cold), 1)
        assert_equal(cold[0]["value"], 500)

        self.log.info("the peer imports its roster key and can stake, but not spend")
        user_w.importprivkey(from_key["wif"], "roster", True)
        self.sync_all()
        balances = user_w.getwalletinfo()
        assert_equal(balances["cold_stake"], 500)
        # Delegated coins are stakeable, never spendable, and the wallet says so.
        assert_equal(balances["balance"], 0)
        assert_equal(balances["delegated"], 0)

        self.log.info("the relay still owns them")
        relay_balances = relay_w.getwalletinfo()
        assert_equal(relay_balances["delegated"], 500)
        assert_equal(relay_balances["cold_stake"], 0)
        assert_greater_than(relay_balances["balance"], 0)

        # Withdrawal is not tested here: the script carries no expiry, so taking
        # a delegation back is the owner spending an output it already owns,
        # which is ordinary wallet behaviour rather than anything this adds.


if __name__ == '__main__':
    RosterDelegationTest().main()
