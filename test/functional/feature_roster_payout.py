#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a relay sharing its block reward with the peers it lists.

Design note 001 section 8 rests its whole anti-sybil argument on this one
mechanism - to attract users you must pay, to pay you must earn, to earn you
must stake - so it is worth a test that a block this node actually stakes
carries the payments, not merely that the arithmetic is right. The arithmetic
has its own tests in src/test/rosterpayout_tests.cpp.

What makes it free is the shape of the coinstake. Every cold-staking rule keys
off HasP2CSOutputs(), so a relay staking its own coins produces a plain
coinstake where none of them engage: no COLD_STAKER_FEE cap, no limit of one
differing output, no second transaction and no chain bytes beyond the outputs.
The same block would be invalid as a cold stake, which is why the wallet only
does this on the plain branch.

Two properties the test is really about:

  * a peer is paid at an address derived from the key it published, so a relay
    can pay a peer it has never spoken to and nothing extra goes on the chain;

  * the money comes out of the staker's own output rather than from thin air -
    the block still pays exactly the reward, which is the only rule consensus
    applies to a plain coinstake.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

# Regtest ships nLastPOWBlock = INT_MAX, so ConnectBlock rejects proof-of-stake
# at every height unless it is lowered. Staking begins at the block AFTER it,
# so the chain is mined to exactly that height and the staker takes the next.
# It must also clear COINBASE_MATURITY (500), or nothing is stakeable yet.
LAST_POW_BLOCK = 620
RELAY_SHARE = 25  # percent


class RosterPayoutTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_args = [
            "-lastpowblock=%d" % LAST_POW_BLOCK,
            "-rosterindex",
            "-fallbackfee=0.0001",
            "-relayshare=%d" % RELAY_SHARE,
        ]
        self.extra_args = [self.base_args + ["-staking=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("relay")
        wallet = node.get_wallet_rpc("relay")
        # Legacy, because a coinstake kernel must be P2PK or P2PKH.
        funds = wallet.getnewaddress("fund", "legacy")
        # One block short, so the peer's listing can go into the last block
        # mined: past LAST_POW_BLOCK only staked blocks are valid.
        node.generatetoaddress(LAST_POW_BLOCK - 1, funds)

        self.log.info("nothing is shared until peers are listed")
        empty = node.getrelaypayout()
        assert_equal(empty["share_percent"], RELAY_SHARE)
        assert_equal(empty["users"], 0)
        assert_equal(empty["total"], 0)
        assert "no peers are listed" in empty["note"]

        self.log.info("take on a peer")
        # A key as a record publishes it: 32 bytes, x only. This stands in for a
        # peer that handed the relay a signed record to pay for. Using this
        # node's own is enough - what matters is that the relay pays the address
        # the key names, not who holds it.
        peers = [node.getrosterstaker()["key"]]

        # A relay pays a peer only while its listing is live - a peer leaves by
        # not renewing - so the peer is listed first.
        record = node.createannouncement({})
        assert_equal(record["key"], peers[0])
        wallet.publishrecord(record["hex"])
        node.generatetoaddress(1, funds)
        assert_equal(node.getblockcount(), LAST_POW_BLOCK)
        # Liveness is read from the roster index, which follows on its own thread.
        self.wait_until(lambda: node.getrosterinfo()["best_block_height"] == LAST_POW_BLOCK, timeout=30)

        added = node.addrosteruser(peers[0])
        assert_equal(added["added"], True)
        assert_equal(added["users"], 1)
        # Listing the same peer twice lists it once.
        assert_equal(node.addrosteruser(peers[0])["added"], False)
        assert_equal(node.getrelaypayout()["users"], 1)

        self.log.info("a peer with no live listing is on the list but not paid")
        # The x coordinate of the curve's generator: a valid key nobody listed.
        unlisted = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        node.addrosteruser(unlisted)
        plan = node.getrelaypayout()
        assert_equal(plan["users"], 1)
        assert_equal(plan["lapsed"], 1)
        assert_equal(len(plan["payouts"]), 1)
        node.removerosteruser(unlisted)

        self.log.info("a key that is not a point on the curve is refused")
        assert_raises_rpc_error(-8, "not a point on the curve",
                                node.addrosteruser, "ff" * 32)
        assert_raises_rpc_error(-8, "32 bytes of hex", node.addrosteruser, "abcd")

        self.log.info("what the next block would pay")
        plan = node.getrelaypayout()
        assert_equal(plan["users"], 1)
        reward = plan["block_reward"]
        assert_equal(plan["total"], reward * RELAY_SHARE / 100)
        assert_equal(len(plan["payouts"]), 1)
        assert_equal(plan["payouts"][0]["key"], peers[0])
        expected_address = node.getrosterstaker(peers[0])["staker_address"]
        assert_equal(plan["payouts"][0]["address"], expected_address)
        expected_amount = plan["payouts"][0]["amount"]
        self.log.info("  %s would receive %s", expected_address, expected_amount)

        self.log.info("stake a block and look inside its coinstake")
        self.restart_node(0, self.base_args + ["-staking=1", "-wallet=relay"])
        # The old handle carries the old cookie, so re-acquire it after a restart.
        wallet = node.get_wallet_rpc("relay")
        self.wait_until(lambda: node.getblockcount() > LAST_POW_BLOCK, timeout=600)

        staked = node.getblock(node.getblockhash(LAST_POW_BLOCK + 1), 2)
        assert_equal(staked["flags"], "proof-of-stake")
        self.log.info("  proof-of-stake block at height %d", staked["height"])

        coinstake = staked["tx"][1]
        vout = coinstake["vout"]

        # Not a cold stake: that is the whole reason many payouts are allowed.
        assert all(o["scriptPubKey"]["type"] != "coldstake" for o in vout)
        # vout[1] is where the block signature is recovered from.
        assert_equal(vout[1]["scriptPubKey"]["type"], "pubkey")

        def addresses_of(out):
            spk = out["scriptPubKey"]
            if "addresses" in spk:
                return spk["addresses"]
            return [spk["address"]] if "address" in spk else []

        paid = [o for o in vout if expected_address in addresses_of(o)]
        assert_equal(len(paid), 1)
        assert_equal(paid[0]["value"], expected_amount)
        self.log.info("  the listed peer was paid %s inside the coinstake", paid[0]["value"])

        self.log.info("the payment came out of the staker's own share")
        # A plain coinstake may pay anyone, but never more than it takes in, and
        # that is the only rule consensus applies to it.
        spent = sum(Decimal(str(o["value"])) for o in vout)
        inputs = Decimal(0)
        for txin in coinstake["vin"]:
            # The staked outputs are this wallet's own, so ask the wallet rather
            # than needing txindex.
            entry = wallet.gettransaction(txin["txid"], True, True)
            inputs += Decimal(str(entry["decoded"]["vout"][txin["vout"]]["value"]))
        assert_equal(spent - inputs, Decimal(str(reward)))
        self.log.info("  block paid exactly its reward: %s", spent - inputs)

        self.log.info("dropping a peer stops its share")
        node.removerosteruser(peers[0])
        assert_equal(node.getrelaypayout()["users"], 0)
        assert_equal(node.getrelaypayout()["total"], 0)


if __name__ == '__main__':
    RosterPayoutTest().main()
