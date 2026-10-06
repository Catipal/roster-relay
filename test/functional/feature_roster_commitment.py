#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the roster commitment: the roster's fingerprint in every block.

Design note 001 section 6, phase 2. DEPLOYMENT_ROSTER is active here through
-vbparams; on every real network it is defined but not scheduled.

  node 0  enforces the rule, keeps a roster index, mines and later stakes
  node 1  enforces the rule with no roster index: the ledger beside the chain
          state is all it needs
  node 2  does not know the rule - an old node - and keeps no roster at all;
          it also plays the light client, checking snapshots by headers alone
  node 3  breaks the rule (-testrostercorrupt) and is kept off the network

What the test is about:

  * blocks carry the root of the roster AGE_DEPTH blocks back, as one more
    push after the witness commitment, in mined and in staked blocks alike;

  * a node that does not know the rule follows the chain all the same - this
    is a soft fork;

  * a block with a wrong root, or none, is rejected by nodes that enforce it;

  * a client holding only headers checks a whole roster, or one member of
    it, served by a node it does not trust.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

AGE_DEPTH = 100
LAST_POW_BLOCK = 900
ACTIVE = "-vbparams=roster:-1:999999999999"
ROSTER_TAG = "42505352"  # "BPSR"


class RosterCommitmentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        common = ["-fallbackfee=0.0001", "-lastpowblock=%d" % LAST_POW_BLOCK, "-staking=0"]
        self.args0 = common + [ACTIVE, "-rosterindex"]
        self.extra_args = [
            self.args0,
            common + [ACTIVE],
            common,
            common + [ACTIVE, "-testrostercorrupt"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # 2 -> 1 -> 0, and 3 alone: it only ever hands its blocks over by hand.
        # Each dials towards node 0: a node still syncing fetches blocks only
        # from peers it dialled.
        self.setup_nodes()
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 1)

    def mine(self, n=1, nodes=None):
        nodes = nodes or self.nodes[:3]
        self.sync_mempools(nodes)
        self.nodes[0].generatetoaddress(n, self.address)
        self.sync_blocks(nodes)
        tip = self.nodes[0].getblockcount()
        self.wait_until(lambda: self.nodes[0].getrosterinfo()["best_block_height"] == tip, timeout=60)

    def roster_push(self, node, blockhash):
        """The hex of the roster push in a block's witness commitment, or None."""
        coinbase = node.getblock(blockhash, 2)["tx"][0]
        for out in coinbase["vout"]:
            script = out["scriptPubKey"]["hex"]
            if script.startswith("6a24aa21a9ed"):
                tail = script[76:]
                return tail if ROSTER_TAG in tail else None
        return None

    def run_test(self):
        n0, n1, n2, n3 = self.nodes
        self.address = n0.getnewaddress("", "legacy")
        n0.generatetoaddress(520, self.address)
        self.sync_blocks(self.nodes[:3])

        self.log.info("every block commits, and nodes without the rule follow the same chain")
        assert self.roster_push(n0, n0.getbestblockhash()) is not None
        for node in (n1, n2):
            assert_equal(node.getbestblockhash(), n0.getbestblockhash())
        # Nothing is AGE_DEPTH deep yet: the roster committed to is empty.
        assert_equal(self.roster_push(n0, n0.getbestblockhash()), "24" + ROSTER_TAG + "00" * 32)

        self.log.info("three listings, committed once they are deep")
        keys = []
        for node in (n0, n1, n2):
            record = node.createannouncement()
            n0.publishrecord(record["hex"])
            keys.append(record["key"])
        self.mine()
        listed_at = n0.getblockcount()
        self.mine(AGE_DEPTH - 1)
        assert_equal(n0.getrostersnapshot()["members"], [])
        self.mine()
        snapshot = n0.getrostersnapshot()
        assert_equal(sorted(m["key"] for m in snapshot["members"]), sorted(keys))
        assert_equal(snapshot["root"], snapshot["committed_root"])
        assert_equal(self.roster_push(n0, snapshot["blockhash"]), "24" + ROSTER_TAG + bytes.fromhex(snapshot["root"])[::-1].hex())
        # The node with no index answers from its ledger, and agrees.
        assert_equal(n1.getrostersnapshot()["root"], snapshot["root"])

        self.log.info("a client with headers only checks the whole roster")
        checked = n2.verifyrostersnapshot(snapshot)
        assert_equal(checked["valid"], True)
        assert_equal(checked["members"], 3)
        short = dict(snapshot)
        short["members"] = snapshot["members"][1:]
        assert_equal(n2.verifyrostersnapshot(short)["valid"], False)
        moved = dict(snapshot)
        moved["members"] = [dict(m) for m in snapshot["members"]]
        moved["members"][0]["height"] = listed_at - 1
        assert_equal(n2.verifyrostersnapshot(moved)["valid"], False)

        self.log.info("or one member, with a merkle branch")
        proof = n1.getrostermembership(keys[1])
        assert_equal(n2.verifyrostermembership(proof)["valid"], True)
        proof["member"]["height"] -= 1
        assert_equal(n2.verifyrostermembership(proof)["valid"], False)

        self.log.info("a block with a wrong root is rejected by nodes that enforce the rule")
        self.connect_nodes(3, 2)
        self.sync_blocks()
        self.disconnect_nodes(3, 2)
        bad = n3.generatetoaddress(1, n3.getnewaddress())[0]
        bad_hex = n3.getblock(bad, 0)
        assert_equal(n0.submitblock(bad_hex), "bad-roster-commitment")
        # Node 1 may have it already, from node 0's fast relay, and refused it then.
        assert n1.submitblock(bad_hex) in ("bad-roster-commitment", "duplicate-invalid")
        assert_equal([t["status"] for t in n1.getchaintips() if t["hash"] == bad], ["invalid"])
        # An old node takes it, as old nodes do under a soft fork, and goes
        # back to the longer chain the enforcing majority builds.
        self.disconnect_nodes(2, 1)
        # It may have taken it already from node 1's fast relay, which passes a
        # block on before checking it fully.
        assert n2.submitblock(bad_hex) in (None, "duplicate")
        assert_equal(n2.getbestblockhash(), bad)
        self.mine(2, self.nodes[:2])
        self.connect_nodes(2, 1)
        self.sync_blocks(self.nodes[:3])
        assert_equal(n2.getbestblockhash(), n0.getbestblockhash())

        self.log.info("so is a block with no root at all")
        self.disconnect_nodes(2, 1)
        bare = n2.generatetoaddress(1, n2.getnewaddress())[0]
        assert self.roster_push(n2, bare) is None
        assert_equal(n0.submitblock(n2.getblock(bare, 0)), "bad-roster-commitment-missing")
        self.mine(2, self.nodes[:2])
        self.connect_nodes(2, 1)
        self.sync_blocks(self.nodes[:3])
        assert_equal(n2.getbestblockhash(), n0.getbestblockhash())

        self.log.info("a revoked key leaves the committed roster once the revocation is deep")
        revocation = n2.createrevocation()
        n0.publishrecord(revocation["revocation"])
        self.mine(AGE_DEPTH)
        assert_equal(len(n0.getrostersnapshot()["members"]), 3)
        self.mine()
        members = [m["key"] for m in n0.getrostersnapshot()["members"]]
        assert_equal(sorted(members), sorted(keys[:2]))
        assert_equal(n2.verifyrostersnapshot(n0.getrostersnapshot())["valid"], True)

        self.log.info("the ledger is saved with the chain state and read back")
        with n1.assert_debug_log(["roster: ledger loaded at height"]):
            self.restart_node(1)
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 1)
        assert_equal(n1.getrostersnapshot()["root"], n0.getrostersnapshot()["root"])

        self.log.info("staked blocks carry it too")
        self.mine(LAST_POW_BLOCK - n0.getblockcount())
        self.restart_node(0, [a for a in self.args0 if a != "-staking=0"] + ["-staking=1"])
        self.connect_nodes(1, 0)
        self.wait_until(lambda: n0.getblockcount() > LAST_POW_BLOCK, timeout=600)
        staked = n0.getblock(n0.getblockhash(LAST_POW_BLOCK + 1))
        assert_equal(staked["flags"], "proof-of-stake")
        assert self.roster_push(n0, staked["hash"]) is not None
        self.sync_blocks(self.nodes[:3])
        assert_equal(n1.getblockhash(LAST_POW_BLOCK + 1), staked["hash"])
        assert_equal(n2.getblockhash(LAST_POW_BLOCK + 1), staked["hash"])


if __name__ == '__main__':
    RosterCommitmentTest().main()
