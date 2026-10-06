#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test identities, rotation, vetoes, age proofs and revocations.

Design note 001 sections 5, 7 and 9. Three nodes: 0 and 1 keep a roster
index, 2 does not - it stands for a client with headers only.

What the test is about:

  * an identity runs a node only once the node's own announcement accepts
    it, so nobody can claim someone else's node by delegating to its key;

  * age is continuous history, proved link by link with merkle branches that
    a node without any roster checks against its headers;

  * a rotation carries the age to the new key once its veto window is over,
    and the recovery key cancels one inside the window;

  * a revocation counts the moment a node sees it - passed from node to node
    without a transaction - and a reorg does not bring the key back.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

AGE_DEPTH = 100
ROTATE_VETO = 672


class RosterIdentityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        indexed = ["-rosterindex", "-fallbackfee=0.0001"]
        self.extra_args = [indexed, indexed, ["-fallbackfee=0.0001"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine(self, n=1):
        self.sync_mempools()
        self.nodes[0].generatetoaddress(n, self.address)
        self.sync_blocks()
        tip = self.nodes[0].getblockcount()
        for node in self.nodes[:2]:
            self.wait_until(lambda: node.getrosterinfo()["best_block_height"] == tip, timeout=60)

    def publish(self, node, hexrec):
        return node.publishrecord(hexrec)["txid"]

    def announce(self, node):
        rec = node.createannouncement()
        self.publish(node, rec["hex"])
        return rec

    def run_test(self):
        n0, n1, n2 = self.nodes
        self.address = n0.getnewaddress("", "legacy")
        n0.generatetoaddress(520, self.address)
        n0.sendtoaddress(n1.getnewaddress("", "legacy"), 100)
        self.mine()
        op0 = n0.getrosterinfo()["operational_key"]
        op1 = n1.getrosterinfo()["operational_key"]

        self.log.info("an identity runs a key once the key's own announcement accepts it")
        ident = n0.createidentity()
        id0 = ident["identity_key"]
        assert_equal(n0.getrosterinfo()["identity_key"], id0)
        self.publish(n0, ident["delegation"])
        self.mine()
        delegated_at = n0.getblockcount()
        self.announce(n0)
        self.mine()
        # The announcement points back at the delegation: that is the acceptance.
        listed = [p for p in n1.getroster(0) if p["key"] == op0][0]
        assert_equal(listed["prev_height"], delegated_at)
        standing = n1.getidentity(op0)
        assert_equal(standing["identity"], id0)
        assert_equal(standing["since_height"], delegated_at)
        # Not deep enough to count yet.
        assert_equal(standing["age_blocks"], 0)

        self.log.info("someone else's delegation to the same key claims nothing")
        other = n1.createidentity(False)
        id1 = other["identity_key"]
        self.publish(n1, other["delegation"])
        squat = n1.createdelegation(op0, other["identity_key_wif"])
        self.publish(n1, squat["delegation"])
        self.mine()
        assert_equal(n0.getidentity(op0)["identity"], id0)
        claimed = n0.getidentity(id1)["as_identity"]["operational_keys"]
        squatted = [k for k in claimed if k["key"] == op0][0]
        assert_equal(squatted["accepted"], False)
        assert_equal(squatted["counts"], False)

        self.log.info("age counts once its history is deep, and a node with headers only can check it")
        self.mine(AGE_DEPTH)
        tip = n0.getblockcount()
        assert_equal(n0.getidentity(op0)["age_blocks"], tip - delegated_at)
        proof = n1.getageproof(op0)
        assert_equal([l["role"] for l in proof["links"]], ["announcement", "delegation"])
        checked = n2.verifyageproof(proof)
        assert_equal(checked["valid"], True)
        assert_equal(checked["identity"], id0)
        assert_equal(checked["since_height"], delegated_at)
        assert_equal(checked["age_blocks"], tip - delegated_at)
        # A proof cannot be stretched: pointing a link at another block fails.
        forged = dict(proof)
        forged["links"] = [dict(proof["links"][0]), dict(proof["links"][1])]
        forged["links"][1]["tx"] = proof["links"][0]["tx"]
        assert_equal(n2.verifyageproof(forged)["valid"], False)

        self.log.info("the recovery key vetoes a rotation inside its window")
        stolen = n1.createrotation(other["identity_key_wif"])
        self.publish(n1, stolen["rotation"])
        self.mine()
        pending = n0.getidentity(id1)["as_identity"]
        assert_equal(pending["rotation"]["to"], stolen["to"])
        veto = n1.createveto(other["recovery_key_wif"], id1)
        self.publish(n1, veto["veto"])
        self.mine()
        state = n0.getidentity(id1)["as_identity"]
        assert "rotation" not in state
        assert_equal(len(state["vetoed_rotations"]), 1)
        self.mine(ROTATE_VETO)
        assert_equal(n0.getidentity(id1)["as_identity"]["retired"], False)

        self.log.info("the owner's rotation takes effect after the window and carries the age")
        moved = n0.createrotation()
        self.publish(n0, moved["rotation"])
        self.publish(n0, moved["delegation"])
        self.mine()
        assert_equal(n0.getrosterinfo()["identity_key"], moved["to"])
        self.mine(ROTATE_VETO)
        old_state = n1.getidentity(id0)["as_identity"]
        assert_equal(old_state["retired"], True)
        assert_equal(old_state["current_key"], moved["to"])
        # The key re-announces, linking to the new identity's delegation.
        self.announce(n0)
        self.mine()
        standing = n1.getidentity(op0)
        assert_equal(standing["identity"], moved["to"])
        assert_equal(standing["since_height"], delegated_at)

        self.log.info("a revocation counts on sight, passed between nodes without a transaction")
        self.announce(n1)
        self.mine()
        assert op1 in [p["key"] for p in n0.getroster(0)]
        revocation = n1.createrevocation()
        sent = n1.sendrevocation(revocation["revocation"])
        assert_equal(sent["new"], True)
        for node in (n0, n2):
            self.wait_until(lambda: op1 in [r["key"] for r in node.listrevocations()], timeout=30)
        assert op1 not in [p["key"] for p in n0.getroster(0)]
        assert_equal(n0.getidentity(op1)["revoked"], True)
        assert_equal([r["confirmed"] for r in n0.listrevocations()], [False])

        self.log.info("on the chain too, and a reorg that drops it does not bring the key back")
        self.publish(n1, revocation["revocation"])
        self.mine()
        assert_equal([r["confirmed"] for r in n0.listrevocations()], [True])
        dropped = n0.getbestblockhash()
        n0.invalidateblock(dropped)
        assert op1 not in [p["key"] for p in n0.getroster(0)]
        n0.reconsiderblock(dropped)

        self.log.info("a roster a month old is stale: still dialled, not trusted")
        assert_equal(n0.getrosterinfo()["stale"], False)
        n0.setmocktime(n0.getblock(n0.getbestblockhash())["time"] + 31 * 24 * 3600)
        assert_equal(n0.getrosterinfo()["stale"], True)
        n0.setmocktime(0)


if __name__ == '__main__':
    RosterIdentityTest().main()
