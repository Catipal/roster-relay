#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test paying by name.

Design note 001 section 11. Node 0 pays; node 1 holds a name and takes
payments on it.

What the test is really about:

  * a name never points at an address: the payee publishes a spending key,
    signed by its roster key, and every payment goes to an address of its own
    worked out from that key and a one-time key the payment carries;

  * so no two payments share an address, none of them is the published key's,
    and only the payee's wallet recognises them - in the mempool already;

  * a name, a petname, a subname or the bare key all pay the same payee, and
    a name or key that changed in the last day is refused unless the payer
    says so, because a payment cannot be taken back - though renewing a name
    is not a change;

  * a payment that arrives while the wallet is locked shows as watch-only and
    becomes spendable when the wallet is unlocked;

  * a wallet restored from a backup finds its payments again by rescanning;

  * and nobody pays a key that has been revoked.
"""

import os
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

COMMIT_MIN_AGE = 6
SETTLE_DEPTH = 500


class NamePaymentsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-nameindex", "-fallbackfee=0.0001"] for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def mine(self, n=1):
        self.sync_mempools()
        self.nodes[0].generatetoaddress(n, self.address)
        self.sync_all()
        tip = self.nodes[0].getblockcount()
        for node in self.nodes:
            self.wait_until(lambda: node.getnameinfo()["best_block_height"] == tip, timeout=30)

    def run_test(self):
        payer, payee = self.nodes
        self.address = payer.getnewaddress("", "legacy")
        payer.generatetoaddress(520, self.address)
        self.sync_all()
        payer.sendtoaddress(payee.getnewaddress("", "legacy"), 10)
        self.mine()

        self.log.info("the payee registers a name; nobody can pay it by name yet")
        payee.registername("pilot")
        self.mine(COMMIT_MIN_AGE + 1)
        assert_equal(payee.registername("pilot")["status"], "claimed")
        self.mine()
        assert_equal(payer.resolvename("pilot")["payable"], False)
        assert_equal(payee.getnameinfo()["payable"], False)
        assert_raises_rpc_error(-8, "pilot does not take payments by name", payer.sendtoname, "pilot", 1)

        self.log.info("it turns payments on; payers wait until the name and the key have settled")
        self.mine(SETTLE_DEPTH)
        on = payee.setnamepayments()
        assert_equal(on["key"], self.key(1))
        backup = os.path.join(self.nodes[1].datadir, "before_payments.dat")
        payee.backupwallet(backup)
        self.mine()
        assert_equal(payee.getnameinfo()["payable"], True)
        resolved = payer.resolvename("pilot")
        assert_equal(resolved["payable"], True)
        assert_equal(resolved["settled"], True)
        assert_raises_rpc_error(-8, "published the key it is paid on 0 blocks ago", payer.sendtoname, "pilot", 1)
        self.mine(SETTLE_DEPTH)

        self.log.info("a payment by name reaches the payee at an address of its own, seen in the mempool")
        balance = payee.getbalance()
        first = payer.sendtoname("pilot", Decimal("1.5"))
        assert_equal(first["to"], "pilot")
        assert_equal(first["source"], "name")
        assert_equal(first["key"], self.key(1))
        self.sync_mempools()
        self.wait_until(lambda: len(payee.listnamepayments()) == 1, timeout=30)
        seen = payee.listnamepayments()
        assert_equal(seen[0]["txid"], first["txid"])
        assert_equal(seen[0]["address"], first["address"])
        assert_equal(seen[0]["amount"], Decimal("1.5"))
        assert_equal(seen[0]["confirmations"], 0)
        assert_equal(seen[0]["spendable"], True)
        self.mine()
        assert_equal(payee.listnamepayments()[0]["confirmations"], 1)
        assert_equal(payee.getbalance(), balance + Decimal("1.5"))
        # The payer keeps it as a payment it made, not as its own coins.
        assert_equal(payer.getaddressinfo(first["address"])["ismine"], False)
        assert_equal(payer.getaddressinfo(first["address"])["labels"], ["Paid to pilot"])
        assert_equal(payee.getaddressinfo(first["address"])["ismine"], True)

        self.log.info("renewing the name does not make payers wait again")
        depth = payer.resolvename("pilot")["depth"]
        payee.renewname("pilot")
        self.mine()
        resolved = payer.resolvename("pilot")
        assert_equal(resolved["settled"], True)
        assert_equal(resolved["depth"], depth + 1)

        self.log.info("a petname, a subname and the bare key pay the same payee, never at the same address")
        payer.setpetname("friend", "pilot")
        by_petname = payer.sendtoname("friend", 2)
        assert_equal(by_petname["source"], "petname")
        by_key = payer.sendtoname(self.key(1), Decimal("0.5"))
        assert_equal(by_key["source"], "key")
        payee.setsubname("shop.pilot", self.key(1))
        self.mine()
        assert_raises_rpc_error(-8, "shop.pilot changed hands", payer.sendtoname, "shop.pilot", 1)
        by_subname = payer.sendtoname("shop.pilot", Decimal("0.25"), True)
        self.mine()
        payments = payee.listnamepayments()
        assert_equal(len(payments), 4)
        assert_equal(sum(p["amount"] for p in payments), Decimal("4.25"))
        addresses = {p["address"] for p in payments}
        assert_equal(addresses, {first["address"], by_petname["address"], by_key["address"], by_subname["address"]})
        # None of them is the key the payee published.
        spend_address = payee.getaddressesbylabel("Payments by name")
        assert addresses.isdisjoint(spend_address.keys())

        self.log.info("a payment that arrives while the wallet is locked is watch-only until it is unlocked")
        payee.encryptwallet("pass")
        locked = payer.sendtoname("pilot", 3)
        self.mine()
        entry = [p for p in payee.listnamepayments() if p["txid"] == locked["txid"]][0]
        assert_equal(entry["spendable"], False)
        info = payee.getaddressinfo(locked["address"])
        assert_equal(info["ismine"], False)
        assert_equal(info["iswatchonly"], True)
        payee.walletpassphrase("pass", 600)
        entry = [p for p in payee.listnamepayments() if p["txid"] == locked["txid"]][0]
        assert_equal(entry["spendable"], True)
        info = payee.getaddressinfo(locked["address"])
        assert_equal(info["ismine"], True)
        assert_equal(info["iswatchonly"], False)

        self.log.info("the payee spends what it was paid")
        back = payer.getnewaddress("", "legacy")
        raw = payee.createrawtransaction(
            [{"txid": locked["txid"], "vout": entry["vout"]}], [{back: Decimal("2.999")}])
        signed = payee.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        payee.sendrawtransaction(signed["hex"])
        self.mine()
        entry = [p for p in payee.listnamepayments() if p["txid"] == locked["txid"]][0]
        assert_equal(entry["spent"], True)
        assert_equal(payer.getreceivedbyaddress(back), Decimal("2.999"))

        self.log.info("a wallet restored from before any payment finds them all as it catches up")
        # On the same node: payments are found with its roster key, which
        # holds its names too and is backed up with them.
        payee.unloadwallet(self.default_wallet_name)
        wallets_dir = os.path.join(self.nodes[1].datadir, self.chain, "wallets")
        os.replace(backup, os.path.join(wallets_dir, "restored.dat"))
        payee.loadwallet("restored.dat")
        restored = payee.get_wallet_rpc("restored.dat")
        for rescan in (False, True):
            if rescan:
                restored.rescanblockchain()
            found = restored.listnamepayments()
            assert_equal(len(found), 5)
            assert_equal({p["address"] for p in found}, addresses | {locked["address"]})
            assert all(p["spendable"] for p in found)
            assert_equal([p["spent"] for p in found if p["txid"] == locked["txid"]], [True])

        self.log.info("nobody pays a roster key that has been revoked, settled or not")
        revocation = payee.createrevocation()
        payee.sendrevocation(revocation["revocation"])
        self.wait_until(lambda: self.key(1) in [r["key"] for r in payer.listrevocations()], timeout=30)
        assert_raises_rpc_error(-8, "pilot points to has been revoked", payer.sendtoname, "pilot", 1, True)
        assert_raises_rpc_error(-8, "That roster key has been revoked", payer.sendtoname, self.key(1), 1)


if __name__ == '__main__':
    NamePaymentsTest().main()
