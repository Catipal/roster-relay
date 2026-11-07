#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the phone companion end to end: a phone with no coin keys spends
through its home node.

Six nodes, every one listed in the roster with an endpoint and running the
overlay. Node 0 is the home node: -companion, paying from a wallet called
"allowance". The phone is bps-companion-cli, which links what a phone links
and nothing of a node - no chain, no wallet - and reaches node 0 through
three of the other five, picked by itself.

What the test is really about:

  * the phone holds a device key and nothing that can spend; the home node
    pays for it, from the allowance wallet only;

  * pairing needs the ticket the home node shows and the home node's
    acceptance, with limits set at that moment; the six digits both sides
    show agree;

  * payments are held to the limits and the PIN by the home node, which the
    phone cannot change: one payment's limit, the day's limit, five wrong PINs
    lock the phone until the home node unlocks it;

  * paying a name works from the phone exactly as from the console;

  * a payment prepared before the home node restarted is gone, not sent;

  * a revoked phone can do nothing more.
"""

import json
import os
import subprocess
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    p2p_port,
)

FUNDED_HEIGHT = 520
COMMIT_MIN_AGE = 6
SETTLE_DEPTH = 500
PIN = "246810"


class Phone:
    """bps-companion-cli with a data directory of its own."""

    def __init__(self, test, name):
        self.test = test
        self.dir = os.path.join(test.options.tmpdir, "phone_" + name)
        # BPS_COMPANION_CLI runs the scenario with another build of the phone,
        # such as mobile/core's, which shares no library with the node.
        self.binary = os.environ.get("BPS_COMPANION_CLI") or os.path.join(
            test.config["environment"]["BUILDDIR"], "src", "bps-companion-cli" + test.config["environment"]["EXEEXT"])

    def run(self, *args):
        """The command's JSON, or raise with its error."""
        p = subprocess.run([self.binary, "-datadir=" + self.dir] + [str(a) for a in args],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
        if p.returncode != 0:
            raise PhoneError(p.stderr.strip())
        return json.loads(p.stdout)

    def fails(self, message, *args):
        try:
            self.run(*args)
        except PhoneError as e:
            assert message in str(e), "expected '{}' in '{}'".format(message, e)
            return
        raise AssertionError("'{}' did not fail".format(" ".join(str(a) for a in args)))


class PhoneError(Exception):
    pass


class CompanionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 6
        self.setup_clean_chain = True
        # Whitelisted so a payment crosses all six nodes at once, not after a
        # trickle delay per hop.
        base = ["-overlay", "-rosterindex", "-nameindex", "-fallbackfee=0.0001", "-mailpoll=0",
                "-whitelist=noban@127.0.0.1"]
        self.extra_args = [base + ["-companion", "-companionwallet=allowance"]] + \
                          [list(base) for _ in range(self.num_nodes - 1)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine(self, n=1):
        self.sync_mempools()
        self.nodes[0].generatetoaddress(n, self.address)
        self.sync_all()
        tip = self.nodes[0].getblockcount()
        for node in self.nodes:
            self.wait_until(lambda: node.getrosterinfo()["best_block_height"] == tip, timeout=30)

    def run_test(self):
        home, payee = self.nodes[0], self.nodes[1]
        self.address = home.getnewaddress("", "legacy")
        home.generatetoaddress(FUNDED_HEIGHT, self.address)
        self.sync_all()

        self.log.info("before this node is a listed relay, no phone can reach it")
        info = home.getcompanioninfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["listed"], False)
        assert_equal(info["wallet_ok"], False)
        assert "is not open" in info["wallet_error"]
        for n in range(1, self.num_nodes):
            assert_equal(self.nodes[n].getcompanioninfo()["enabled"], False)

        self.log.info("list every node, with the endpoint its overlay listens beside")
        for n, node in enumerate(self.nodes):
            record = node.createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            home.publishrecord(record["hex"])
        self.mine()
        info = home.getcompanioninfo()
        assert_equal(info["listed"], True)
        assert_equal(info["node_key"][2:], home.getrosterinfo()["operational_key"])

        self.log.info("the payee registers a name and takes payments on it, so the phone can pay it by name")
        payee_address = payee.getnewaddress("", "legacy")
        home.sendtoaddress(payee_address, 10)
        self.mine()
        payee.registername("bob")
        self.mine(COMMIT_MIN_AGE + 1)
        assert_equal(payee.registername("bob")["status"], "claimed")
        self.mine(SETTLE_DEPTH)
        payee.setnamepayments()
        self.mine(SETTLE_DEPTH + 1)

        self.log.info("a phone pairs before there is an allowance wallet, and is told it cannot spend yet")
        early = Phone(self, "early")
        ticket = home.companionpair()
        early_paired = early.run("pair", ticket["ticket"], "Early", PIN)
        home.companionaccept(ticket["token"], 1, 1)
        assert_equal(early.run("pairstatus")["state"], "accepted")
        status = early.run("status")
        assert "is not open" in status["wallet_problem"], status
        assert_equal(status["balance"], "0.00")
        assert_equal(early.run("history")["history"], [])
        early.fails("is not open", "address")

        self.log.info("an allowance wallet, small, with no passphrase, filled from the main one")
        home.createwallet("allowance")
        allowance = home.get_wallet_rpc("allowance")
        main = home.get_wallet_rpc(self.default_wallet_name)
        main.sendtoaddress(allowance.getnewaddress("", "legacy"), 20)
        self.mine()
        info = home.getcompanioninfo()
        assert_equal(info["wallet_ok"], True)
        assert_equal(info["balance"], Decimal("20"))
        # The phone paired early sees it as soon as it is there.
        status = early.run("status")
        assert "wallet_problem" not in status, status
        assert_equal(status["balance"], "20.00")
        home.revokecompaniondevice(early_paired["device"])

        self.log.info("the phone answers a pairing ticket; nothing works until the home node accepts")
        phone = Phone(self, "a")
        ticket = home.companionpair()
        paired = phone.run("pair", ticket["ticket"], "Pixel", PIN)
        assert_equal(len(paired["code"]), 6)
        pending = [p for p in home.companionpending() if p["token"] == ticket["token"]]
        assert_equal(pending[0]["answered"], True)
        assert_equal(pending[0]["name"], "Pixel")
        # The digits on the phone and on the home node agree: the same phone.
        assert_equal(pending[0]["code"], paired["code"])
        assert_equal(phone.run("pairstatus")["state"], "waiting")
        phone.fails("not paired", "status")
        # A second phone with the same ticket is turned away.
        Phone(self, "intruder").fails("already been used", "pair", ticket["ticket"], "Other", PIN)

        accepted = home.companionaccept(ticket["token"], 5, 6)
        assert_equal(accepted["key"], paired["device"])
        state = phone.run("pairstatus")
        assert_equal(state["state"], "accepted")
        assert_equal(state["per_day"], "6.00")

        self.log.info("the phone sees the allowance, and an address of it to be paid at")
        status = phone.run("status")
        assert_equal(status["balance"], "20.00")
        assert_equal(status["per_tx"], "5.00")
        assert_equal(status["left_today"], "6.00")
        assert_equal(status["locked"], False)
        address = phone.run("address")["address"]
        assert_equal(allowance.getaddressinfo(address)["ismine"], True)
        assert_equal(main.getaddressinfo(address)["ismine"], False)

        self.log.info("the phone pays an address; the home node signs from the allowance and nothing else")
        paid = phone.run("pay", payee_address, 2, PIN)
        assert paid["txid"] in home.getrawmempool()
        self.mine()
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", main.gettransaction, paid["txid"])
        tx = allowance.gettransaction(paid["txid"])
        assert_equal(tx["amount"], Decimal("-2"))
        assert_greater_than(Decimal("20") - Decimal("2"), allowance.getbalance())
        spent = Decimal("2") - tx["fee"]  # fee is negative
        history = phone.run("history")["history"]
        assert_equal(history[0]["txid"], paid["txid"])
        assert_equal(history[0]["counterparty"], payee_address)

        self.log.info("the limits hold: one payment, then what is left of the day")
        phone.fails("more than this phone may send in one payment", "pay", payee_address, "5.1", PIN)
        phone.fails("left of this phone's limit for the day", "pay", payee_address, "4", PIN)
        status = phone.run("status")
        assert_equal(Decimal(status["spent_today"]), spent)

        self.log.info("a payment by name, refused and accepted for the same reasons as from the console")
        by_name = phone.run("pay", "bob", "1.5", PIN)
        assert_equal(by_name["to"] != payee_address, True)  # a one-time address, not the payee's own
        self.sync_mempools()
        self.wait_until(lambda: any(p["txid"] == by_name["txid"] for p in payee.listnamepayments()), timeout=30)
        self.mine()
        assert_equal(phone.run("history")["history"][0]["counterparty"], "bob")
        phone.fails("neither an address nor a name", "pay", "nobody-here", "1", PIN)

        self.log.info("a payment prepared before the home node restarts is gone, not sent")
        prepared = phone.run("prepare", payee_address, "0.5")
        assert_equal(prepared["amount"], "0.50")
        # The framework loads the default wallet itself; the allowance has to be named.
        self.restart_node(0, extra_args=self.extra_args[0] + ["-wallet=allowance"])
        for n in range(1, self.num_nodes):
            self.connect_nodes(0, n)
        self.wait_until(lambda: home.getcompanioninfo()["wallet_ok"], timeout=30)
        phone.fails("no longer waiting", "send", PIN)
        assert_equal(len(home.listcompaniondevices()), 1)

        self.log.info("five wrong PINs lock the phone until the home node unlocks it")
        phone.run("prepare", payee_address, "0.1")
        for left in (4, 3, 2, 1):
            phone.fails("{} {} left".format(left, "try" if left == 1 else "tries"), "send", "000000")
        phone.fails("now locked", "send", "000000")
        phone.fails("locked", "send", PIN)
        assert_equal(home.listcompaniondevices()[0]["locked"], True)
        assert_equal(home.getcompanioninfo()["locked"], 1)
        home.unlockcompaniondevice(paired["device"])
        phone.run("pay", payee_address, "0.1", PIN)

        self.log.info("the phone can change its PIN; the home node can change its limits")
        phone.run("setpin", PIN, "13579246")
        home.setcompanionlimits(paired["device"], 1, 20)
        phone.fails("one payment", "pay", payee_address, "2", "13579246")
        phone.run("pay", payee_address, "0.9", "13579246")

        self.log.info("one relay stops: the phone builds its path through others")
        self.stop_node(5)
        for _ in range(3):
            assert_equal(phone.run("status")["route"], "path")

        self.log.info("a revoked phone can do nothing more")
        home.revokecompaniondevice(paired["device"])
        assert_equal(home.listcompaniondevices(), [])
        phone.fails("not paired", "status")
        phone.fails("not paired", "pay", payee_address, "0.1", "13579246")

        self.log.info("with fewer than three relays to build a path through, a phone goes straight to the home node")
        for n in (2, 3, 4):
            self.stop_node(n)
        info = home.getcompanioninfo()
        # The pairing ticket says where to dial the home node, its listed
        # address first: the overlay, beside the p2p port.
        assert info["addresses"].startswith("127.0.0.1:{}".format(p2p_port(0) + 1)), info["addresses"]
        straight = Phone(self, "b")
        ticket = home.companionpair()
        paired = straight.run("pair", ticket["ticket"], "Pinephone", PIN)
        assert_equal([p["code"] for p in home.companionpending() if p["token"] == ticket["token"]], [paired["code"]])
        home.companionaccept(ticket["token"], 1, 2)
        assert_equal(straight.run("pairstatus")["state"], "accepted")
        status = straight.run("status")
        assert_equal(status["route"], "direct")
        assert_equal(status["per_tx"], "1.00")
        paid = straight.run("pay", payee_address, "0.5", PIN)
        assert paid["txid"] in home.getrawmempool()
        straight.fails("more than this phone may send in one payment", "pay", payee_address, "1.5", PIN)
        # Straight there or not, the phone proves its key: a revoked one is refused.
        home.revokecompaniondevice(paired["device"])
        straight.fails("not paired", "status")


if __name__ == '__main__':
    CompanionTest().main()
