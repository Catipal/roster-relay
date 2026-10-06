#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mail between roster keys, end to end over the overlay.

Design note 001 section 11.5. Six nodes, every one listed in the roster with
an endpoint, every one running the overlay, a mailbox and a mail client. On
regtest each 127.0.0.1 address and port counts as its own operator, so the
roster is six relays run by six different people.

What the test is really about:

  * a letter reaches its recipient through mailboxes nobody assigned - the
    roster decides them, and sender and recipient agree without asking;

  * every trip runs through three relays the sender never had to connect to
    beforehand: relays dial the next hop because the roster lists it;

  * the recipient's mail key is fetched from a mailbox, checked against the
    recipient's roster key, and the letter opens only for the recipient;

  * mailboxes hand letters over only to their owner, and drop them once
    collected, so the recipient's node holds the only copy;

  * a person who never published a mail key cannot be written to, and a node
    with mail off says so.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    p2p_port,
)

# COINBASE_MATURITY on this chain is 500, so the payer mines past it.
FUNDED_HEIGHT = 520


class MailTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 6
        self.setup_clean_chain = True
        # The overlay listens one above each node's p2p port by default, which
        # is where the roster says to find it. Mail is collected only when the
        # test asks (-mailpoll=0), so nothing moves behind its back.
        self.extra_args = [["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0"]
                           for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def wait_for_index(self):
        tip = self.nodes[0].getblockcount()
        for node in self.nodes:
            self.wait_until(lambda: node.getrosterinfo()["best_block_height"] == tip, timeout=30)

    def holding(self):
        return sum(node.getmailinfo()["holding"]["letters"] for node in self.nodes)

    def run_test(self):
        payer = self.nodes[0]
        payer.generatetoaddress(FUNDED_HEIGHT, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("before anyone is listed there is nowhere to hold mail")
        # Read now, so the next read has to notice the roster changed under it.
        assert_equal(self.nodes[1].getmailinfo()["mailboxes"], [])

        self.log.info("list every node, with the endpoint its overlay listens beside")
        for n, node in enumerate(self.nodes):
            record = node.createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            payer.publishrecord(record["hex"])
        payer.generatetoaddress(1, payer.getnewaddress())
        self.sync_all()
        self.wait_for_index()
        for node in self.nodes:
            assert_equal(node.getrosterinfo()["live_peers"], self.num_nodes)

        alice, bob = self.nodes[0], self.nodes[1]
        info = bob.getmailinfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["address"], self.key(1))
        assert_equal(len(info["mailboxes"]), 3)
        assert self.key(1) not in info["mailboxes"]
        # Anyone works out the same mailboxes from the roster.
        assert_equal(sorted(info["mailboxes"]), sorted(bob.getmailinfo()["mailboxes"]))

        self.log.info("nobody can write to a person who has not published a mail key")
        assert_raises_rpc_error(-1, "None of the recipient's mailboxes has a current mail key",
                                alice.sendmail, self.key(1), "Too early", "Bob has not been online with mail yet.")

        self.log.info("the recipient leaves its mail key at its mailboxes, through three relays")
        checked = bob.checkmail()
        assert_equal(checked["mailboxes"], 3)
        assert_equal(checked["reached"], 3)
        assert_equal(checked["fetched"], 0)
        assert_equal(bob.getmailinfo()["key"]["id"], 1)

        self.log.info("a letter is sealed to that key and left at every mailbox")
        body = "Bob,\n\nThis went through three relays to each of your mailboxes.\n\nAlice"
        sent = alice.sendmail(self.key(1), "Hello", body)
        assert_equal(sent["mailboxes"], 3)
        assert_equal(sent["delivered"], 3)
        assert_equal(self.holding(), 3)
        outbox = alice.listmail("sent")
        assert_equal(len(outbox), 1)
        assert_equal(outbox[0]["id"], sent["id"])
        assert_equal(outbox[0]["delivered"], 3)
        assert_equal(outbox[0]["to"], self.key(1))

        self.log.info("the recipient collects it, once, and the mailboxes let it go")
        checked = bob.checkmail()
        assert_equal(checked["fetched"], 1)
        assert_equal(checked["reached"], 3)
        assert_equal(self.holding(), 0)
        inbox = bob.listmail()
        assert_equal(len(inbox), 1)
        letter = inbox[0]
        assert_equal(letter["id"], sent["id"])
        assert_equal(letter["from"], self.key(0))
        assert_equal(letter["subject"], "Hello")
        assert_equal(letter["read"], False)
        assert_equal(bob.getmailinfo()["unread"], 1)
        full = bob.readmail(letter["id"])
        assert_equal(full["body"], body)
        assert_equal(bob.listmail()[0]["read"], True)
        assert_equal(bob.getmailinfo()["unread"], 0)
        # Nothing new the second time.
        assert_equal(bob.checkmail()["fetched"], 0)
        # Nobody else got a copy.
        for node in self.nodes[2:]:
            assert_equal(node.listmail(), [])

        self.log.info("a reply goes the other way")
        assert_equal(alice.checkmail()["reached"], 3)
        bob.sendmail(self.key(0), "Re: Hello", "Got it.")
        assert_equal(alice.checkmail()["fetched"], 1)
        assert_equal(alice.listmail()[0]["subject"], "Re: Hello")
        assert_equal(alice.listmail()[0]["from"], self.key(1))

        self.log.info("a letter is deleted from the node that kept it")
        assert_equal(bob.deletemail(letter["id"]), True)
        assert_equal(bob.deletemail(letter["id"]), False)
        assert_equal(bob.listmail(), [])

        self.log.info("limits are enforced before anything is sent")
        assert_raises_rpc_error(-1, "longer than", alice.sendmail, self.key(1), "s" * 201, "x")
        assert_raises_rpc_error(-8, "roster key", alice.sendmail, "00" * 31, "s", "x")

        self.log.info("a node with mail off says so")
        self.restart_node(5, ["-overlay", "-rosterindex", "-mail=0"])
        assert_equal(self.nodes[5].getmailinfo()["enabled"], False)
        assert_raises_rpc_error(-1, "Mail is off", self.nodes[5].sendmail, self.key(1), "s", "x")
        # It still holds mail for others: that is -mailbox, not -mail.
        assert_equal(self.nodes[5].getmailinfo()["holding"]["enabled"], True)

        stats = sum(node.getmailinfo()["holding"]["keys"] for node in self.nodes[:5])
        assert_greater_than(stats, 0)


if __name__ == '__main__':
    MailTest().main()
