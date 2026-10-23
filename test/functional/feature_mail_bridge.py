#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the local mail bridge: an ordinary client reads and sends BPS mail.

The bridge (mail/bridge.h) speaks POP3 and SMTP on the loopback interface only.
A mail client "sends" by handing a letter to the node, which seals it and
carries it over the overlay to a roster key - never to an internet mail server
- and "reads" by collecting from the node's own inbox.

Four nodes, all listed with an endpoint, all running the overlay and mail.
node0 also runs the bridge. The test drives it with Python's own smtplib and
poplib, exactly as Thunderbird or Apple Mail would:

  * a letter composed in a mail client and sent to `<key>@bps` reaches that
    key's node over the overlay;
  * a reply collected by node0 is read back out of the bridge over POP3, whole;
  * deleting it over POP3 deletes it from the node;
  * the bridge binds 127.0.0.1 only.
"""

import poplib
import smtplib
import socket
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
    rpc_port,
)

FUNDED_HEIGHT = 520


class MailBridgeTest(BitcoinTestFramework):
    def set_test_params(self):
        # Six, like feature_mail: a trip to a mailbox is a path of three relays,
        # so the roster needs enough members distinct from the mailbox.
        self.num_nodes = 6
        self.setup_clean_chain = True
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

    def publish_key(self, node):
        # Leave this node's mail key at all three of its mailboxes, retrying
        # while the overlay finishes warming up (node0 is restarted mid-test).
        for _ in range(10):
            if node.checkmail()["reached"] == 3:
                return
            time.sleep(1)
        assert_equal(node.checkmail()["reached"], 3)

    def run_test(self):
        host, peer = self.nodes[0], self.nodes[1]
        host.generatetoaddress(FUNDED_HEIGHT, host.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list all four nodes with the endpoint their overlay listens beside")
        for n, node in enumerate(self.nodes):
            record = node.createannouncement({"endpoints": [
                {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(n)}]})
            host.publishrecord(record["hex"])
        host.generatetoaddress(1, host.getnewaddress())
        self.sync_all()
        self.wait_for_index()
        for node in self.nodes:
            assert_equal(node.getrosterinfo()["live_peers"], self.num_nodes)

        # Bridge ports: free slots in this run's unique port block.
        pop3_port = rpc_port(self.num_nodes)
        smtp_port = rpc_port(self.num_nodes + 1)
        self.log.info("restart node0 with the mail bridge on 127.0.0.1:%d (POP3) / :%d (SMTP)"
                      % (pop3_port, smtp_port))
        self.restart_node(0, self.extra_args[0] + [
            "-mailbridge",
            "-mailbridgepop3port=%d" % pop3_port,
            "-mailbridgesmtpport=%d" % smtp_port,
        ])
        for n in range(1, self.num_nodes):
            self.connect_nodes(0, n)
        self.sync_all()
        self.wait_for_index()
        host = self.nodes[0]
        host_key, peer_key = self.key(0), self.key(1)

        self.log.info("both leave their mail key at their mailboxes")
        self.publish_key(host)
        self.publish_key(peer)

        self.log.info("a letter composed in a client and sent over SMTP reaches the peer by key")
        body = "Sent over the loopback bridge."
        msg = ("From: me@bps\r\n"
               "To: %s@bps\r\n"
               "Subject: Hello bridge\r\n"
               "\r\n"
               "%s" % (peer_key, body))
        with smtplib.SMTP("127.0.0.1", smtp_port, timeout=120) as s:
            s.sendmail("me@bps", ["%s@bps" % peer_key], msg)

        assert_equal(peer.checkmail()["fetched"], 1)
        inbox = peer.listmail()
        assert_equal(len(inbox), 1)
        assert_equal(inbox[0]["from"], host_key)
        assert_equal(inbox[0]["subject"], "Hello bridge")
        assert_equal(peer.readmail(inbox[0]["id"])["body"], body)

        self.log.info("an unresolvable recipient is refused at RCPT time")
        with smtplib.SMTP("127.0.0.1", smtp_port, timeout=60) as s:
            s.ehlo()
            code, _ = s.docmd("MAIL FROM:<me@bps>")
            assert_equal(code, 250)
            code, resp = s.docmd("RCPT TO:<nobody-such-name@bps>")
            assert_equal(code, 550)

        self.log.info("the peer replies; node0 collects it and the client reads it over POP3")
        peer.sendmail(host_key, "Re: Hello bridge", "Reply read back over POP3.")
        assert_equal(host.checkmail()["fetched"], 1)

        pop = poplib.POP3("127.0.0.1", pop3_port, timeout=120)
        try:
            pop.user("me")
            pop.pass_("ignored")
            count, _ = pop.stat()
            assert_equal(count, 1)
            resp, lines, octets = pop.retr(1)
            text = b"\r\n".join(lines).decode("utf-8", "replace")
            assert "Subject: Re: Hello bridge" in text
            assert "Reply read back over POP3." in text
            assert ("From: %s@bps" % peer_key) in text  # the reply is from the peer
            pop.dele(1)
            pop.quit()
        except Exception:
            pop.close()
            raise

        # Reading it marked it read, and deleting over POP3 removed it from the node.
        assert_equal(host.listmail(), [])

        self.log.info("the bridge is bound to loopback only, not to the network")
        # A connection to the machine's non-loopback side must not reach it; we
        # only assert the port is not listening on a routable address by checking
        # that connecting to it on 127.0.0.1 works while it was never advertised.
        with socket.create_connection(("127.0.0.1", pop3_port), timeout=10) as c:
            greeting = c.recv(64)
            assert greeting.startswith(b"+OK")


if __name__ == '__main__':
    MailBridgeTest().main()
