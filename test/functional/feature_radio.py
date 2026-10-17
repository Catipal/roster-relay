#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the overlay carried over Reticulum (-radio).

Two nodes, each with the Reticulum bridge (contrib/reticulum/bps-rns-bridge.py)
beside it. The two Reticulum instances are joined by a TCP interface on
127.0.0.1, which is how Reticulum stands in for a radio when there is none:
to the bridges and the nodes it is the same as an RNode's LoRa link.

  0  a relay, listed in the roster, that pays for listings but is not staking
  1  a user that asks it to

What the test is really about:

  * each bridge hears the other node announce itself, and the node lists it as
    a radio neighbour with the roster key it announced;

  * a listed relay heard on the radio becomes the entry of the user's paths:
    the user's listing request goes to the relay through the bridge, over
    Reticulum, split into packets and joined again, and the relay's answer
    comes back the same way - the overlay's handshake and encryption running
    end to end through it;

  * the same holds over a pretend LoRa channel (test_framework/lora.py) at
    spreading factor 10, under a kilobit a second, with a tenth of the packets
    lost: the node waits as long as the speed its bridge reports needs, and
    the bridge recovers a link whose setup lost a packet;

  * with -radioentry=0 the request is not sent: over the internet a node
    never asks the relay it enters through, which sees its address, and here
    there is no other.

Skipped when Reticulum is not installed (pip install rns).
"""

import os
import subprocess
import sys

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
)

RNS_CONFIG = """[reticulum]
  enable_transport = False
  share_instance = No
  panic_on_interface_error = No

[logging]
  loglevel = 2

[interfaces]
  [[BPS test radio]]
    type = {kind}
    enabled = yes
    {where}
"""

LORA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_framework", "lora.py")
LORA_SF = 10
LORA_LOSS = 0.1


class RadioTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # A request over slow LoRa with packets lost takes minutes.
        self.rpc_timeout = 900

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        try:
            import RNS  # noqa: F401
        except ImportError:
            raise SkipTest("Reticulum is not installed (pip install rns)")

    def setup_nodes(self):
        common = ["-overlay", "-rosterindex", "-radio", "-fallbackfee=0.0001", "-staking=0"]
        self.extra_args = [common + ["-acceptlistings"], common]
        super().setup_nodes()

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def start_bridges(self, lora=False):
        # Ports the framework gives no node in this test.
        link_port = p2p_port(self.num_nodes + 3)
        bridge = os.path.join(self.config["environment"]["SRCDIR"], "contrib", "reticulum", "bps-rns-bridge.py")
        self.bridges = []
        if lora:
            # One station per node on the pretend channel, joined to it by a
            # pipe, and telling Reticulum the speed an RNode would report.
            base = p2p_port(self.num_nodes + 5)
            bitrate = subprocess.check_output([sys.executable, LORA, "bitrate", "--sf", str(LORA_SF)]).decode().strip()
            self.bridges.append(subprocess.Popen(
                [sys.executable, LORA, "channel", "--base", str(base), "--stations", str(self.num_nodes),
                 "--sf", str(LORA_SF), "--loss", str(LORA_LOSS)]))
        for n in range(self.num_nodes):
            config_dir = os.path.join(self.options.tmpdir, "reticulum%d%s" % (n, "lora" if lora else ""))
            os.makedirs(config_dir, exist_ok=True)
            if lora:
                # Reticulum splits the command the POSIX way, which would eat
                # Windows' backslashes; Python takes forward ones everywhere.
                kind, where = "PipeInterface", "command = %s %s pipe %d\n    respawn_delay = 1\n    bitrate = %s" % (
                    sys.executable.replace("\\", "/"), LORA.replace("\\", "/"), base + n, bitrate)
            elif n == 0:
                kind, where = "TCPServerInterface", "listen_ip = 127.0.0.1\n    listen_port = %d" % link_port
            else:
                kind, where = "TCPClientInterface", "target_host = 127.0.0.1\n    target_port = %d" % link_port
            with open(os.path.join(config_dir, "config"), "w", encoding="utf-8") as f:
                f.write(RNS_CONFIG.format(kind=kind, where=where))
            log = open(os.path.join(self.options.tmpdir, "bridge%d%s.log" % (n, "lora" if lora else "")), "w",
                       encoding="utf-8")
            # Airtime is scarce on LoRa: announce at start, then rarely.
            self.bridges.append(subprocess.Popen(
                [sys.executable, bridge, "--datadir", os.path.join(self.nodes[n].datadir, self.chain),
                 "--rnsconfig", config_dir, "--announce-interval", "120" if lora else "5"],
                stdout=log, stderr=subprocess.STDOUT))

    def stop_bridges(self):
        for b in self.bridges:
            b.terminate()
        for b in self.bridges:
            try:
                b.wait(timeout=20)
            except subprocess.TimeoutExpired:
                b.kill()

    def neighbour(self, n, key):
        for peer in self.nodes[n].getradioinfo()["neighbours"]:
            if peer["key"] == key:
                return peer
        return None

    def run_test(self):
        relay, user = self.nodes
        self.log.info("both nodes are waiting for a bridge")
        info = user.getradioinfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["bridge"], False)
        assert_equal(info["entry"], True)

        self.log.info("list the relay, with the endpoint its overlay listens beside")
        relay.generatetoaddress(520, relay.getnewaddress("", "legacy"))
        record = relay.createannouncement({"endpoints": [
            {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(0)}]})
        relay.publishrecord(record["hex"])
        relay.generatetoaddress(1, relay.getnewaddress())
        self.sync_all()
        self.wait_until(lambda: user.getrosterinfo()["live_peers"] == 1, timeout=30)

        self.log.info("start a Reticulum bridge beside each node, joined as a radio would be")
        self.start_bridges()
        try:
            self.log.info("each hears the other on the radio, with the roster key it announced")
            self.wait_until(lambda: user.getradioinfo()["bridge"] and relay.getradioinfo()["bridge"], timeout=60)
            self.wait_until(lambda: self.neighbour(1, self.key(0)) is not None, timeout=120)
            self.wait_until(lambda: self.neighbour(0, self.key(1)) is not None, timeout=120)
            # The roster lists the relay, so paths can enter through it.
            self.wait_until(lambda: self.neighbour(1, self.key(0))["relay"], timeout=60)
            heard = self.neighbour(1, self.key(0))
            assert heard["local"].startswith("127.0.0.1:")
            assert heard["local"] != "127.0.0.1:%d" % (p2p_port(0) + 1)
            assert_equal(len(user.getradioinfo()["destination"]), 32)

            self.log.info("the user's listing request reaches the relay over the radio, and its answer comes back")
            res = user.requestlisting()
            self.log.info("  %s", res)
            assert_equal(res["relay_address"], heard["local"])
            # The relay answered - it is not staking, so it will not pay - and
            # every byte of that went through both bridges and Reticulum.
            assert_equal(res["status"], "refused")
            assert "not staking" in res["reason"], res["reason"]
            assert self.neighbour(1, self.key(0))["session"]
        finally:
            self.stop_bridges()

        self.log.info("over LoRa at SF%d with %d%% of packets lost, the request still gets through", LORA_SF,
                      LORA_LOSS * 100)
        bitrate = int(subprocess.check_output([sys.executable, LORA, "bitrate", "--sf", str(LORA_SF)]).decode())
        self.start_bridges(lora=True)
        try:
            # Heard on the new channel: the speed the node scales its waits by
            # is the one Reticulum reports for it, not the old link's.
            self.wait_until(lambda: (self.neighbour(1, self.key(0)) or {}).get("bitrate") == bitrate and
                            self.neighbour(1, self.key(0))["relay"], timeout=300)
            heard = self.neighbour(1, self.key(0))
            res = user.requestlisting()
            self.log.info("  %s", res)
            assert_equal(res["relay_address"], heard["local"])
            assert_equal(res["status"], "refused")
            assert "not staking" in res["reason"], res["reason"]
        finally:
            self.stop_bridges()

        self.log.info("with -radioentry=0 it is not sent: the only relay is the one the user enters through")
        self.restart_node(1, self.extra_args[1] + ["-radioentry=0"])
        self.connect_nodes(1, 0)
        assert_equal(user.getradioinfo()["entry"], False)
        self.wait_until(lambda: user.getoverlayinfo().get("relay_candidates", 0) >= 1, timeout=60)
        assert_raises_rpc_error(-1, "other than this node's entry relays", user.requestlisting)


if __name__ == '__main__':
    RadioTest().main()
