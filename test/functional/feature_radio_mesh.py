#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A relay forwards to the next relay over radio (design note §8·7).

Radio used to replace only the first hop of a path. Now any relay reaches the
next hop over radio when that hop is a radio neighbour it has no internet route
to, so a path can cross a stretch that has only radio.

Four nodes:

  0  a user on the internet, not on the radio
  1  R1, a relay on the internet and the radio
  2  R2, a relay reachable only over the radio - listed with an onion endpoint
     nobody here can dial, and heard by R1 on the radio
  3  S, a service (-meetable) on the internet, not on the radio, listed with no
     endpoint at all

Only R1 and R2 are on the (pretend LoRa) radio, so it is the one hop under
test. S's meeting points are R1 and R2; registering at R2, and a visitor
meeting S there, both go S/U -> R1 -> R2, and the R1 -> R2 leg is radio.

Skipped when Reticulum is not installed.
"""

import os
import subprocess
import sys

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

LORA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_framework", "lora.py")

RNS_CONFIG = """[reticulum]
  enable_transport = No
  share_instance = No
  panic_on_interface_error = No
[logging]
  loglevel = 3
[interfaces]
  [[LoRa]]
    type = PipeInterface
    enabled = yes
    command = {python} {lora} pipe {port}
    respawn_delay = 1
    bitrate = {bitrate}
"""


class RadioMeshTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.rpc_timeout = 900
        # -overlayblocks off: this test is about forwarding and meeting, not
        # block sync, and its chatter would only compete for the radio.
        common = ["-overlay", "-rosterindex", "-fallbackfee=0.0001", "-mailpoll=0", "-mail=0", "-overlayblocks=0"]
        # Only R1 and R2 run the radio. S is meetable; it reaches its radio-only
        # meeting point through R1.
        self.extra_args = [
            common,                                   # 0 user
            common + ["-radio", "-radioentry=0"],     # 1 R1 (bridges; does not itself enter by radio)
            common + ["-radio", "-radioentry=0"],     # 2 R2 (radio only)
            common + ["-meetable", "-meethops=1"],    # 3 S
        ]
        self.radio_nodes = [1, 2]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        try:
            import RNS  # noqa: F401
        except ImportError:
            raise SkipTest("Reticulum is not installed (pip install rns)")

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def start_radio(self):
        base = p2p_port(self.num_nodes + 5)
        bitrate = int(subprocess.check_output([sys.executable, LORA, "bitrate", "--sf", "8"]).decode())
        self.procs = [subprocess.Popen(
            [sys.executable, LORA, "channel", "--base", str(base), "--stations", "2", "--sf", "8"],
            stdout=open(os.path.join(self.options.tmpdir, "air.log"), "w"), stderr=subprocess.STDOUT)]
        bridge = os.path.join(self.config["environment"]["SRCDIR"], "contrib", "reticulum", "bps-rns-bridge.py")
        for station, n in enumerate(self.radio_nodes):
            cfg = os.path.join(self.options.tmpdir, "rns%d" % n)
            os.makedirs(cfg, exist_ok=True)
            with open(os.path.join(cfg, "config"), "w", encoding="utf-8") as f:
                f.write(RNS_CONFIG.format(python=sys.executable.replace("\\", "/"),
                                          lora=LORA.replace("\\", "/"), port=base + station, bitrate=bitrate))
            log = open(os.path.join(self.options.tmpdir, "bridge%d.log" % n), "w", encoding="utf-8")
            self.procs.append(subprocess.Popen(
                [sys.executable, bridge, "--datadir", os.path.join(self.nodes[n].datadir, self.chain),
                 "--rnsconfig", cfg, "--announce-interval", "20"], stdout=log, stderr=subprocess.STDOUT))

    def stop_radio(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()

    def run_test(self):
        user, r1, r2, s = self.nodes
        payer = user
        payer.generatetoaddress(520, payer.getnewaddress("", "legacy"))
        self.sync_all()

        self.log.info("list R1 on the internet, R2 by an onion nobody here can dial, S with no endpoint")
        payer.publishrecord(r1.createannouncement({"endpoints": [
            {"network": "ipv4", "address": "127.0.0.1", "port": p2p_port(1)}]})["hex"])
        # A TorV3 key as 32 bytes of hex; never dialed, it only makes R2
        # unreachable to everyone here except over the radio.
        onion = "11" * 32
        payer.publishrecord(r2.createannouncement({"endpoints": [
            {"network": "onion", "address": onion, "port": 9345}]})["hex"])
        payer.publishrecord(s.createannouncement({})["hex"])
        payer.generatetoaddress(1, payer.getnewaddress())
        self.sync_all()

        # Into the next epoch, so the listings are in place at its anchor (the
        # height whose roster decides the meeting points).
        target = 2 * 480 + 10
        while payer.getblockcount() < target:
            payer.generatetoaddress(min(200, target - payer.getblockcount()), payer.getnewaddress())
        self.sync_all()
        for node in self.nodes:
            self.wait_until(lambda: node.getrosterinfo()["best_block_height"] == payer.getblockcount(), timeout=60)

        # S's meeting points are the two relays, R2 among them.
        self.wait_until(lambda: len(s.getoverlayinfo()["rendezvous"]) == 2, timeout=30)
        assert self.key(2) in s.getoverlayinfo()["rendezvous"]

        self.log.info("start the radio between R1 and R2")
        self.start_radio()
        try:
            self.wait_until(lambda: any(p["key"] == self.key(2) for p in r1.getradioinfo()["neighbours"]), timeout=180)
            self.log.info("R1 hears R2 on the radio; R2 has no other way in")

            # S reaches R2 only through R1 over the radio (reaching R1 as a
            # meeting point would need R2 as the entry, which S cannot reach),
            # so a registration at R2 is itself proof the radio leg carried it.
            self.log.info("S registers at R2, carried there by R1 over radio")
            self.wait_until(lambda: self.key(2) in [r["point"] for r in s.getmeetinginfo()["registrations"]],
                            timeout=300)
            self.wait_until(lambda: r2.getmeetinginfo()["held"] >= 1, timeout=60)

            self.log.info("the user meets S through R2, so R1 forwarded the path to R2 over radio")
            met = user.meet(self.key(3))
            self.log.info("  %s", met)
            assert_equal(met["point"], self.key(2))
            assert "rtt_ms" in met
        finally:
            self.stop_radio()


if __name__ == '__main__':
    RadioMeshTest().main()
