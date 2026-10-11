#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blocks over the overlay, to a node with only radio (design note §8·7).

The overlay carries mail and listings; the block chain travels the internet, so
a node with only radio never learns the roster. This closes that gap: a node
feeds new blocks to its radio neighbours, and a node with no internet pulls the
blocks it is missing from a neighbour that is ahead.

Two nodes, deliberately NOT connected over the peer-to-peer network - the only
thing between them is a (simulated LoRa) radio:

  0  a node on the internet that mines
  1  a node with no peer-to-peer peers at all

Node 1 cannot get blocks the usual way. It follows node 0's chain over the
radio, one block at a time, validating each as the peer-to-peer layer would.

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


class RadioBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.rpc_timeout = 300
        common = ["-overlay", "-rosterindex", "-radio", "-radioentry=0", "-overlayblocks", "-fallbackfee=0.0001"]
        self.extra_args = [list(common), list(common)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        try:
            import RNS  # noqa: F401
        except ImportError:
            raise SkipTest("Reticulum is not installed (pip install rns)")

    def setup_network(self):
        # The point of the test is that there is NO peer-to-peer link between
        # the two nodes; the radio is the only thing between them.
        self.setup_nodes()

    def start_radio(self):
        base = p2p_port(self.num_nodes + 5)
        bitrate = int(subprocess.check_output([sys.executable, LORA, "bitrate", "--sf", "8"]).decode())
        self.procs = [subprocess.Popen(
            [sys.executable, LORA, "channel", "--base", str(base), "--stations", "2", "--sf", "8"],
            stdout=open(os.path.join(self.options.tmpdir, "air.log"), "w"), stderr=subprocess.STDOUT)]
        bridge = os.path.join(self.config["environment"]["SRCDIR"], "contrib", "reticulum", "bps-rns-bridge.py")
        for n in range(self.num_nodes):
            cfg = os.path.join(self.options.tmpdir, "rns%d" % n)
            os.makedirs(cfg, exist_ok=True)
            with open(os.path.join(cfg, "config"), "w", encoding="utf-8") as f:
                f.write(RNS_CONFIG.format(python=sys.executable.replace("\\", "/"),
                                          lora=LORA.replace("\\", "/"), port=base + n, bitrate=bitrate))
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

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def run_test(self):
        miner, radio = self.nodes

        self.log.info("the two share no peer-to-peer link")
        assert_equal(miner.getpeerinfo(), [])
        assert_equal(radio.getpeerinfo(), [])

        self.log.info("the miner builds a short chain; the radio node stays at genesis")
        miner.generatetoaddress(6, miner.getnewaddress())
        assert_equal(miner.getblockcount(), 6)
        assert_equal(radio.getblockcount(), 0)

        self.log.info("start the radio between them")
        self.start_radio()
        try:
            self.wait_until(lambda: any(p["key"] == self.key(0) for p in radio.getradioinfo()["neighbours"]), timeout=180)
            self.log.info("the radio node hears the miner and sees it is ahead")
            self.wait_until(lambda: any(nb["key"] == self.key(0) and nb["height"] == 6
                                        for nb in radio.getchainfeedinfo()["neighbours"]), timeout=180)

            self.log.info("it follows the chain over the radio to the miner's tip")
            self.wait_until(lambda: radio.getblockcount() == 6, timeout=300)
            assert_equal(radio.getbestblockhash(), miner.getbestblockhash())

            self.log.info("and keeps up as the miner extends it")
            miner.generatetoaddress(3, miner.getnewaddress())
            self.wait_until(lambda: radio.getblockcount() == 9, timeout=300)
            assert_equal(radio.getbestblockhash(), miner.getbestblockhash())
            # The roster index on the radio node followed the blocks it took.
            assert_equal(radio.getrosterinfo()["best_block_height"], 9)
        finally:
            self.stop_radio()


if __name__ == '__main__':
    RadioBlocksTest().main()
