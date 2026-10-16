#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the chain-anchored peer roster: index, publishing, expiry and reorg.

The roster stores signed peer records in OP_RETURN outputs and indexes them, so
that every node derives the same live peer set from the chain rather than from a
directory server. This exercises the parts that only ever get checked by hand.

Four things here are worth stating, because they are the behaviours most likely
to rot without a test watching them:

  * signing is separate from paying. A record is signed by the announcing node's
    operational key, which lives in roster.key and is deliberately not a wallet
    key, and it stays valid no matter who funds the transaction carrying it.
    A peer with no coins at all can therefore be listed by somebody else - the
    property the whole listing model rests on.

  * expiry is judged against the block a record CONFIRMS in, not against the tip
    it was built on. Those differ by however long the record sits in the mempool,
    and getting it wrong makes near-boundary records fail silently.

  * the checks that can reject a record all run before a coin is spent, so a
    rejected publish costs the payer nothing. Each failing case below asserts the
    balance is untouched, not merely that an error was raised.

  * writing a block into the index is idempotent, so a reorg that disconnects and
    reconnects a block leaves exactly one copy of its records.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

# src/roster/record.h
MIN_TTL = 14400
MAX_TTL = 175320
# src/rpc/roster.cpp
DEFAULT_CONFIRM_MARGIN = 144
# src/consensus/consensus.h - this fork matures coinbases at 500, not 100.
COINBASE_MATURITY = 500

# RFC5737 documentation space: a legal endpoint to publish, but not routable,
# so the address manager will not take it. Used wherever the test only needs a
# record to exist.
IPV4_ENDPOINT = {"network": "ipv4", "address": "203.0.113.7", "port": 9345}
# Ordinary public space, for the one test that checks an address really lands.
ROUTABLE_ENDPOINT = {"network": "ipv4", "address": "51.68.204.11", "port": 9345}
# roster/peers.h
ROSTER_PEERS_INTERVAL_SECONDS = 30 * 60
ONION_ENDPOINT = {
    "network": "onion",
    "address": "1122334455667788990011223344556677889900112233445566778899001122",
    "port": 9345,
}
# Three onion endpoints - near the largest legal record, and the case that needs
# the datacarrier limit raised above Bitcoin's 83.
BIG_ENDPOINTS = [
    {"network": "onion", "address": ("%02x" % n) * 32, "port": 9345}
    for n in (0xaa, 0xbb, 0xcc)
]


class RosterTest(BitcoinTestFramework):
    def set_test_params(self):
        # Two nodes so that "signs" and "pays" can be genuinely different
        # parties: node1 announces itself, node0 pays to publish it.
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-rosterindex", "-fallbackfee=0.0001"],
            ["-rosterindex", "-fallbackfee=0.0001"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # helpers

    def roster_keys(self, node=None):
        node = node or self.nodes[0]
        return [entry["key"] for entry in node.getroster()]

    def wait_for_index(self, node=None):
        """Wait until the roster index has caught up with the node's tip.

        The index follows the chain on its own thread, so reading it the
        instant a block lands races - and loses on a slower machine.
        """
        node = node or self.nodes[0]
        self.wait_until(lambda: node.getrosterinfo()["best_block_height"] == node.getblockcount(),
                        timeout=30)

    def publish(self, record, payer=None):
        """Publish a record and confirm it, returning the entry the index kept."""
        payer = payer if payer is not None else self.nodes[0]
        txid = payer.publishrecord(record["hex"])["txid"]
        self.last_txid = txid
        assert txid in payer.getrawmempool()
        self.nodes[0].generatetoaddress(1, self.sink)
        self.sync_all()
        self.wait_for_index()
        matches = [e for e in self.nodes[0].getroster() if e["key"] == record["key"]]
        assert_equal(len(matches), 1)
        return matches[0]

    def assert_costs_nothing(self, expected_error_fragment, record_hex):
        """A publish that is refused must not move a single coin."""
        before = self.nodes[0].getbalance()
        assert_raises_rpc_error(
            -8, expected_error_fragment, self.nodes[0].publishrecord, record_hex
        )
        assert_equal(self.nodes[0].getrawmempool(), [])
        assert_equal(self.nodes[0].getbalance(), before)

    # tests

    def test_index_reports_itself(self):
        self.log.info("getrosterinfo reports the index and the constants it enforces")
        info = self.nodes[0].getrosterinfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["min_ttl"], MIN_TTL)
        assert_equal(info["max_ttl"], MAX_TTL)
        assert_equal(info["live_peers"], 0)
        # The operational key exists without the wallet being involved at all.
        assert_equal(len(info["operational_key"]), 64)

    def test_roundtrip(self):
        self.log.info("a record survives create -> publish -> confirm -> query")
        record = self.nodes[0].createannouncement({"endpoints": [IPV4_ENDPOINT]})
        assert_equal(record["key"], self.nodes[0].getrosterinfo()["operational_key"])
        # Default expiry leaves room for the record to confirm after the tip it
        # was built against; without that margin it would be invalid by one block.
        tip = self.nodes[0].getblockcount()
        assert_equal(record["expiry_height"], tip + MIN_TTL + DEFAULT_CONFIRM_MARGIN)

        entry = self.publish(record)
        assert_equal(entry["type"], "announce")
        assert_equal(entry["height"], self.nodes[0].getblockcount())
        assert_equal(entry["dialable"], True)
        assert_equal(entry["endpoints"], [IPV4_ENDPOINT])
        assert_equal(entry["prev_height"], 0)  # first record for this key
        assert_equal(self.nodes[0].getrosterinfo()["live_peers"], 1)

    def test_signing_is_separate_from_paying(self):
        self.log.info("node1 signs its own record and node0 pays to publish it")
        # node1 has never received a coin.
        assert_equal(self.nodes[1].getbalance(), 0)
        record = self.nodes[1].createannouncement({"endpoints": [ONION_ENDPOINT]})
        assert record["key"] != self.nodes[0].getrosterinfo()["operational_key"]

        entry = self.publish(record, payer=self.nodes[0])

        # The listing belongs to node1; the coins came from node0. Comparing
        # balances would not show this - mining the record in also pays a
        # coinbase - so ask each wallet whether the funding transaction is its
        # own, which is the question actually being posed.
        assert_equal(entry["key"], record["key"])
        assert_equal(entry["endpoints"][0]["network"], "onion")
        funding = self.nodes[0].gettransaction(self.last_txid)
        assert_greater_than(0, Decimal(funding["fee"]))  # node0 paid, so negative
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id",
                                self.nodes[1].gettransaction, self.last_txid)
        assert_equal(self.nodes[1].getbalance(), 0)
        # Both nodes derive the same roster from the same chain.
        assert_equal(sorted(self.roster_keys(self.nodes[0])),
                     sorted(self.roster_keys(self.nodes[1])))

    def test_renewal_chains_to_the_previous_record(self):
        self.log.info("a renewal points back at the record it replaces")
        first = [e for e in self.nodes[0].getroster()
                 if e["key"] == self.nodes[0].getrosterinfo()["operational_key"]][0]
        renewal = self.nodes[0].createannouncement({"endpoints": [IPV4_ENDPOINT]})
        entry = self.publish(renewal)

        assert_equal(entry["prev_height"], first["height"])
        # The roster keeps one live entry per key, not two.
        assert_equal(self.roster_keys().count(entry["key"]), 1)
        # But the history keeps both.
        history = self.nodes[0].getrosterhistory(entry["key"])
        assert_greater_than(len(history), 1)
        assert_equal(history[0]["height"], first["height"])

    def test_expiry_bounds_are_enforced(self):
        self.log.info("expiry below the floor or above the ceiling is refused at build time")
        # Rejected while building, so an unpublishable record is never handed
        # out in the first place. The bounds are measured from the block the
        # record could confirm in - one past the tip - not from the tip.
        confirm_at = self.nodes[0].getblockcount() + 1
        for bad in [confirm_at + MIN_TTL - 1, confirm_at + MAX_TTL + 1]:
            assert_raises_rpc_error(
                -8, "out of range", self.nodes[0].createannouncement,
                {"expiry_height": bad, "endpoints": [IPV4_ENDPOINT]})

    def test_record_that_went_stale_is_refused_at_publish(self):
        self.log.info("a record held too long before publishing is refused, and costs nothing")
        # Valid when built, with the default 144 blocks of room to confirm.
        record = self.nodes[0].createannouncement({"endpoints": [IPV4_ENDPOINT]})
        # Sit on it for longer than that room allows: the expiry is fixed, so
        # the gap to the confirming block shrinks below the floor.
        self.nodes[0].generatetoaddress(DEFAULT_CONFIRM_MARGIN + 50, self.sink)
        self.sync_all()
        self.assert_costs_nothing("out of range", record["hex"])

    def test_expiry_is_measured_from_the_confirming_block(self):
        self.log.info("the boundary is judged against the confirming block, not the tip")
        # Exactly MIN_TTL ahead of the block this will confirm in: legal, and the
        # tightest record the chain accepts. Built against the tip it would look
        # one block short, which is the bug this pins down.
        confirm_at = self.nodes[0].getblockcount() + 1
        record = self.nodes[0].createannouncement(
            {"expiry_height": confirm_at + MIN_TTL, "endpoints": [IPV4_ENDPOINT]})
        entry = self.publish(record)
        assert_equal(entry["height"], confirm_at)
        assert_equal(entry["expiry_height"], confirm_at + MIN_TTL)

    def test_garbage_is_refused_before_spending(self):
        self.log.info("malformed input costs the payer nothing")
        self.assert_costs_nothing("not valid hexadecimal", "nothexatall")
        # Well-formed hex that is not a record.
        self.assert_costs_nothing("does not parse", "00" * 120)
        # A real record with one byte of its signature flipped.
        record = self.nodes[0].createannouncement({"endpoints": [IPV4_ENDPOINT]})
        tampered = record["hex"][:-2] + ("00" if record["hex"][-2:] != "00" else "01")
        self.assert_costs_nothing("does not parse", tampered)

    def test_unimplemented_service_bits_are_refused(self):
        self.log.info("createannouncement refuses to advertise what nothing delivers")
        for bit in ["relay_capable", "rendezvous_only"]:
            assert_raises_rpc_error(
                -8, "not implemented",
                self.nodes[0].createannouncement, {bit: True})

    def test_datacarrier_limit_is_reported_usefully(self):
        self.log.info("a node configured too tightly says so, and spends nothing")
        self.restart_node(0, self.extra_args[0] + ["-datacarriersize=200"])
        # Three onion endpoints is the shape that needs the raised limit: an
        # IPv4 record fits inside Bitcoin's original 83 bytes and would prove
        # nothing here.
        record = self.nodes[0].createannouncement({"endpoints": BIG_ENDPOINTS})
        assert_greater_than(record["size"], 200)
        self.assert_costs_nothing("datacarrier limit", record["hex"])
        self.restart_node(0, self.extra_args[0])
        self.connect_nodes(0, 1)

    def test_reorg_leaves_one_copy(self):
        self.log.info("disconnecting and reconnecting a block does not duplicate it")
        key = self.nodes[0].getrosterinfo()["operational_key"]

        def live_height():
            """Height of the one live record for this key, or None."""
            found = [e for e in self.nodes[0].getroster() if e["key"] == key]
            assert len(found) <= 1, "a key must never hold two live records"
            return found[0]["height"] if found else None

        # live_peers counts keys, so it cannot see a single record appear or
        # vanish for a key that already has one. Track the height instead.
        previous = live_height()
        record = self.nodes[0].createannouncement({"endpoints": [IPV4_ENDPOINT]})
        # Publish into a block of its own so it can be invalidated cleanly.
        self.nodes[0].publishrecord(record["hex"])
        self.nodes[0].generatetoaddress(1, self.sink)
        block_hash = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount()
        # The index follows the chain on its own thread, so each step waits for
        # it rather than reading it the instant the block lands - which raced,
        # and lost on a slower machine. live_height() still checks for a
        # duplicate on every poll.
        self.wait_until(lambda: live_height() == height, timeout=30)
        assert previous != height

        self.nodes[0].invalidateblock(block_hash)
        assert_equal(self.nodes[0].getblockcount(), height - 1)
        # The disconnected record is gone and the key has fallen back to
        # whatever it published before.
        self.wait_until(lambda: live_height() == previous, timeout=30)

        self.nodes[0].reconsiderblock(block_hash)
        assert_equal(self.nodes[0].getblockcount(), height)
        # Back, exactly once - the second write of the same block must not
        # stack a duplicate behind the first.
        self.wait_until(lambda: live_height() == height, timeout=30)
        assert_equal(self.roster_keys().count(key), 1)
        assert_equal(len(self.nodes[0].getrosterhistory(key)),
                     len(set(h["height"] for h in self.nodes[0].getrosterhistory(key))))
        self.log.info("  record height %s -> %s -> %s across the reorg",
                      height, previous, height)

    def test_competing_block_clears_the_old_records(self):
        self.log.info("a reorg onto a different block at the same height drops its records")
        # This is the case the invalidate/reconsider test above cannot reach.
        # BaseIndex::Rewind only moves the locator - it deletes nothing - so
        # records from a disconnected block survive until a new block is written
        # at that height and clears them first. Re-connecting the *same* block
        # overwrites key-for-key and hides the bug; a *different* block with
        # fewer records is what leaves stale entries behind.
        rec_a = self.nodes[0].createannouncement({"endpoints": [IPV4_ENDPOINT]})
        rec_b = self.nodes[1].createannouncement({"endpoints": [ONION_ENDPOINT]})

        self.disconnect_nodes(0, 1)
        self.nodes[0].publishrecord(rec_a["hex"])
        self.nodes[0].publishrecord(rec_b["hex"])
        self.nodes[0].generatetoaddress(1, self.sink)
        forked_height = self.nodes[0].getblockcount()
        losing_hash = self.nodes[0].getbestblockhash()
        self.wait_for_index()

        at_height = [e for e in self.nodes[0].getroster()
                     if e["height"] == forked_height]
        assert_equal(len(at_height), 2)

        # node1 builds a longer chain, carrying no roster records at all.
        self.nodes[1].generatetoaddress(2, self.nodes[1].getnewaddress())
        self.connect_nodes(0, 1)
        self.sync_blocks()

        assert self.nodes[0].getbestblockhash() != losing_hash
        assert_equal(self.nodes[0].getblockcount(), forked_height + 1)
        self.wait_for_index()
        # The losing block's records must be gone, not merely shadowed.
        survivors = [e for e in self.nodes[0].getroster()
                     if e["height"] == forked_height]
        assert_equal(survivors, [])
        for record in (rec_a, rec_b):
            assert_equal([h for h in self.nodes[0].getrosterhistory(record["key"])
                          if h["height"] == forked_height], [])

    def test_deployment_is_addressable_by_name(self):
        self.log.info("the roster deployment can be driven and named without crashing")
        # DEPLOYMENT_ROSTER needs an entry in VersionBitsDeploymentInfo[], or
        # its name is a null pointer. Two places read it and neither is exotic:
        # -vbparams compares against that name at startup, and getblocktemplate
        # builds a std::string from it for any deployment past DEFINED. Both
        # are reached the moment a real activation window is set, which is the
        # first thing scheduling the roster would do - so the crash would land
        # on whoever schedules it, not on whoever added the enum.
        window = ["-vbparams=roster:0:999999999999"]
        self.restart_node(0, self.extra_args[0] + window)
        self.restart_node(1, self.extra_args[1] + window)
        self.connect_nodes(0, 1)
        self.nodes[0].generatetoaddress(300, self.sink)
        self.sync_blocks()

        status = self.nodes[0].getblockchaininfo()["softforks"]["roster"]["bip9"]["status"]
        assert status != "defined", status

        # getblocktemplate refuses outright while the node has no peers, so the
        # reconnect above is load-bearing rather than tidiness.
        template = self.nodes[0].getblocktemplate({"rules": ["segwit"]})
        named = "roster" in template.get("vbavailable", {}) or \
                "roster" in template.get("rules", [])
        assert named, "deployment reached %s without appearing by name" % status

        self.restart_node(0, self.extra_args[0])
        self.restart_node(1, self.extra_args[1])
        self.connect_nodes(0, 1)

    def test_roster_feeds_peer_discovery(self):
        self.log.info("a listed peer reaches the address manager")
        # The point of the roster: a node that reads it learns where to connect.
        # Without this the index is a database nothing consults.
        before = {a["address"] for a in self.nodes[0].getnodeaddresses(0)}
        assert ROUTABLE_ENDPOINT["address"] not in before

        record = self.nodes[1].createannouncement({"endpoints": [ROUTABLE_ENDPOINT]})
        self.publish(record)

        # The top-up runs on a timer; drive it rather than waiting half an hour.
        self.nodes[0].mockscheduler(ROSTER_PEERS_INTERVAL_SECONDS + 1)
        self.wait_until(
            lambda: ROUTABLE_ENDPOINT["address"] in
                    {a["address"] for a in self.nodes[0].getnodeaddresses(0)},
            timeout=30)

        entry = [a for a in self.nodes[0].getnodeaddresses(0)
                 if a["address"] == ROUTABLE_ENDPOINT["address"]][0]
        assert_equal(entry["port"], ROUTABLE_ENDPOINT["port"])
        # Dated by the block that carried the record, not by when it was read -
        # an old announcement must not present itself as fresh.
        tip_time = self.nodes[0].getblock(self.nodes[0].getbestblockhash())["time"]
        assert_greater_than(tip_time + 1, entry["time"])

    def test_documentation_addresses_are_not_offered(self):
        self.log.info("non-routable endpoints are dropped rather than handed over")
        # IPV4_ENDPOINT is in RFC5737 documentation space, which addrman rejects
        # outright (addrman.cpp:264). Publishing one must not put it in the
        # address manager, or the collector's counts would be fiction.
        record = self.nodes[1].createannouncement({"endpoints": [IPV4_ENDPOINT]})
        self.publish(record)
        self.nodes[0].mockscheduler(ROSTER_PEERS_INTERVAL_SECONDS + 1)
        addresses = {a["address"] for a in self.nodes[0].getnodeaddresses(0)}
        assert IPV4_ENDPOINT["address"] not in addresses

    def test_onion_endpoints_reach_the_address_manager(self):
        self.log.info("an onion endpoint is offered, so the private path is not filtered out")
        # "Routable" in IsRoutable() means "usable on the public internet" and
        # excludes LAN, loopback and documentation ranges. It is unrelated to
        # publishing a routed address instead of a real one: CNetAddr::IsRoutable
        # exempts Tor explicitly - (IsRFC4193() && !IsTor()) - so an onion
        # address is never dropped for being unroutable.
        #
        # It IS dropped when the node has no way to dial it, which is a node
        # with no Tor proxy - the default, including here. That is the filter
        # working, not the privacy path being blocked, so the proxy is
        # configured to show the address arriving once dialling is possible.
        # It never has to answer; reachability is a matter of configuration.
        record = self.nodes[1].createannouncement({"endpoints": [ONION_ENDPOINT]})
        self.publish(record)
        self.restart_node(0, self.extra_args[0] + ["-onion=127.0.0.1:9050"])
        self.connect_nodes(0, 1)
        self.nodes[0].mockscheduler(ROSTER_PEERS_INTERVAL_SECONDS + 1)
        self.wait_until(
            lambda: any(a["address"].endswith(".onion")
                        for a in self.nodes[0].getnodeaddresses(0)),
            timeout=30)
        onions = [a for a in self.nodes[0].getnodeaddresses(0)
                  if a["address"].endswith(".onion")]
        assert_equal(onions[0]["port"], ONION_ENDPOINT["port"])
        self.restart_node(0, self.extra_args[0])
        self.connect_nodes(0, 1)

    def test_index_can_be_switched_off(self):
        self.log.info("without -rosterindex the queries refuse rather than lie")
        self.restart_node(0, ["-fallbackfee=0.0001"])
        assert_equal(self.nodes[0].getrosterinfo()["enabled"], False)
        # getrosterinfo still answers, and says the index is off rather than
        # reporting an empty roster - an empty answer would be a lie.
        assert_raises_rpc_error(-32601, "Restart with -rosterindex",
                                self.nodes[0].getroster)
        assert_raises_rpc_error(-32601, "Restart with -rosterindex",
                                self.nodes[0].getrosterhistory, "aa" * 32)
        self.restart_node(0, self.extra_args[0])
        self.connect_nodes(0, 1)

    def test_too_small_a_window_is_refused(self):
        self.log.info("a retention window shorter than a listing's life is refused, pruned or not")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            self.extra_args[0] + ["-rosterindexwindow=1000"],
            "-rosterindexwindow=1000 is below MAX_TTL",
            match=ErrorMatch.PARTIAL_REGEX)
        # A year's worth is accepted.
        self.start_node(0, self.extra_args[0] + ["-rosterindexwindow=%d" % MAX_TTL])
        self.restart_node(0, self.extra_args[0])
        self.connect_nodes(0, 1)

    def test_gateway_records(self):
        self.log.info("a gateway is listed with no endpoint, and never with one")
        # An address beside the gateway bit would publish where an exit is.
        assert_raises_rpc_error(
            -8, "listed with no endpoint",
            self.nodes[1].createannouncement, {"gateway": True, "endpoints": [IPV4_ENDPOINT]})
        record = self.nodes[1].createannouncement({"gateway": True})
        # Not the "offers nowhere to dial" warning: a gateway is met, not dialled.
        assert "warnings" not in record
        entry = self.publish(record)
        assert_equal(entry["gateway"], True)
        assert_equal(entry["dialable"], False)
        assert_equal(entry["endpoints"], [])
        others = [e for e in self.nodes[0].getroster() if e["key"] != record["key"]]
        assert all(not e["gateway"] for e in others)

    def run_test(self):
        node = self.nodes[0]
        self.sink = node.getnewaddress()
        # Coinbases here mature at 500, so fund well past that before spending.
        node.generatetoaddress(COINBASE_MATURITY + 100, node.getnewaddress())
        self.sync_all()
        assert_greater_than(node.getbalance(), 0)

        self.test_index_reports_itself()
        self.test_roundtrip()
        self.test_signing_is_separate_from_paying()
        self.test_renewal_chains_to_the_previous_record()
        self.test_expiry_bounds_are_enforced()
        self.test_record_that_went_stale_is_refused_at_publish()
        self.test_expiry_is_measured_from_the_confirming_block()
        self.test_garbage_is_refused_before_spending()
        self.test_unimplemented_service_bits_are_refused()
        self.test_datacarrier_limit_is_reported_usefully()
        self.test_reorg_leaves_one_copy()
        self.test_competing_block_clears_the_old_records()
        self.test_deployment_is_addressable_by_name()
        self.test_roster_feeds_peer_discovery()
        self.test_documentation_addresses_are_not_offered()
        self.test_onion_endpoints_reach_the_address_manager()
        self.test_index_can_be_switched_off()
        self.test_too_small_a_window_is_refused()
        self.test_gateway_records()


if __name__ == "__main__":
    RosterTest().main()
