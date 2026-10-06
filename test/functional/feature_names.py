#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test names: registering, burning, renewing, subnames, petnames, transfer.

Design note 001 section 11. Two nodes with the name index; node 0 pays.

What the test is really about:

  * a name is registered in two steps blocks apart - a commitment that hides
    it, then a claim the node sends on its own once the commitment is old
    enough - so nobody watching the mempool can take it first;

  * its price is burned in the claim itself, where nobody can spend it;

  * every node resolves the name to the same roster key, and a subname and a
    petname resolve too, the petname winning over a name spelled the same;

  * names that are taken, look like taken ones, or are too short are refused
    before anything is spent;

  * a reorg that removes a record takes its effect away with it;

  * a holder can put a name up for sale and anyone can buy it at once, the
    seller offline: one transaction pays the seller, burns the renewal and
    moves the name, and while it is for sale the seller cannot give it away.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

COMMIT_MIN_AGE = 6
BLOCKS_PER_YEAR = 175320
MAX_TERM = 2 * BLOCKS_PER_YEAR
SALE_COIN = Decimal("0.0001")


def burn_for(per_year, blocks):
    """What `blocks` of a name costs, pro rata and rounded up to the satoshi."""
    sat = int(per_year * 100000000)
    return Decimal(-(-(sat * blocks) // BLOCKS_PER_YEAR)) / Decimal(100000000)


class NamesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-nameindex", "-fallbackfee=0.0001"] for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def key(self, n):
        return self.nodes[n].getrosterinfo()["operational_key"]

    def mine(self, n=1, sync_mempools=True):
        # Transactions sent from node 1 have to reach node 0, which mines.
        if sync_mempools:
            self.sync_mempools()
        self.nodes[0].generatetoaddress(n, self.address)
        self.sync_all()
        tip = self.nodes[0].getblockcount()
        for node in self.nodes:
            self.wait_until(lambda: node.getnameinfo()["best_block_height"] == tip, timeout=30)

    def finish(self, name):
        """Ask the node to move a registration along, as its scheduler would."""
        return self.nodes[0].registername(name)

    def run_test(self):
        payer, other = self.nodes
        self.address = payer.getnewaddress("", "legacy")
        payer.generatetoaddress(520, self.address)
        self.sync_all()
        self.mine(0)

        self.log.info("the rules and prices are published")
        info = payer.getnameinfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["active"], True)
        assert_equal(info["live_names"], 0)
        assert_equal([p["per_year"] for p in info["prices"]],
                     [Decimal("100"), Decimal("20"), Decimal("5"), Decimal("1")])
        price = payer.getnameprice("Pilot")
        assert_equal(price["name"], "pilot")
        assert_equal(price["price"], Decimal("5"))
        assert_equal(price["available"], True)

        self.log.info("names that cannot be registered are refused before anything is spent")
        assert_raises_rpc_error(-8, "3 to 32", payer.registername, "ab")
        assert_raises_rpc_error(-8, "plain letters", payer.registername, "luigı")
        assert_raises_rpc_error(-8, "years must be 1 or 2", payer.registername, "pilot", 3)
        assert_raises_rpc_error(-6, "costs", other.registername, "pilot")

        self.log.info("registering is commit, then claim")
        reg = payer.registername("pilot")
        assert_equal(reg["status"], "committed")
        assert_equal(reg["price"], Decimal("5"))
        self.mine()
        # Asking again reports progress rather than committing twice.
        assert_equal(self.finish("pilot")["status"], "committed")
        assert_raises_rpc_error(-5, "Nobody holds pilot", other.resolvename, "pilot")
        self.mine(COMMIT_MIN_AGE)
        claimed = self.finish("pilot")
        assert_equal(claimed["status"], "claimed")
        self.mine()
        assert_equal(self.finish("pilot")["status"], "done")

        self.log.info("the price is burned in the claim itself")
        wtx = payer.gettransaction(claimed["claim_txid"], False, True)
        burns = [o for o in wtx["decoded"]["vout"] if o["scriptPubKey"]["type"] == "nulldata"]
        assert_equal(len(burns), 1)
        assert_equal(burns[0]["value"], Decimal("5"))
        # The wallet sees it leave and not come back: an output nobody owns.
        assert_equal(wtx["amount"], Decimal("-5"))
        assert_greater_than(Decimal("0"), wtx["fee"])

        self.log.info("every node resolves it to the holder's roster key")
        for node in self.nodes:
            res = node.resolvename("PILOT")
            assert_equal(res["key"], self.key(0))
            assert_equal(res["source"], "name")
            assert_equal(res["settled"], False)
        held = payer.listnames()
        assert_equal([n["name"] for n in held], ["pilot"])
        assert_equal(held[0]["status"], "live")
        assert_equal(payer.getnameinfo()["live_names"], 1)
        expiry = held[0]["expiry_height"]

        self.log.info("taken names and look-alikes are refused")
        assert_raises_rpc_error(-8, "taken", other.registername, "pilot")
        assert_equal(other.getnameprice("pi1ot")["available"], False)
        assert "looks too much like pilot" in other.getnameprice("pi1ot")["reason"]

        self.log.info("the holder renews by hand, paying for the added year only")
        renewed = payer.renewname("pilot")
        assert_equal(renewed["expiry_height"], expiry + BLOCKS_PER_YEAR)
        assert_equal(renewed["burned"], Decimal("5"))
        self.mine()
        assert_equal(other.resolvename("pilot")["expiry_height"], expiry + BLOCKS_PER_YEAR)
        assert_raises_rpc_error(-8, "at most two years ahead", payer.renewname, "pilot")
        assert_raises_rpc_error(-8, "does not hold", other.renewname, "pilot")

        self.log.info("subnames are free and resolve on every node")
        payer.setsubname("alice.pilot", self.key(1))
        self.mine()
        res = other.resolvename("alice.pilot")
        assert_equal(res["key"], self.key(1))
        assert_equal(res["subname"], True)
        assert_equal(payer.listnames()[0]["subnames"][0]["name"], "alice.pilot")

        self.log.info("a petname is local, and wins over a name spelled the same")
        pinned = other.setpetname("Boss", "pilot")
        assert_equal(pinned["key"], self.key(0))
        assert_equal(other.resolvename("boss")["source"], "petname")
        other.setpetname("pilot", self.key(1))
        assert_equal(other.resolvename("pilot")["source"], "petname")
        assert_equal(other.resolvename("pilot")["key"], self.key(1))
        assert_equal(payer.resolvename("pilot")["key"], self.key(0))
        assert_equal(len(other.listpetnames()), 2)
        assert_equal(other.deletepetname("pilot"), True)
        assert_equal(other.resolvename("pilot")["source"], "name")

        self.log.info("the holder transfers it; a reorg that drops the transfer takes it back")
        transfer = payer.transfername("pilot", self.key(1))["txid"]
        self.mine()
        assert_equal(other.resolvename("pilot")["key"], self.key(1))
        assert_equal([n["name"] for n in other.listnames()], ["pilot"])
        assert_raises_rpc_error(-8, "does not hold", payer.renewname, "pilot")
        # A longer chain without the transfer replaces the block that had it.
        payer.invalidateblock(payer.getbestblockhash())
        payer.prioritisetransaction(transfer, 0, -100 * 100000000)
        self.mine(2, sync_mempools=False)
        assert_equal(other.resolvename("pilot")["key"], self.key(0))
        assert_equal([n["name"] for n in payer.listnames()], ["pilot"])

        self.log.info("pending registrations are listed")
        assert_equal(payer.listnameregistrations()[0]["status"], "done")

        self.test_sale()

    def test_sale(self):
        payer, other = self.nodes
        payer.sendtoaddress(other.getnewaddress("", "legacy"), 50)
        self.mine()

        self.log.info("the holder puts a name up for sale")
        sale = payer.sellname("pilot", 7)
        assert_equal(sale["price"], Decimal("7"))
        self.mine()
        listed = other.listnames("forsale")
        assert_equal([n["name"] for n in listed], ["pilot"])
        assert_equal(listed[0]["for_sale"]["price"], Decimal("7"))
        assert_equal(listed[0]["for_sale"]["state"], "open")
        assert_equal(listed[0]["for_sale"]["pay_to"], sale["pay_to"])

        self.log.info("its price is the renewal plus what the holder asks")
        quote = other.getnameprice("pilot")
        assert_equal(quote["status"], "for sale")
        assert_equal(quote["action"], "buy")
        assert_equal(quote["available"], True)
        assert_equal(quote["asking"], Decimal("7"))
        # pilot is paid almost two years ahead, so the renewal that comes with
        # it only reaches the two-year limit.
        held = payer.listnames()[0]
        nxt = payer.getblockcount() + 1
        expected = burn_for(5, nxt + MAX_TERM - max(held["expiry_height"], nxt))
        assert_equal(quote["renewal"], expected)
        assert_equal(quote["total"], expected + Decimal("7"))

        self.log.info("while it is for sale the seller cannot give it away or put it up again")
        assert_raises_rpc_error(-8, "up for sale", payer.transfername, "pilot", self.key(1))
        assert_raises_rpc_error(-8, "up for sale already", payer.sellname, "pilot", 9)
        assert_raises_rpc_error(-8, "holds pilot already", payer.buyname, "pilot")

        self.log.info("anyone buys it at once: paying and taking the name are one transaction")
        bought = other.buyname("pilot")
        assert_equal(bought["paid"], Decimal("7"))
        assert_equal(bought["burned"], expected)
        assert_equal(other.listnames("forsale")[0]["for_sale"]["state"], "pending")
        self.mine()
        for node in self.nodes:
            assert_equal(node.resolvename("pilot")["key"], self.key(1))
        assert_equal(other.listnames()[0]["expiry_height"], bought["expiry_height"])
        assert_equal(other.listnames("forsale"), [])
        assert_equal(payer.listnames(), [])
        # The buyer gets it clean: the seller's subnames do not come with it.
        assert_raises_rpc_error(-5, "no subname alice", other.resolvename, "alice.pilot")
        # The seller was paid the price, and the coin set aside comes back too.
        assert_equal(payer.getreceivedbyaddress(sale["pay_to"]), Decimal("7") + SALE_COIN)
        txs = other.gettransaction(bought["txid"], False, True)["decoded"]
        burns = [o for o in txs["vout"] if o["scriptPubKey"]["type"] == "nulldata"]
        assert_equal(burns[0]["value"], expected)
        assert_raises_rpc_error(-8, "not for sale", payer.buyname, "pilot")

        self.log.info("a sale is taken off by spending its coin; then the name can move again")
        other.sellname("pilot", 100)
        self.mine()
        assert_equal(payer.getnameprice("pilot")["asking"], Decimal("100"))
        other.cancelnamesale("pilot")
        self.mine()
        assert_equal(other.listnames("forsale"), [])
        assert_equal(payer.getnameprice("pilot")["status"], "held")
        assert_raises_rpc_error(-8, "not for sale", payer.buyname, "pilot")
        other.transfername("pilot", self.key(0))
        self.mine()
        assert_equal(other.resolvename("pilot")["key"], self.key(0))


if __name__ == '__main__':
    NamesTest().main()
