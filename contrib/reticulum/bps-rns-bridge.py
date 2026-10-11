#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Carry a BPS node's overlay over Reticulum: LoRa (RNode), packet radio,
serial links, or anything else Reticulum has an interface for.

Runs beside a node started with -overlay -radio. The node and this bridge
talk through files in the node's data directory and through UDP on
127.0.0.1 only:

  radio/node.json    written by the node: its overlay port, roster key, network
  radio/peers.json   written here: the BPS nodes heard on the radio, each with
                     a local port the node can send overlay datagrams to

Every BPS node this bridge hears announcing itself gets a local UDP port.
What the node sends to that port goes to that node over a Reticulum link,
split to fit (a link packet holds 431 bytes; an overlay datagram up to 1200)
and joined again on the far side, where its bridge hands it to its node as if
it came from a local peer. The overlay's own encryption and handshake run
end to end through this as through anything else: the bridge never sees
what is inside, and a node that is not who it announced cannot answer.

Reticulum is not part of BPS and is not shipped with it; it has its own
licence. Install it with:   pip install rns
and configure its interfaces (an RNode, say) in ~/.reticulum/config as usual.

Usage:  bps-rns-bridge.py --datadir <node data directory for the network>
"""

import argparse
import json
import os
import select
import signal
import socket
import struct
import sys
import threading
import time

try:
    import RNS
except ImportError:
    sys.stderr.write("Reticulum is not installed. Install it with:  pip install rns\n")
    sys.exit(2)

APP_NAME = "bps"
ASPECT = "overlay"
#: Each fragment: message id, its index, and how many there are. A count of
#: zero marks a control message instead, and the index says which.
FRAGMENT_HEADER = struct.Struct("!HBB")
#: Control: "I cannot tell who you are; identify yourself again."
CONTROL_IDENTIFY = 1
#: Packets on a link whose far end has not identified itself yet are held
#: this long, this many at most: the identification can arrive after them, or
#: be lost on the way.
UNIDENTIFIED_TTL = 60
UNIDENTIFIED_MAX = 32
#: How often an unidentified link is asked to identify, and how often such a
#: request is answered.
IDENTIFY_INTERVAL = 5
#: A link that carries datagrams out and brings nothing back for this long
#: (or eight round trips, if longer), plus the airtime of what it was given to
#: send meanwhile, there and back, is started again: a lost packet while
#: setting it up can leave both ends thinking it works when it does not.
SILENCE = 45
#: Airtime per byte handed to Reticulum, against the interface's bit rate:
#: its headers and encryption, and an RNode sending each packet as two.
FRAMING = 1.5
#: Largest datagram passed on; the overlay's are at most 1200 bytes.
MAX_DATAGRAM = 1500
#: Fragments of a datagram not complete by then are dropped; the overlay retries.
REASSEMBLY_TTL = 120
#: peers.json is rewritten at least this often, so the node can tell the bridge is alive.
HEARTBEAT = 10
#: At most this many nodes are kept, each with a local port.
MAX_PEERS = 256


def log(message, level=RNS.LOG_NOTICE):
    RNS.log("[bps] " + message, level)


class Peer:
    """A BPS node heard on the radio, and the local port that stands for it."""

    def __init__(self, destination_hash):
        self.hash = destination_hash
        self.key = b""          # its roster key, from its announce
        self.hops = None
        self.heard = 0
        self.link = None
        self.queue = []          # datagrams waiting for the link
        self.next_id = 0
        self.partial = {}        # message id -> (deadline, count, {index: bytes})
        self.waiting_since = None  # first datagram sent since anything came back
        self.unanswered = 0        # bytes sent since then
        self.last_identify = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]

    def link_up(self):
        return self.link is not None and self.link.status == RNS.Link.ACTIVE


class Bridge:
    def __init__(self, args):
        self.args = args
        self.radio_dir = os.path.join(args.datadir, "radio")
        os.makedirs(self.radio_dir, exist_ok=True)
        self.lock = threading.RLock()
        self.peers = {}          # destination hash -> Peer
        self.links = {}          # link id -> Peer, for links others opened to us
        self.unidentified = {}   # link id -> what came on it before it identified
        self.node = None         # what the node wrote in node.json
        self.running = True
        self.changed = True
        self.last_write = 0
        self.last_announce = 0
        self.announce_soon = False

        self.wait_for_node()
        self.network = self.node["network"]
        self.reticulum = RNS.Reticulum(configdir=args.rnsconfig, loglevel=args.loglevel)
        self.identity = self.load_identity()
        self.destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                                           APP_NAME, ASPECT, self.network)
        self.destination.set_link_established_callback(self.inbound_link)
        self.aspect_filter = "%s.%s.%s" % (APP_NAME, ASPECT, self.network)
        RNS.Transport.register_announce_handler(self)
        log("this node is %s on the radio" % RNS.prettyhexrep(self.destination.hash))

    # --- the node's side ---------------------------------------------------

    def read_node(self):
        try:
            with open(os.path.join(self.radio_dir, "node.json"), "r", encoding="utf-8") as f:
                node = json.load(f)
            node["key"] = bytes.fromhex(node["key"])
            if len(node["key"]) != 32 or not 0 < int(node["overlay_port"]) < 65536:
                return None
            return node
        except (OSError, ValueError, KeyError):
            return None

    def wait_for_node(self):
        while True:
            self.node = self.read_node()
            if self.node is not None:
                return
            sys.stderr.write("Waiting for the node: start it with -overlay -radio (no %s yet)\n" %
                             os.path.join(self.radio_dir, "node.json"))
            time.sleep(5)

    def node_addr(self):
        return ("127.0.0.1", int(self.node["overlay_port"]))

    def load_identity(self):
        path = os.path.join(self.radio_dir, "identity")
        if os.path.exists(path):
            identity = RNS.Identity.from_file(path)
            if identity is not None:
                return identity
        identity = RNS.Identity()
        identity.to_file(path)
        return identity

    @staticmethod
    def bitrate_to(destination_hash):
        """Bits a second of the interface the way to a node starts on; 0 if not known."""
        try:
            return int(RNS.Transport.next_hop_interface_bitrate(destination_hash) or 0)
        except Exception:
            return 0

    def write_peers(self, force=False):
        now = time.time()
        with self.lock:
            if not force and not self.changed and now - self.last_write < HEARTBEAT:
                return
            peers = [{
                "key": p.key.hex(),
                "port": p.port,
                "destination": p.hash.hex(),
                "hops": p.hops if p.hops is not None else -1,
                "heard": int(p.heard),
                "link": p.link_up(),
                # So the node can wait as long as this radio needs.
                "bitrate": self.bitrate_to(p.hash),
            } for p in self.peers.values()]
            self.changed = False
            self.last_write = now
        state = {
            "version": 1,
            "network": self.network,
            "destination": self.destination.hash.hex(),
            "updated": int(now),
            "interfaces": [str(i) for i in RNS.Transport.interfaces],
            "peers": peers,
        }
        path = os.path.join(self.radio_dir, "peers.json")
        tmp = path + ".new"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=1)
        os.replace(tmp, path)

    # --- announces -----------------------------------------------------------

    def announce(self):
        # The roster key, so a node hearing this knows who to expect at the
        # end of the handshake. Unsigned: the handshake is the proof.
        self.destination.announce(app_data=self.node["key"])
        self.last_announce = time.time()
        self.announce_soon = False
        log("announced", RNS.LOG_VERBOSE)

    def received_announce(self, destination_hash, announced_identity, app_data):
        if destination_hash == self.destination.hash:
            return
        if app_data is None or len(app_data) != 32:
            return
        with self.lock:
            peer = self.peers.get(destination_hash)
            if peer is None:
                if len(self.peers) >= MAX_PEERS:
                    return
                peer = Peer(destination_hash)
                self.peers[destination_hash] = peer
                # A newcomer missed our last announce; answer it soon rather
                # than leave it waiting for the next one.
                self.announce_soon = True
                log("heard %s (roster key %s...)" % (RNS.prettyhexrep(destination_hash), app_data.hex()[:16]))
            peer.key = bytes(app_data)
            peer.heard = time.time()
            peer.hops = RNS.Transport.hops_to(destination_hash)
            self.changed = True

    # --- links ---------------------------------------------------------------

    def inbound_link(self, link):
        # Who opened it is known only once it identifies itself.
        link.set_remote_identified_callback(self.link_identified)
        link.set_packet_callback(lambda data, packet, link=link: self.from_link(link, data))
        link.set_link_closed_callback(self.link_closed)

    def link_identified(self, link, identity):
        destination_hash = RNS.Destination.hash(identity, APP_NAME, ASPECT, self.network)
        with self.lock:
            peer = self.peers.get(destination_hash)
            if peer is None:
                peer = Peer(destination_hash)
                self.peers[destination_hash] = peer
            peer.heard = time.time()
            if not peer.link_up():
                peer.link = link
            self.links[link.link_id] = peer
            self.changed = True
            held = self.unidentified.pop(link.link_id, None)
        # What arrived before the identification, in the order it came.
        for data in (held["held"] if held else []):
            self.from_link(link, data)

    def outbound_link(self, peer):
        identity = RNS.Identity.recall(peer.hash)
        if identity is None:
            RNS.Transport.request_path(peer.hash)
            return
        destination = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                                      APP_NAME, ASPECT, self.network)
        link = RNS.Link(destination, established_callback=self.link_established,
                        closed_callback=self.link_closed)
        link.set_packet_callback(lambda data, packet, link=link: self.from_link(link, data))
        peer.link = link
        self.links[link.link_id] = peer

    def link_established(self, link):
        link.identify(self.identity)
        with self.lock:
            peer = self.links.get(link.link_id)
            if peer is None:
                return
            queued, peer.queue = peer.queue, []
            self.changed = True
        for datagram in queued:
            self.send(peer, datagram)

    def link_closed(self, link):
        with self.lock:
            peer = self.links.pop(link.link_id, None)
            self.unidentified.pop(link.link_id, None)
            if peer is not None and peer.link is link:
                peer.link = None
                peer.waiting_since = None
                peer.unanswered = 0
            self.changed = True

    def send_control(self, link, kind):
        RNS.Packet(link, FRAGMENT_HEADER.pack(0, kind, 0)).send()

    def control(self, link, kind):
        if kind != CONTROL_IDENTIFY or not link.initiator:
            return
        # The far end lost our identification (or it has not reached it yet):
        # say again who we are, at most every few seconds.
        with self.lock:
            peer = self.links.get(link.link_id)
            now = time.time()
            if peer is None or now - peer.last_identify < IDENTIFY_INTERVAL:
                return
            peer.last_identify = now
        log("identifying again to %s" % RNS.prettyhexrep(peer.hash), RNS.LOG_VERBOSE)
        link.identify(self.identity)

    def hold(self, link, data):
        """Keep what came on a link that has not said who it is yet; expire() asks."""
        entry = self.unidentified.get(link.link_id)
        if entry is None:
            if len(self.unidentified) >= MAX_PEERS:
                return
            # Not asked at once: the identification is usually just behind,
            # since each packet is handled on a thread of its own.
            now = time.time()
            entry = self.unidentified[link.link_id] = {"link": link, "since": now, "asked": now, "held": []}
        if len(entry["held"]) < UNIDENTIFIED_MAX:
            entry["held"].append(data)

    # --- datagrams -----------------------------------------------------------

    def to_radio(self, peer, datagram):
        with self.lock:
            if not peer.link_up():
                # Kept until the link is up; a few only, as the overlay retries.
                peer.queue = (peer.queue + [datagram])[-8:]
                if peer.link is None or peer.link.status == RNS.Link.CLOSED:
                    self.outbound_link(peer)
                return
        self.send(peer, datagram)

    def send(self, peer, datagram):
        link = peer.link
        if link is None:
            return
        chunk = link.get_mdu() - FRAGMENT_HEADER.size
        parts = [datagram[i:i + chunk] for i in range(0, len(datagram), chunk)] or [b""]
        if len(parts) > 255:
            return
        with self.lock:
            message_id = peer.next_id
            peer.next_id = (peer.next_id + 1) & 0xFFFF
            if peer.waiting_since is None:
                peer.waiting_since = time.time()
            peer.unanswered += len(datagram)
        for index, part in enumerate(parts):
            RNS.Packet(link, FRAGMENT_HEADER.pack(message_id, index, len(parts)) + part).send()

    def from_link(self, link, data):
        if len(data) < FRAGMENT_HEADER.size:
            return
        message_id, index, count = FRAGMENT_HEADER.unpack_from(data)
        if count == 0:
            self.control(link, index)
            return
        if index >= count:
            return
        with self.lock:
            peer = self.links.get(link.link_id)
            if peer is None:
                self.hold(link, data)
                return
            peer.heard = time.time()
            peer.waiting_since = None
            peer.unanswered = 0
            deadline, total, parts = peer.partial.get(message_id, (time.time() + REASSEMBLY_TTL, count, {}))
            if total != count:
                return
            parts[index] = data[FRAGMENT_HEADER.size:]
            if len(parts) < count:
                peer.partial[message_id] = (deadline, count, parts)
                return
            peer.partial.pop(message_id, None)
            datagram = b"".join(parts[i] for i in range(count))
        if len(datagram) <= MAX_DATAGRAM:
            peer.sock.sendto(datagram, self.node_addr())

    def expire(self):
        now = time.time()
        ask, silent = [], []
        with self.lock:
            for peer in self.peers.values():
                for message_id in [m for m, (deadline, _, _) in peer.partial.items() if deadline < now]:
                    del peer.partial[message_id]
                link = peer.link
                if peer.waiting_since is not None and link is not None and link.status == RNS.Link.ACTIVE:
                    # A long message on a slow radio is still going out, not lost.
                    airtime = 2 * peer.unanswered * 8 * FRAMING / (self.bitrate_to(peer.hash) or 1000)
                    if now - peer.waiting_since > max(SILENCE, 8 * (link.rtt or 0)) + airtime:
                        silent.append((peer, link))
            for link_id, entry in list(self.unidentified.items()):
                if now - entry["since"] > UNIDENTIFIED_TTL:
                    del self.unidentified[link_id]
                elif now - entry["asked"] >= IDENTIFY_INTERVAL:
                    entry["asked"] = now
                    ask.append(entry["link"])
        for link in ask:
            self.send_control(link, CONTROL_IDENTIFY)
        for peer, link in silent:
            # Started again on the next datagram for it.
            log("nothing back from %s over its link; starting the link again" % RNS.prettyhexrep(peer.hash))
            link.teardown()

    # --- loops ---------------------------------------------------------------

    def pump(self):
        """Datagrams from the node, on each peer's local port, out to the radio."""
        while self.running:
            with self.lock:
                socks = {p.sock: p for p in self.peers.values()}
            if not socks:
                time.sleep(0.2)
                continue
            ready, _, _ = select.select(list(socks), [], [], 0.5)
            for sock in ready:
                try:
                    datagram, source = sock.recvfrom(MAX_DATAGRAM + 1)
                except OSError:
                    continue
                # Only the node may use the radio through these ports.
                if source != self.node_addr() or len(datagram) > MAX_DATAGRAM:
                    continue
                self.to_radio(socks[sock], datagram)

    def run(self):
        threading.Thread(target=self.pump, daemon=True).start()
        self.announce()
        next_announce = time.time() + self.args.announce_interval
        while self.running:
            time.sleep(1)
            node = self.read_node()
            if node is not None and node != self.node:
                if node.get("network") != self.network:
                    log("the node switched networks; restart the bridge", RNS.LOG_ERROR)
                    self.running = False
                    break
                self.node = node
                self.announce()
            if time.time() >= next_announce or (self.announce_soon and time.time() - self.last_announce >= 60):
                self.announce()
                next_announce = time.time() + self.args.announce_interval
            self.expire()
            self.write_peers()

    def stop(self, *_):
        self.running = False


def main():
    parser = argparse.ArgumentParser(description="Carry a BPS node's overlay over Reticulum.")
    parser.add_argument("--datadir", required=True,
                        help="the node's data directory for its network (where radio/node.json is)")
    parser.add_argument("--rnsconfig", default=None, help="Reticulum's configuration directory (default ~/.reticulum)")
    parser.add_argument("--announce-interval", type=int, default=1800,
                        help="seconds between announces (default 1800; radio time is scarce)")
    parser.add_argument("--loglevel", type=int, default=RNS.LOG_NOTICE, help="Reticulum's log level")
    args = parser.parse_args()
    # A line at a time, so a log file shows what is happening as it happens.
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
    bridge = Bridge(args)
    signal.signal(signal.SIGINT, bridge.stop)
    signal.signal(signal.SIGTERM, bridge.stop)
    bridge.run()
    bridge.write_peers(force=True)


if __name__ == "__main__":
    main()
