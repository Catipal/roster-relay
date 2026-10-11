#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A pretend LoRa channel, for testing the overlay over Reticulum without radios.

Run as a program, in one of two modes:

  lora.py channel --base PORT --stations N [--links 0-1,1-2] [--sf 8] [--loss 0.1]
      The air. Station i is whatever connects to TCP port base+i. A frame a
      station sends goes on the air in turn - one transmitter at a time, as
      LoRa's listen-before-talk gives - takes as long as LoRa would take to send
      it, and reaches only the stations that hear the sender, each copy lost
      with the given probability. Frames are HDLC-framed, as Reticulum sends
      them; an RNode carries at most 254 bytes in one LoRa packet, so a longer
      Reticulum packet costs two.

  lora.py pipe PORT
      Joins stdin and stdout to TCP port PORT, so a Reticulum PipeInterface can
      be a station. (Its TCP interface cannot: told it runs at LoRa's speed, it
      picks no hardware MTU and fails on every frame.)

A Reticulum configuration for a station, with the speed LoRa would report:

  [[LoRa]]
    type = PipeInterface
    command = python3 lora.py pipe PORT
    bitrate = <lora.py bitrate --sf 8>
"""

import argparse
import json
import math
import os
import queue
import random
import socket
import sys
import threading
import time

FLAG, ESC = 0x7E, 0x7D


def unescaped_len(data):
    return len(data) - data.count(bytes([ESC]))


def lora_packet_airtime(payload, sf, bw, cr):
    """Semtech's time-on-air formula: explicit header, CRC on, an RNode's 18-symbol preamble."""
    tsym = (2 ** sf) / bw
    de = 1 if tsym > 0.016 else 0
    symbols = 8 + max(math.ceil((8 * payload - 4 * sf + 44) / (4 * (sf - 2 * de))) * (cr + 4), 0)
    return (18 + 4.25) * tsym + symbols * tsym


def frame_airtime(n, sf, bw, cr):
    t = 0.0
    while n > 0:
        part = min(n, 254)
        t += lora_packet_airtime(part + 1, sf, bw, cr)
        n -= part
    return t


def bitrate(sf, bw, cr):
    return int(sf * (bw / 2 ** sf) * (4 / (4 + cr)))


class Channel:
    def __init__(self, args):
        self.args = args
        self.random = random.Random(args.seed)
        self.hears = {i: set() for i in range(args.stations)}
        links = args.links or ",".join("%d-%d" % (a, b) for a in range(args.stations)
                                       for b in range(a + 1, args.stations))
        for pair in links.split(","):
            a, b = (int(x) for x in pair.split("-"))
            self.hears[a].add(b)
            self.hears[b].add(a)
        self.conns = {}
        self.lock = threading.Lock()
        self.air = queue.Queue()
        self.stats = {i: {"frames": 0, "bytes": 0, "airtime": 0.0, "lost": 0} for i in range(args.stations)}

    def listen(self, station):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.args.base + station))
        srv.listen(1)
        while True:
            conn, _ = srv.accept()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self.lock:
                old, self.conns[station] = self.conns.get(station), conn
            if old is not None:
                old.close()
            threading.Thread(target=self.receive, args=(station, conn), daemon=True).start()

    def receive(self, station, conn):
        buf = b""
        while True:
            try:
                data = conn.recv(4096)
            except OSError:
                return
            if not data:
                return
            buf += data
            while True:
                start = buf.find(bytes([FLAG]))
                end = buf.find(bytes([FLAG]), start + 1) if start >= 0 else -1
                if end < 0:
                    buf = buf[start:] if start >= 0 else b""
                    break
                frame, buf = buf[start + 1:end], buf[end:]
                if frame:
                    self.air.put((station, frame))

    def transmit(self):
        while True:
            station, frame = self.air.get()
            airtime = frame_airtime(unescaped_len(frame), self.args.sf, self.args.bw, self.args.cr)
            time.sleep(airtime)
            with self.lock:
                s = self.stats[station]
                s["frames"] += 1
                s["bytes"] += unescaped_len(frame)
                s["airtime"] += airtime
                targets = [self.conns.get(t) for t in sorted(self.hears[station])]
                lost = [self.random.random() < self.args.loss for _ in targets]
                s["lost"] += sum(lost)
            for conn, drop in zip(targets, lost):
                if conn is not None and not drop:
                    try:
                        conn.sendall(bytes([FLAG]) + frame + bytes([FLAG]))
                    except OSError:
                        pass

    def run(self):
        for i in range(self.args.stations):
            threading.Thread(target=self.listen, args=(i,), daemon=True).start()
        threading.Thread(target=self.transmit, daemon=True).start()
        while True:
            time.sleep(1)
            if self.args.stats:
                with self.lock:
                    text = json.dumps({"stations": self.stats})
                with open(self.args.stats + ".new", "w", encoding="utf-8") as f:
                    f.write(text)
                os.replace(self.args.stats + ".new", self.args.stats)


def pipe(port):
    s = socket.create_connection(("127.0.0.1", port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def down():
        while True:
            data = s.recv(4096)
            if not data:
                os._exit(0)
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    threading.Thread(target=down, daemon=True).start()
    while True:
        data = os.read(0, 4096)
        if not data:
            os._exit(0)
        s.sendall(data)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="mode", required=True)
    c = sub.add_parser("channel")
    c.add_argument("--base", type=int, required=True)
    c.add_argument("--stations", type=int, required=True)
    c.add_argument("--links", default="", help="who hears whom, e.g. 0-2,2-1 (default: everyone)")
    for q in (c, sub.add_parser("bitrate")):
        q.add_argument("--sf", type=int, default=8, help="spreading factor")
        q.add_argument("--bw", type=int, default=125000, help="bandwidth, Hz")
        q.add_argument("--cr", type=int, default=1, help="coding rate 4/(4+cr)")
    c.add_argument("--loss", type=float, default=0.0, help="chance each copy of a frame is lost")
    c.add_argument("--seed", type=int, default=1)
    c.add_argument("--stats", default="", help="file to keep each station's airtime in")
    sub.add_parser("pipe").add_argument("port", type=int)
    args = p.parse_args()
    if args.mode == "channel":
        Channel(args).run()
    elif args.mode == "bitrate":
        print(bitrate(args.sf, args.bw, args.cr))
    else:
        pipe(args.port)


if __name__ == "__main__":
    main()
