Radio links through Reticulum
=============================

BPS's overlay - the encrypted network that carries mail and listing requests -
can run over radio as well as the internet, through
[Reticulum](https://reticulum.network/). Reticulum handles the radio side:
LoRa through an RNode, packet radio modems, serial links, and more. A node
with no internet can then reach the overlay through a radio neighbour that
has it.

How it fits together
--------------------

- `bps-rns-bridge.py`, in this directory, runs beside the node. It announces
  the node on Reticulum, hears other BPS nodes announce themselves, and gives
  each one a local UDP port on 127.0.0.1. Whatever the node sends to that port
  goes to that neighbour over a Reticulum link, split into packets that fit
  (431 bytes each) and joined again on the far side.
- The node, started with `-overlay -radio`, reads the neighbours the bridge
  reports (`radio/peers.json` in its data directory) and tells the bridge
  where its overlay listens (`radio/node.json`).
- When a neighbour is a relay listed in the roster, it becomes the entry of
  this node's paths (`-radioentry`, on by default): mail and listing requests
  go to it over the radio, and on from there over the internet.

The overlay's own encryption and handshake run end to end through the bridge,
which never sees inside what it carries. A neighbour that is not who it
announced cannot answer the handshake.

Setting it up
-------------

1. Install Python 3 and Reticulum: `pip install rns`. Reticulum is not part of
   BPS, is not shipped with it, and has its own licence.
2. Set up your radio in Reticulum's configuration, `~/.reticulum/config`. For
   an RNode on a USB port, for example:

   ```
   [interfaces]
     [[RNode LoRa]]
       type = RNodeInterface
       enabled = yes
       port = /dev/ttyUSB0
       frequency = 868000000
       bandwidth = 125000
       txpower = 14
       spreadingfactor = 8
       codingrate = 5
   ```

   Use the frequency, power and duty cycle your country allows.
   `rnstatus` shows whether the interface is up.
3. In BPS Relay: Settings, Radio, tick "Carry the overlay over radio too", and
   restart. BPS Relay starts the bridge itself. With the node alone, start it
   with `-overlay -radio` and run:

   ```
   python3 bps-rns-bridge.py --datadir ~/.bitcoinpos
   ```

   (the data directory of the network you run, e.g. `.../testnet3` for testnet).
4. Node, Overlay in BPS Relay, or `getradioinfo`, lists the BPS nodes heard.

Things to know
--------------

- **Radio is slow, and the node waits accordingly.** A LoRa link moves a few
  hundred bytes a second, and an overlay message is up to 1200. The bridge
  tells the node how fast each neighbour's radio is, and the node stretches
  every wait on a radio hop to match, so the slowest LoRa settings work too.
- **Airtime is shared and limited.** Each node announces itself every half
  hour, and once more soon after it hears a newcomer. Many countries limit how
  much of the time a LoRa transmitter may send - in Europe's 868 MHz band, 1%
  on most of it (36 seconds an hour) and 10% on 869.4-869.65 MHz. Reticulum's
  RNode settings `airtime_limit_short` and `airtime_limit_long` are where that
  is enforced. The figures below show why it matters: one short letter can use
  a whole hour's 1%.
- **Lost packets are expected.** The node retries, and the bridge restarts a
  radio link whose setup lost a packet. Tested with a tenth of all packets
  lost.

How long things take
--------------------

Measured on a simulated LoRa channel (the one `test/functional/feature_radio.py`
uses, `test/functional/test_framework/lora.py`) with real LoRa airtime, two
nodes in range, nothing lost unless stated. "Airtime" is what the node
without the internet sent itself.

| Setting | Speed | What | Took | Airtime |
|---|---|---|---|---|
| SF8, 125 kHz | 3.1 kbit/s | ask a relay to list you | 5 s | 3 s |
| SF8, 125 kHz | 3.1 kbit/s | the same, through a repeater | 10 s | 3 s |
| SF8, 125 kHz | 3.1 kbit/s | the same, 10% of packets lost | 11 s | 4 s |
| SF10, 125 kHz | 1 kbit/s | ask a relay to list you | 16 s | 9 s |
| SF12, 125 kHz | 0.3 kbit/s | ask a relay to list you | 86 s | 45 s |
| SF8, 125 kHz | 3.1 kbit/s | leave your mail key at your 3 mailboxes | 94 s | 59 s |
| SF8, 125 kHz | 3.1 kbit/s | send a short letter (to 3 mailboxes) | 57 s | 36 s |
| SF8, 125 kHz | 3.1 kbit/s | the same, 5% of packets lost | 122 s | 61 s |
| SF8, 125 kHz | 3.1 kbit/s | collect a letter from 3 mailboxes | 86 s | 35 s |
| SF10, 125 kHz | 1 kbit/s | leave your mail key at your 3 mailboxes | 213 s | 134 s |
| SF10, 125 kHz | 1 kbit/s | send a short letter (to 3 mailboxes) | 100 s | 62 s |
| SF10, 125 kHz | 1 kbit/s | collect a letter from 3 mailboxes | 203 s | 81 s |

Mail is the heavy part: every letter goes to three mailboxes, each through its
own path of three relays, and every step of every path crosses the radio. Use
the fastest setting your range allows, and the 10% sub-band in Europe.

Repeaters
---------

Reticulum carries traffic across nodes that relay for others ("transport
nodes"), so a radio in a high place extends everyone's range. A repeater does
not need BPS at all: a small computer with an RNode, running Reticulum with

```
[reticulum]
  enable_transport = yes
```

in its configuration (and `rnsd` to keep it running), passes BPS traffic on
without being able to read it - the overlay's encryption runs end to end
through it. Neighbours heard through a repeater show 2 hops on the Overlay
page. Each repeater sends everything again on the same channel, so a path
through one has half the speed and uses twice the airtime.

A GPS module or antenna cannot do this job: GPS satellites only send, a GPS
receiver only listens, and a GPS antenna is built to receive on 1575 MHz, not
to transmit on LoRa's bands.
- **Ham radio bands are out.** Amateur licences in most countries forbid
  encrypted traffic, and everything the overlay sends is encrypted. Use
  licence-free bands, such as LoRa's.
- **Someone on the radio needs the internet.** The radio replaces the first
  hop only. Mailboxes and the other relays are reached over the internet from
  the radio neighbour, so two nodes with only radio between them cannot mail
  each other yet.
