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

- **Radio is slow.** A LoRa link moves a few hundred bytes a second, and an
  overlay message is up to 1200. Waits on a path that starts with a radio hop
  are longer (30 seconds a step), and sending a letter takes minutes, not
  seconds.
- **Airtime is shared and limited.** Each node announces itself every half
  hour, and once more soon after it hears a newcomer. Many countries limit how
  much of the time a LoRa transmitter may send; Reticulum's interface settings
  are where that is respected.
- **Ham radio bands are out.** Amateur licences in most countries forbid
  encrypted traffic, and everything the overlay sends is encrypted. Use
  licence-free bands, such as LoRa's.
- **Someone on the radio needs the internet.** The radio replaces the first
  hop only. Mailboxes and the other relays are reached over the internet from
  the radio neighbour, so two nodes with only radio between them cannot mail
  each other yet.
