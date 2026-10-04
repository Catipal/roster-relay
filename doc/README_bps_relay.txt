Bitcoin PoS Relay
=================

Intro
-----
Bitcoin PoS Relay (BPS Relay) is the BitcoinPoS client for finding peers and
relaying for them. It runs a full node like BitcoinPoS Core does, but its pages
are about the network rather than about coins:

  Discovery  the peers listed on the chain, and publishing your own listing
  Wallet     the BitcoinPoS Core wallet itself, running inside this window
  Overlay    the encrypted relay network, and what this node pays its users
  Node       the console and peer details
  Settings   roster, overlay, relay and display options


Setup
-----
Unpack the files into a directory and run bps-relay.exe.

BPS Relay uses the same data directory as BitcoinPoS Core, so it shares its
copy of the chain and its wallets. Only one of the two can run at a time.

Unlike BitcoinPoS Core, BPS Relay turns the roster index and the overlay on by
default. The overlay listens on UDP port 48931, one above the peer-to-peer
port, so allow it through the firewall if asked. Its handshake has not yet been
reviewed by anyone who did not write it, so do not rely on it for anything
that has to stay private. It can be switched off on the Settings page.


Getting listed
--------------
A listing is a short record on the chain saying that you exist. It lasts a
month and costs a small fee. Publish it from the Discovery page.

If your wallet has coins, it pays. If it has none, choose "A relay pays": your
node signs the listing and sends it over the overlay to the relay it enters
through, and a relay that has chosen to pay for its users publishes it for you.
A relay that stops paying lets your listing lapse within the month; you can
always renew from a funded wallet yourself.

To pay for other peers' listings as a relay, turn on "Pay to list peers that
ask through the overlay" under Settings > Relay. It spends your coins, so it is
off until you turn it on.


See the bitcoin proof of stake FAQs at:
  https://www.bitcoinpos.net
for more help and information.
