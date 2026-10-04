BPS Relay
=========

Intro
-----
BPS Relay is the BitcoinPoS client for finding peers and relaying for them.
It runs a full node like BitcoinPoS Core does, but its pages are about the
network rather than about coins:

  Discovery  the peers listed on the chain, and publishing your own listing
  Wallet     coins, keys and staking, using the same wallet as BitcoinPoS Core
  Overlay    the encrypted relay network, and what this node pays its users
  Node       the console and peer details
  Settings   roster, overlay and display options


Setup
-----
Unpack the files into a directory and run bps-relay.exe.

BPS Relay uses the same data directory as BitcoinPoS Core, so it shares its
copy of the chain and its wallets. Only one of the two can run at a time.

Unlike BitcoinPoS Core, BPS Relay turns the roster index and the overlay on by
default. The overlay listens on UDP port 9346. Its handshake has not yet been
reviewed by anyone who did not write it, so do not rely on it for anything
that has to stay private. It can be switched off on the Settings page.

See the bitcoin proof of stake FAQs at:
  https://www.bitcoinpos.net
for more help and information.
