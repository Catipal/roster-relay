Bitcoin PoS Relay
=================

Intro
-----
Bitcoin PoS Relay (BPS Relay) is the BitcoinPoS client for finding peers and
relaying for them. It runs a full node like BitcoinPoS Core does, but its pages
are about the network rather than about coins:

  Node       who is listed, the encrypted relay network, names, peers and
             console
  Wallet     the BitcoinPoS Core wallet itself, running inside this window
  Mail       letters to and from other people on the roster
  Server     what this node offers others: relaying and holding mail
  Settings   roster, overlay and display options

What changed in this version is in release-notes.md, next to this file.


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
A listing is a short record on the chain saying that you exist. It costs a
small fee. Publish it from the Discovery tab of the Node page.

If your wallet pays, choose a month or a year. If your wallet has no coins,
choose "A relay pays": your node signs the listing and sends it over the
overlay to the relay it enters through, and a relay that has chosen to pay for
its users publishes it for you, for a month.

A listing can be renewed in its last three days, by hand. If you stop
renewing, it simply lapses.

To be a relay that pays for other peers' listings, turn on "Pay to list peers
that ask through the overlay" on the Server page. It spends your coins, so it
is off until you turn it on, and the node has to be staking.


Mail
----
Your mail address is your roster key, shown on the Mail page. You need to be
listed to have mailboxes. Letters are sealed so only the recipient can open
them, travel through three relays, and wait at the recipient's mailboxes for
up to two weeks until they collect them.


Radio
-----
With a LoRa radio (an RNode) or another radio Reticulum supports, your node
can reach the overlay without the internet, through a BPS node in radio range
that has it. Install Reticulum (pip install rns), set up the radio in
Reticulum's configuration, and turn on Settings, Radio. BPS Relay starts
bps-rns-bridge.py, which comes with it, by itself. It is slow: a letter takes
minutes.


Names
-----
A name points people to your roster key. Get one on the Names tab of the Node
page. A free name of any length costs only the network fee, and so does
renewing it, which you do by hand. A name someone holds can be bought if they
have put it up for sale, for what they ask, and it is yours at once, in one
transaction. Names under yours are free, and so is the address book of your
own labels for people.

Turn on "Take payments by name" and people can pay your name: every payment
lands at an address of its own that only your wallet can spend.


Identity
--------
An identity stands behind your node's key, so that if the key ever has to
change, your node keeps how long it has been listed. Make one on the Discovery
tab. Write down the recovery key it shows you: it is shown only once, and it is
the only way to stop someone who steals your identity from moving it.


See the bitcoin proof of stake FAQs at:
  https://www.bitcoinpos.net
for more help and information.
