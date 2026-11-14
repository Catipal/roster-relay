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
  Settings   roster, overlay, radio, display and language options

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
choose "A relay pays": your node signs the listing and sends it through a
path to a relay it does not enter through, which learns who you are and not
where; a relay that has chosen to pay for its users publishes it for you, for
a month.

The relays your node connects to see its address, but not who it is: unless
it relays, each connection shows them a key made for that connection, never
your roster key.

A listing can be renewed in its last three days, by hand. If you stop
renewing, it simply lapses.

To be a relay that pays for other peers' listings, turn on "Pay to list peers
that ask through the overlay" on the Server page. It spends your coins, so it
is off until you turn it on, and the node has to be staking.

A listing "Through the overlay" puts no address on the chain. Peers meet you
at points both sides work out from the roster, which change every day; the
Discovery tab shows each peer's for today. The listing also names one relay
where you can be met for as long as it lasts, chosen at random and never one
your node enters the network through, and each renewal names a new one.

A listing made here never carries an address. It can carry a note instead:
one line of your own text, up to 72 bytes (about 72 letters of plain English,
fewer in other scripts), shown beside your key in everyone's Discovery tab.
Anyone can read it and the chain keeps it for good, so leave out anything
that says where you are. A renewal offers the note again; clear it to drop
it.

Relaying and sharing the internet are settings of your node, on the Server
page, not choices made with each listing; your listing takes them over when
you publish or renew it, since others find relays and gateways by it. To
carry others' paths as a relay, tick "Carry others' paths as a relay" on the
Server page's Relay card. A relay has to be dialled, so while your node
runs it tells the network its current address, signed with its key, every
hour and whenever the address changes - no transaction, never on the chain,
and the network forgets it within three hours of your node stopping. Others
must be able to reach your computer at the peer-to-peer port (TCP) and the
one above it (UDP); on a home connection, forward both. The node announces
the address most of its peers see it at; to name one yourself, start it with
-relayaddress=<ip>. The Server page shows what it announces, and the
Discovery tab shows a relay's address only while it is online.


Mail
----
Your mail address is your roster key, shown on the Mail page. You need to be
listed to have mailboxes. Letters are sealed so only the recipient can open
them, travel through three relays, and wait at the recipient's mailboxes for
up to two weeks until they collect them.


Sharing the internet
--------------------
BPS Relay shares your internet connection with the network, as every member
with the internet does, unless you switch it off; the first start asks. In
return, programs on your computer can use the network's internet.

The people who use your connection reach it through relays, so it never learns
who they are, and nobody in the network learns where it is. The websites they
visit see your internet address, as they would see yours. Only encrypted
connections leave - the web, and encrypted mail and messaging - never mail
between servers, and never into your own home network. It shares at most
1 GiB a day; change that, or switch sharing off, on the Server page. If the law
where you live or your internet provider's terms forbid sharing your
connection, switch it off.

Sharing is a switch on the Server page, not something you are listed for.
Visitors find gateways among the nodes listed through the overlay, with no
address, and meet them at their meeting points; one whose sharing is off
says so and they try another. So your node shares while the switch is on
and its listing has no address. A relay never shares: its address is
public, so its exit would be at a known address.

The same switch uses the network's internet in return, for the whole
computer: switched off, the network carries only BPS itself (mail, meetings,
the chain) and the computer uses its own connection.

While sharing is switched on, programs on this computer can use a SOCKS5 proxy at
127.0.0.1, on the port the Server page shows. Set it in a browser with names
looked up through the proxy (Firefox: "Proxy DNS when using SOCKS v5"). Each
connection leaves through another member's gateway, and names are looked up
there, never on your computer. .bps names are not sent out. It is slower than
your own connection: browsing and messages, not video.

All of this computer's traffic goes this way too, with no proxy setting in
any program, once BPS Relay may manage the network (below): with sharing
switched on, restart, and BPS Relay adds a network interface of
its own, routes the computer through it and points the computer's resolver at
it, and takes all of that down when it stops. This computer's own network -
the router, a printer - and BPS Relay's own connections stay direct. It needs
an administrator once:

  Linux    let BPS Relay manage the network:
             sudo setcap cap_net_admin+ep /path/to/bps-relay
           (again after each update of the program). The resolver is set
           through systemd-resolved where it runs.
  Windows  "Install the network service..." on the Server page installs
           BPS Relay's network service, bps-relay-net.exe, with the Wintun
           driver (wintun.dll) beside it, into Program Files; Windows asks
           for an administrator. It serves only the user who installed it.
           To remove it, as an administrator: bps-relay-net uninstall

Not yet: on Windows, other computers connecting in to this one while it is
routed through the network, and lookups Windows sends to other networks'
resolvers by itself; a switch that blocks everything while BPS Relay is not
running; macOS.


Payments
--------
Your own transactions leave through the overlay: through two relays to a
third that is not one of your entry relays, which announces each to the
network as it would anyone's. So the network does not first hear of your
payment from your address. If no relay will take one, BPS Relay announces it
the usual way after all, so a payment is never stuck.

Sites
-----
A site is a folder published under your node's key, from the Server page's
Hosting card. Anyone you give your key or your name can read it on the Sites
page: bps://yourname/. Every file is signed and checked piece by piece as it
arrives. If you are listed through the overlay, with no address, visitors meet
your node at its meeting points and nobody learns where the site runs; listed
at an address, visitors reach it through relays, so it never learns who they
are. Until your node is listed, nobody can find the site at all.

A program on this computer - a web application, a chat server, a game - can be
published the same way from the Hosting card, if it listens on 127.0.0.1:
visitors reach it over the overlay, and your node connects to nothing but the
port you name. Call a web application "web" and a browser opens it at your
address when you have no pages. To reach someone else's program, open their
site on the Sites page and use "Connect to a program...": BPS Relay listens on
a port of your computer and carries each connection there to it.

A web application sees every visitor arrive from 127.0.0.1, since nobody here
has an address to show it. So your node checks each request before the
application gets it: it takes out anything the request says about where it
came from (CF-Connecting-IP, X-Forwarded-For and the like), and adds a header
of its own, X-BPS-Visitor - sixteen hex digits that are the same for every
request along one path a visitor built. An application that limits how often
one visitor may post can count by that. A visitor gets a new one by building
a new path, which takes seconds; it says nothing about who they are. Each
connection carries one request: WebSockets and chunked uploads are refused.
Compress what the application sends if it does not already: a path carries
about 64 KB a second.

The Sites page shows pages with no scripts and fetches nothing from outside the
site, so a page cannot learn where you are. "Open in your browser" shows the
same site in an ordinary browser, through a server on this computer only, at
http://<name>.bps.localhost:<port>/. A browser can run a page's scripts, so the
Sites page stays the safer way to read a hidden site.

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


Language
--------
BPS Relay speaks 38 languages. Choose yours under Settings, Display, Language
and start BPS Relay again. The translations were made by Claude, not by
native speakers. Messages the node itself sends stay in English.


See the bitcoin proof of stake FAQs at:
  https://www.bitcoinpos.net
for more help and information.
