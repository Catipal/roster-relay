Bitcoin PoS Relay version 0.22 Release Notes
============================================

Bitcoin PoS Relay (BPS Relay) 0.22 is the first release of a second BitcoinPoS
client. Bitcoin PoS Core is about coins; BPS Relay is about who is on the
network. It runs the same full node, shares the same chain data and wallets,
and adds a roster of peers kept on the chain, an encrypted relay network, the
means to run a relay that pays the peers who use it, mail between the
people on the roster, and names for them.

It ships as its own package, `bps-relay-0.22-<platform>`, next to the Bitcoin
PoS Core one. Bitcoin PoS Core's own changes in 0.22 are in its release notes.

How to install
==============

Unpack the archive and run `bps-relay` (`bps-relay.exe` on Windows). On
macOS, `bps-relay-0.22-osx.dmg` holds BPS Relay as an app: open it and drag
BPS Relay to Applications.

BPS Relay uses the same data directory as Bitcoin PoS Core, so it shares its
copy of the chain and its wallets. Only one of the two can run at a time:
close one before starting the other.

The first start builds the roster index from the chain, which takes a few
minutes on mainnet. A roster or name index made by an earlier test build is
rebuilt once, the same way. Allow UDP port 48931 through the firewall if asked; that
is the relay network.

Windows: the programs are not code-signed yet, so Smart App Control may
refuse a new build for a while, or until it has seen it before.

macOS: the app is not signed or notarised either, so the first time macOS
refuses to open it; open it from its menu (Control-click, Open) to allow it.

Linux, Raspberry Pi included: file managers often take the program for a
library and do nothing on a double-click, so start it from a terminal in its
folder with `./bps-relay`. Use `aarch64` on a 64-bit Raspberry Pi OS and
`armhf` on a 32-bit one (`getconf LONG_BIT` tells which); the builds need
glibc 2.34 or newer, as in Raspberry Pi OS Bookworm, Debian 12 or Ubuntu
22.04; Raspberry Pi OS Bullseye is too old.

Two loopback ports sit just above the peer-to-peer one: the local proxy (two
above, 48932) and the site server for browsers (three above, 48933). If
another node already uses them, BPS Relay now starts without that part and
says so; give them free ports with `gatewayproxyport=` and `siteproxyport=` in
bitcoin-pos.conf.

What's in it
============

Node
----

The first page, with four tabs.

- **Discovery** - the peers listed on the chain, and your own listing. A
  listing is a short signed record saying you exist and, if you want, a
  line of your own text (a note, up to 72 bytes) shown beside your key. It
  never carries your address. Nobody can list you without your key, hide you from
  some clients and not others, or quietly remove you. Click a peer's key or
  address to copy it. A peer listed through the overlay shows where it can
  be met today, worked out from the roster; these change every day, and its
  listing also names one relay to meet it at for as long as the listing
  lasts, a new one at each renewal. A relay listed through the overlay says
  where it is while it runs, in a short message signed with its key that
  peers pass on, and its address shows here only while it is online ("Only
  relays online now" hides the rest). It can change without a transaction,
  and none of it is ever on the chain. "Listed for" is how long each peer has been listed
  without a break - the one thing a newcomer cannot fake - and its tooltip
  says whether an identity stands behind it (see Identities).
  If the newest block this node has is over a month old, the roster is
  marked as that old: it is still used to reach peers, but not trusted,
  because peers revoked since may still be in it.
- **Overlay** - the encrypted relay network: whether it runs, the relays it
  knows, the two it enters through, and where people can meet you. Every
  path this node builds goes through three relays run by different people,
  so the relay that sees where you are never sees what you reach, and the one
  that sees what you reach cannot tell which relay you came in through. Until
  the roster lists enough relays for that, paths are refused rather than
  shortened.
- **Names** - see Names below.
- **Peers and console** - the same console, peer table and traffic graph
  as Bitcoin PoS Core.

The overlay picks the relay it enters through from relays listed for a month
or more when there are any, and never puts two relays of the same identity
on one path.

Getting listed
--------------

Publish from the Discovery tab. A listing costs a small fee, and who pays
decides how long it lasts:

- **Your own wallet pays** - a month or a year, your choice.
- **A relay pays** - for a wallet with no coins. Your node signs the listing
  and sends it through a path to a relay it does not enter through, which
  learns who you are and not where, pays the fee and adds you to the peers it
  shares its rewards with. A month, always. The relays a node connects to see
  its address and, unless it relays itself, a key made for each connection,
  never its roster key.

  A node enters through two relays of its own, so a relay that pays can be
  reached this way only once at least three are listed. Until then the window
  offers **Ask my entry relay directly**: that relay then sees your IP address
  together with your key, and you have to tick it yourself.

A listing can be renewed in its last three days and not before. Renewing is
always done by hand: a peer leaves simply by not renewing, and stops costing
its relay when the month runs out.

Whether a listing says you are a relay comes from the **Relay** switch on the
Server page, at the moment you publish. If you change the switch while listed,
Discovery offers **Update your listing** at once rather than in the last three
days; your own wallet pays for it.

Listings are larger than 0.21 nodes will pass on, so until most of the network
runs 0.22 a listing confirms only in a block staked by a node running this
version. If you stake, your listing goes into your own next block; a relay
stakes the listings it pays for into its own. Old nodes accept those blocks
like any other.

Wallet
------

The Bitcoin PoS Core wallet itself, running inside a window on this page -
menus, toolbar, staking and all - so it always matches the wallet client.

Mail
----

Letters between the people on the roster. Your address is your roster key,
shown at the top of the page with a button to copy it.

- **Writing** - Write, put in the recipient's roster key, and send. Your
  node fetches the recipient's current mail key, seals the letter to it and
  leaves it at each of their mailboxes. Up to 32 KB of text; no attachments.
- **Mailboxes** - three relays chosen from each person's key by the roster
  itself, so nobody assigns them and nobody can be asked where your mail
  goes. They hold letters for two weeks at most.
- **Collecting** - every five minutes, or now with Collect now. Collected
  letters are removed from the mailboxes, so this computer keeps the only
  copy.

How it is protected, following the three changes Session announced for its
protocol in December 2025:

- **Old keys are deleted.** Your mail key changes every week, and the
  private half of an old one is deleted once nothing sealed to it can still be
  waiting, so a letter cannot be opened later from this computer's keys.
- **Post-quantum.** Each letter is sealed with two key exchanges at once,
  secp256k1 and ML-KEM-768 (FIPS 203), and stays sealed unless both are
  broken. ML-KEM comes from mlkem-native 2.0.0, the implementation AWS uses,
  and its answers are checked against Go's own implementation in the tests.
- **Sealed sender.** Who wrote a letter travels inside the seal, signed, so
  the mailbox holding it cannot tell. Every trip to a mailbox also goes
  through three relays, so it does not learn where you are either.

A letter is signed by the sender's roster key and bound to the recipient, so
it cannot be passed on to someone else as though it had been written to them.

- **Your usual mail client** - with `-mailbridge` the node also speaks POP3 and
  SMTP on the loopback interface (127.0.0.1), so Thunderbird, Apple Mail or K-9
  can read and write BPS mail. Point the client at `127.0.0.1`, POP3 on 1100 and
  SMTP on 1587 (change with `-mailbridgepop3port` / `-mailbridgesmtpport`), no
  encryption, any username and password. Write a recipient as `name@bps` or
  `<key>@bps` - the part after `@` is ignored. Nothing here touches the internet's
  mail network: "send" hands the letter to the node, which seals it and carries
  it over the overlay to that key, and "receive" reads the node's own inbox. It
  is **off by default**, because while it is on any program on the computer that
  can reach the port reads this node's mail in the clear; turn it on only on a
  machine that is yours. There are no folders: it serves the inbox, marks a
  letter read when the client fetches it, and deletes it from the node when the
  client does.

Radio
-----

The overlay can run over radio as well as the internet, through Reticulum:
LoRa with an RNode, packet radio, serial links. A node without the internet
reaches the overlay through a radio neighbour that is a listed relay, so its
mail and listing requests still go out.

- **It is on by default** - Settings, Radio: "Carry the overlay over radio
  too" is ticked, with an off switch there. BPS Relay starts the Reticulum
  bridge (`bps-rns-bridge.py`, shipped beside it) by itself. Until Reticulum
  is installed and a radio is set up the bridge simply finds no radio and the
  node carries on over the internet, so having it on costs nothing. Reticulum
  is installed separately, with `pip install rns`, and the radio is set up in
  Reticulum's own configuration. `contrib/reticulum/README.md` walks through it.
- **Neighbours** - the BPS nodes heard on the radio are on the Overlay page.
  Each one announces itself every half hour, and again soon after it hears a
  newcomer.
- **Entering by radio** - when a neighbour is a listed relay, your paths
  start there (on by default; Settings, Radio). A relay then carries the path
  on to the next relay over radio too, when it has no internet route to it, so
  a path reaches across a stretch that has only radio rather than only its
  first hop.
- **Private as before** - the bridge carries the overlay's datagrams and
  never sees inside them; the handshake still proves the neighbour is who it
  announced.
- **Repeaters** - a Reticulum node set to pass traffic on (a small computer
  with an RNode on a roof, say) extends the range, and needs no BPS of its
  own. It cannot read what it carries.

Radio is slow - a LoRa link moves a few hundred bytes a second - and BPS
Relay waits as long as the radio's speed needs, down to LoRa's slowest
setting. Tested on a simulated LoRa link at 3 kbit/s: a listing request takes
about 5 seconds, sending a short letter about a minute, collecting one about a
minute and a half. Sending one letter uses about 36 seconds of transmitting,
which in Europe is a whole hour's allowance on most of the 868 MHz band (1%);
the 869.4-869.65 MHz slice allows 10%. `contrib/reticulum/README.md` has the
figures for other settings.

Names
-----

A tab of the Node page. A name points people to your roster key, so they can
write to you, and pay you, as `pilot` instead of 64 characters of key.

- **Getting a name** - Get a name, type it, choose one or two years, and see
  whether it is free before anything is spent. A free name is registered in
  two steps: a commitment that hides the name, then, six blocks later (about
  twenty minutes), the claim, which BPS Relay sends by itself. Nobody
  watching for new names can take yours in between. Keep BPS Relay running
  and the wallet unlocked until the claim goes out.
- **Price** - none. Registering and renewing cost only the network fee, for
  a name of any length from one letter to 32. A name somebody holds costs
  whatever they ask for it, if they have put it up for sale.
- **Selling and buying** - Sell a name you hold at your price, and anyone can
  buy it at once, even while your BPS Relay is closed: one transaction pays
  you and moves the name, all or nothing. Two buyers can never both pay, and
  while the name is for sale you cannot transfer it, so a buyer cannot be
  outrun by the seller either. Take off sale ends it. The buyer gets the
  name without its subnames, and keeps the time left on it, renewed up to
  two years ahead if they ask.
- **Renewing** - by hand, for the network fee, while the name is live and for
  a month after it ends; after that anyone may register it. A name can be
  renewed at most two years ahead.
- **Paying by name** - Take payments by name, once, and anyone can pay
  `pilot`, `shop.pilot`, a petname they keep for you, or your key. A name
  never points at an address: each payment goes to an address of its own,
  worked out from a key your wallet published and a one-time key the payment
  carries, so only your wallet can spend it and nobody watching can tell who
  was paid or that two payments went to the same person. Payments show in
  the wallet as "Paid by name". One that arrives while the wallet is locked
  shows as watch-only and becomes spendable when you unlock. Pay someone
  from Look up or the address book; a payment cannot be taken back, so a
  name that changed hands, or a payment key that changed, in the last 500
  blocks (about a day) is flagged first, and a key that has been revoked is
  refused. Renewing a name does not count as a change.
- **Subnames** - free under a name you hold: `alice.pilot` can point to
  anyone's key, and lasts as long as `pilot` does.
- **Transfer** - give a name to another key.
- **Look-alikes** - names are plain letters a-z, digits and hyphens, and a
  name that looks like one somebody else holds (`pi1ot` for `pilot`, `rn` for
  `m`) is refused.
- **Address book** - your own labels for people (petnames), kept on this
  computer and free. A petname wins over a registered name spelled the same.
- **Look up** - what any name, subname or petname points to.

Mail accepts a name or a petname wherever it accepts a key.

Names are open on mainnet, counting from block 1,220,000, and on regtest,
testnet and signet from the beginning.

Identities
----------

Your node's roster key is hot: it lives on the node and signs every listing.
An identity is a second key that stands behind it, so that if the node's key
is ever lost or stolen a new one can be put under the same identity and keep
how long the node has been listed, instead of starting again.

- **Making one** - Make one on the Discovery tab, or `createidentity`. You are
  shown a recovery key once: write it down. A small transaction publishes the
  identity, and your next listing renewal links the node's key to it - an
  identity only stands behind a key whose own listing accepts it, so nobody
  can claim your node as theirs.
- **Moving it** - `createrotation` moves the identity to a new key, carrying
  its age. The move takes effect about a day and a half after it confirms.
- **If it is stolen** - whoever took it can try to move it away; within that
  day and a half, `createveto` with your recovery key cancels the move.
- **Ending a key** - `createrevocation` signs the end of a key, for good, and
  `sendrevocation` passes it from node to node without a transaction: every
  node drops the key the moment it hears, and keeps it dropped even if a
  reorganisation takes away the block that carried it.
- **Proving age** - `getageproof` proves how long a key has been listed, link
  by link, to someone who holds only block headers; `verifyageproof` checks
  it.

The roster's fingerprint
------------------------

Built, and switched off on every network until an activation is scheduled.
When active, every block carries the fingerprint - a merkle root - of the
roster as it stood a hundred blocks earlier, as one more push after the
witness commitment in its coinbase, so nodes that do not know the rule keep
following the chain (a soft fork). A client that holds only block headers
can then take the whole roster, or one entry of it, from any node it does not
trust and check it (`getrostersnapshot` and `verifyrostersnapshot`,
`getrostermembership` and `verifyrostermembership`). A node enforcing it
keeps the roster beside its chain state (`roster_ledger.dat`), whether or not
it runs the roster index.

Server
------

What this node offers other people.

- **Relay** - running today. Turn on "Pay to list peers that ask through the
  overlay" to pay for the listings of peers that use this node, choose how
  many peers to keep, which wallet pays the fees, and what share of each block
  you stake to give them. A relay has to be staking: the listings it pays for
  go into blocks it stakes itself. Peers whose listing has run out are no
  longer paid.
- **Mailbox** - running wherever the relay network runs. Holds sealed mail
  for the people the roster makes this node a mailbox for, and only for
  listed people. It cannot read what it holds. You can turn it off or limit
  the disk it uses (256 MiB by default, 8 MiB at most for any one person).
- **Gateway** - running wherever the relay network runs, unless switched
  off. Shares this computer's internet connection with the network, and lets
  programs on this computer use the network's internet in return. The first
  start says plainly what sharing means and lets you switch it off before
  anything runs. Sharing is a switch, not a listing: visitors find gateways
  among the nodes listed through the overlay with no address, met only
  through relays at their meeting points, so a gateway never learns who uses
  it and nobody learns where it is; the websites people visit through it see
  its address. A relay never shares, since its address is public. Only encrypted connections leave (TCP 443, 465, 853, 993,
  995, 5223, 5228 and UDP 443), never port 25 and never a private address;
  at most 1 GiB a day by default (`-gatewaybandwidth`), 64 KiB/s per visitor
  (`-gatewayrate`). Names are looked up with the gateway computer's own
  resolver, and only public addresses are given back. The card shows
  today's traffic, open connections and the meeting points it is registered
  at, and says why the node does not share when it does not.
- **Local proxy** - a SOCKS5 proxy on 127.0.0.1 (`-gatewayproxy`, on in BPS
  Relay; port `-gatewayproxyport`, two above the peer-to-peer port). Each
  connection leaves through another member's gateway, met through two relays
  of this node's own (`-gatewayhops`); names are looked up at a gateway,
  never here, and `.bps`, `.onion` and home-network names are not sent out
  at all. It works while this node's own gateway is switched on, or while it
  has no line and relays over radio; it never needs a listing, which would tie
  the node's key to its address for whoever paid for it. Measured on one computer (regtest): 1.5 MiB
  in 39 s, paced to stay under the relays' caps.
- **All of this computer's traffic** - comes with the gateway switch on the
  Server page: switched on, the computer shares its line and uses the
  network's in return, all of it (`-gatewayinterface`, `-gatewayroutes`) once
  BPS Relay may manage the network, through the local proxy until then;
  switched off, the network carries only BPS itself. The computer's own IP
  packets go through the gateways,
  each new connection through another, and only what comes back for the
  computer's own connections is let in. The interface's resolver
  (10.77.1.53) answers every lookup the computer sends through it, at a
  gateway; `.bps`, `.onion` and home-network names are never sent anywhere,
  and other record types than addresses get no answer. The computer's own
  network and the node's own connections stay direct, and a gateway's own
  lookups go to the resolvers the computer had before. Needs an
  administrator once: on Linux `sudo setcap cap_net_admin+ep` on the
  program, after which it sets the routes up and takes them down itself; on
  Windows BPS Relay's network service (bps-relay-net.exe, with Wintun 0.14.1
  beside it), installed from the Server page.
- **Your own transactions leave through a path** (`-txpath`, wherever the
  overlay runs): a payment goes through two relays to a relay that is not one
  of your entry relays, which announces it as it would anyone's. Announced
  from your own address, a transaction can be traced to you by anyone
  connected to many nodes; this way the first to announce it does not know
  where it came from. If no relay takes it, the peer-to-peer network carries
  it after all, and the log says so. A relay announces others' this way too,
  at most 20 a minute from one path and 600 in all. `gettxpathinfo` counts
  both.
- **Relays carry within limits** - `-relaypathrate` (64 KiB/s per path) and
  `-relaybandwidth` (1 GiB of other people's traffic a day), shown in
  `getoverlayinfo`.
- **Hosting** - publish a folder as a site under this node's key ("Publish a
  folder..."), publish it again after changing it, or stop. Listed with no
  address, the node keeps itself registered at its meeting points while it
  publishes, so nobody learns where the site runs; listed at an address,
  visitors reach it through three relays, so it never learns who they are.
  The card shows how the site is reached and what has been sent, and says so
  when the node is not listed and nobody can find it yet. The folder is
  published again at every start until stopped. "Publish a program..." does
  the same for a program on this computer - a web application, a chat
  server, a game - listening on 127.0.0.1: visitors reach it over the
  overlay as a stream, and this node connects to nothing but the port named.
  A program named `web` is what a browser opens at the node's address when
  there are no pages. Its requests pass the host's node first: one request
  per stream, with every header that claims where it came from removed
  (`CF-Connecting-IP`, `X-Forwarded-For`, ...) and `X-BPS-Visitor` added, a
  label that is the same along one path a visitor built - so an application
  that sits behind a reverse proxy elsewhere cannot be told a visitor is
  someone else, and can still tell visitors apart. A request with a chunked
  body, a folded header or a bare line feed is refused, since the
  application might read it differently. A visitor's node asks a host with
  no pages for one once a minute, not before every request.
- **Sites** - a page of its own for reading sites: write `bps://name/` or a
  site's key. Pages are shown with no scripts, and nothing on them is fetched
  from outside the site, so a page cannot learn where its reader is; a link
  outside BPS is shown, not followed. The page says how the site was reached,
  and warns when a name now points to a different key than when it was last
  opened. "Open in your browser" shows the same site in an ordinary browser,
  through a server on this computer only (`-siteproxy`, on in BPS Relay):
  `http://<name or key>.bps.localhost:<port>/`, the port three above the
  peer-to-peer one. There a page may load only from its own site, but scripts
  can run, so the viewer stays the safer way to read a hidden site.
  "Connect to a program..." carries a port of this computer to a program the
  site runs, for a chat client or a game to connect to.
- **Phone companion** - off until you turn it on. Lets your phone spend from
  a small allowance wallet on this node while your coins stay here; see below.

Phone companion
---------------

Spend from your phone without putting your keys on it. The phone holds one
key of its own, made on the phone, which can spend nothing; this node pays
for it from a separate allowance wallet, after checking the phone's PIN and
the limits you set.

- **Setting up** - Server, Phone companion: turn on "Let paired phones spend
  from an allowance wallet" and restart. Then Create it makes the allowance
  wallet - no passphrase, because nobody is there to type one when the phone
  pays - and Top up opens Send in the wallet to move coins into it. Put in it
  only what the phone should be able to spend. It never stakes.
- **Pairing** - Pair a phone shows a code, as a QR code and as text, good
  for ten minutes and one phone. The phone answers it with a name and a PIN
  of six to twelve digits. Both screens then show the same six digits: if
  they differ, someone else answered first - reject, and show a new code.
  When you accept, you set the most one payment may send and the most any
  24 hours may send, fees included. The phone cannot change either.
- **Paying** - the phone asks for a payment to an address or a name, sees
  the fee, and sends it with its PIN. Names are paid exactly as from the
  console: one that changed hands in the last day is refused.
- **If the phone is lost** - Unpair it here. Five wrong PINs in a row lock
  it until you unlock it here, and PIN tries are capped for all phones
  together, so a stolen phone cannot guess its way in. At worst it can spend
  what is left of the day's limit, never more than the allowance holds.
- **How it is reached** - through three relays the phone picks itself, then
  this node, which therefore has to be a listed relay. The relays cannot
  read what passes and none of them learns both where the phone is and that
  it is talking to this node. This node never learns where the phone is.

The app is coming for Android and Linux phones; until then `bps-companion-cli`
does the same from a terminal.

Footer
------

Your listing, the relay network, the wallet's lock and staking state with the
yearly rate staking pays, your peers (click to pause the network) and the
block height, with a progress bar while catching up.

Languages
---------

BPS Relay is translated into the 38 languages whose wallet translation was
at least 80% done: Afrikaans, Arabic, Bengali, Catalan, Chinese (simplified
and traditional), Croatian, Czech, Danish, Dutch, Filipino, Finnish, French,
Galician, German, Greek, Hebrew, Hungarian, Indonesian, Italian, Japanese,
Korean, Malay, Norwegian, Persian, Polish, Portuguese (Brazil and Portugal),
Romanian, Russian, Serbian, Slovak, Slovenian, Spanish, Swedish, Tamil,
Ukrainian and Vietnamese. Regional variants such as Mexican Spanish use their
base language. Choose one under Settings, Display, Language; it takes effect
when BPS Relay starts again, and the wallet inside it follows the same
setting. The other languages the wallet carries can be chosen too, but show
BPS Relay's own pages in English.

New options
===========

| Option | Default | What it does |
|---|---|---|
| `-rosterindex` | on in BPS Relay, off in the node | Keep an index of the roster |
| `-rosterconnect` | on | Offer roster peers to the address manager |
| `-rosterindexstart` | 0 | Height the roster index starts reading from; needed with `-prune` |
| `-rosterindexwindow` | 0, keep everything | Blocks of roster history to keep; at least 175,320 (a year), or the node refuses to start |
| `-overlay` | on in BPS Relay, off in the node | Run the encrypted relay network |
| `-overlayport` | one above this node's peer-to-peer port (48931 on mainnet) | Its UDP port |
| `-radio` | on | Carry the overlay over Reticulum too (inert until the bridge and a radio are set up) |
| `-radioentry` | on | With `-radio`, enter the overlay through a radio neighbour that is a listed relay |
| `-overlayblocks` | on with `-radio` | Carry new blocks to and from radio neighbours, so a radio-only node keeps up with the chain |
| `-meetable` | off | Stay registered at this node's meeting points, so it can be reached by its key with no address published (needs a listing) |
| `-meethops` | 2 | Relays between this node and each meeting point, 1 to 3 |
| `-gatewayhops` | 2 | Relays between this node and a gateway's meeting point, 1 to 3 |
| `-nameindex` | on in BPS Relay, off in the node | Keep an index of names, to look them up, register, sell and buy |
| `-mail` | on | Send and collect mail (needs the overlay) |
| `-mailbox` | on | Hold sealed mail for others (needs the overlay) |
| `-mailboxmaxsize` | 256 | Disk the mailbox may use, in MiB |
| `-mailbridge` | off | Read and send BPS mail from an ordinary client over loopback POP3/SMTP (needs `-mail`) |
| `-mailbridgepop3port` | 1100 | Loopback port the bridge serves POP3 on |
| `-mailbridgesmtpport` | 1587 | Loopback port the bridge accepts SMTP on |
| `-acceptlistings` | off | Pay for the listings peers ask this node to publish |
| `-maxlistedusers` | 100 | Most peers to keep listed |
| `-listingwallet` | the only wallet open | Which wallet pays for listings |
| `-relayshare` | 0 | Percent of each block this node stakes, shared with its peers |
| `-companion` | off | Let paired phones spend from an allowance wallet (needs the overlay and this node listed) |
| `-companionwallet` | none | The allowance wallet paired phones spend from |

The default for `-datacarriersize` rises from 83 to 253 bytes, so this node
relays listings. It is relay policy only; blocks are validated as before.

New RPCs
========

`getrosterinfo`, `getroster`, `getrosterhistory`, `createannouncement`,
`publishrecord`, `requestlisting`, `getoverlayinfo`, `getrosterstaker`,
`dumprosterkey`, `addrosteruser`, `removerosteruser`, `getrelaypayout`; for
mail `sendmail`, `checkmail`, `listmail`, `readmail`, `deletemail` and
`getmailinfo`; and for names `getnameinfo`, `resolvename`, `listnames`,
`getnameprice`, `registername`, `renewname`, `transfername`, `setsubname`,
`listnameregistrations`, `sellname`, `cancelnamesale`, `buyname`,
`setpetname`, `deletepetname`, `listpetnames`, `setnamepayments`,
`sendtoname` and `listnamepayments`; for identities and
revocations `getidentity`, `createidentity`, `createdelegation`,
`createrotation`, `createveto`, `createrevocation`, `sendrevocation`,
`listrevocations`, `getageproof` and `verifyageproof`; and for the roster's
fingerprint `getrostersnapshot`, `verifyrostersnapshot`,
`getrostermembership` and `verifyrostermembership`; `getradioinfo` for
radio links; and `getmeetinginfo` and `meet` for reaching a node by its key alone; and `getchainfeedinfo` for blocks over radio; and `publishsite`, `unpublishsite`, `gethostinginfo`, `getsite` and `getsiteaddress` for hosting a folder under a key and reading it over the overlay; and `publishservice`, `unpublishservice`, `connectservice`, `disconnectservice` and `getserviceinfo` for programs reached as streams; `gettxpathinfo` for transactions sent through paths; and `getrostergrowth`, which says how much of the chain's growth listings are, over the last blocks - the tripwire the design note asks to watch from the first release; and for the phone companion `getcompanioninfo`, `companionpair`, `companionpending`, `companionaccept`, `companionreject`, `listcompaniondevices`, `setcompanionlimits`, `revokecompaniondevice` and `unlockcompaniondevice`.
Each has its full description in `help`.

The console suggests commands from what you type in plain words - "pay pilot
2", "saldo", "how many blocks" - in English, Italian, Spanish, French, German
and Portuguese. Suggestions are worked out on this computer from the
commands' own help; nothing typed is sent anywhere, and a suggestion is only
put in the input line, never run.

Nodes pass revocations to each other in a new message, `rosterrevoke`, which
older nodes ignore.

The node also advertises a new service bit, `NODE_ROSTER`, meaning it serves
the blocks a roster is built from, and `-blockfilterindex=roster` builds
compact filters that match listings.

Known issues
============

- Relays now carry a path on to the next relay over radio when they have no
  internet route to it, so a path can cross a stretch that has only radio, and
  a radio neighbour is no longer only the first hop.
- New blocks now travel over the radio as well. A node with the internet feeds
  them to its radio neighbours, and a node with only radio follows a neighbour
  that is ahead, one block at a time, so it keeps up with the chain and so with
  the roster (`-overlayblocks`, on by default with the radio; `getchainfeedinfo`
  shows the neighbours and their heights). This is not a sync from genesis -
  LoRa cannot carry that - so a radio-only node starts from a recent copy and
  only ever follows the last few hundred blocks this way. A node kept at the
  tip by the internet has nothing to pull.
- A folder can be hosted as a site under a node's roster key (`publishsite`)
  and fetched back over the overlay by that key (`getsite`). Every file is cut
  into 16 KiB pieces, each one hashed, and the whole manifest is signed by the
  key; a visitor checks the signature against the key it asked for and every
  piece against the manifest as it lands, so a relay or a host that changes a
  byte is caught at once. A visitor asks for several pieces at once - two at
  first, one more for each that arrives whole, half as many after a loss -
  and a host sends no faster than 48 KiB/s down one path, under the relays'
  cap. A program's bytes travel as a stream: numbered cells, the far end
  saying which it has, cells not acknowledged in time sent again, and both
  how many are out and how fast they leave halving on a loss and growing
  back, so a stream finds the pace a path's relays allow. Measured on one
  computer (regtest): 200 KiB echoed both ways through a hidden service in
  about nine seconds. The Sites page says when a site is reached over the
  radio, so a slow page is not taken for a broken one.
- Mail over radio is heavy: each letter goes to three mailboxes through
  three separate paths, and every path is built across the radio.
- Radio needs Python and Reticulum installed beside BPS Relay. Ham radio
  bands do not allow encrypted traffic; use licence-free ones such as LoRa's.
- The translations were made by Claude, not by native speakers; corrections
  are welcome. Texts the node itself sends, such as error messages from
  commands, stay in English.
- Arabic, Hebrew and Persian read right to left, but the window keeps its
  left-to-right layout, as the wallet client does.
- The relay network's handshake has not been reviewed by anyone who did not
  write it. Do not rely on it for anything that must stay private.
- A relay pays its peers inside the blocks it stakes, so who a relay pays is
  visible on the chain.
- A listing records the peer-to-peer port only; a relay that moves its relay
  network off one above it has to be named by hand.
- Mail has one device per address. Session's third change, several devices
  sharing one account, is not built.
- Anyone listed can write to anyone listed. A mailbox limits how much it holds
  for each person, but there is no spam filter yet.
- Mail keys and letters on this computer are stored unencrypted in the data
  directory (`mail/`), like the roster key. Protect the computer itself.
- The identity key is kept on the node by default, beside the roster key. It
  is meant to live elsewhere; the RPCs that sign with it take it as an
  argument for that.
- A node whose roster key is revoked needs a new one by hand: stop it, move
  `roster.key` aside, start it again. Names it holds stay with the old key, so
  transfer them first.
- The roster's fingerprint is not active on any network (see above).
- An age proof does not carry age across an identity's move to a new key:
  that the move was not vetoed cannot be shown to a client with headers only.
- Payments by name are found with the node's roster key. A wallet restored
  on another node, or after `roster.key` is replaced, does not find them;
  keep `roster.key` with the wallet backup, as it also holds your names.
- Paying by name is BPS's own scheme: only this wallet can pay a name or
  find payments made to one.
- Nobody settles a disputed name. The first valid registration holds it.
- Names cost nothing but the fee, so nothing stops someone registering many
  of them, short ones included; the commitment step only stops them taking
  a name someone else is registering.
- `getmininginfo` and `getstakinginfo` fail when more than one wallet is open.
- On Linux the window can stay in the process list after quitting.
