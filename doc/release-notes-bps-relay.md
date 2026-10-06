Bitcoin PoS Relay version 0.22 Release Notes
============================================

Bitcoin PoS Relay (BPS Relay) 0.22 is the first release of a second BitcoinPoS
client. Bitcoin PoS Core is about coins; BPS Relay is about who is on the
network. It runs the same full node, shares the same chain data and wallets,
and adds a roster of peers kept on the chain, an encrypted relay network, the
means to run a relay that pays the peers who use it, and mail between the
people on the roster.

It ships as its own package, `bps-relay-0.22-<platform>`, next to the Bitcoin
PoS Core one. Bitcoin PoS Core's own changes in 0.22 are in its release notes.

How to install
==============

Unpack the archive and run `bps-relay` (`bps-relay.exe` on Windows).

BPS Relay uses the same data directory as Bitcoin PoS Core, so it shares its
copy of the chain and its wallets. Only one of the two can run at a time:
close one before starting the other.

The first start builds the roster index from the chain, which takes a few
minutes on mainnet. Allow UDP port 48931 through the firewall if asked; that
is the relay network.

Windows: the programs are not code-signed yet, so Smart App Control may
refuse a new build for a while, or until it has seen it before.

What's in it
============

Node
----

The first page, with three tabs.

- **Discovery** - the peers listed on the chain, and your own listing. A
  listing is a short signed record saying you exist and, if you want,
  where to reach you. Nobody can list you without your key, hide you from
  some clients and not others, or quietly remove you.
- **Overlay** - the encrypted relay network: whether it runs, the relays it
  knows, the two it enters through, and where people can meet you. Every
  path this node builds goes through three relays run by different people,
  so the relay that sees where you are never sees what you reach, and the one
  that sees what you reach cannot tell which relay you came in through. Until
  the roster lists enough relays for that, paths are refused rather than
  shortened.
- **Peers and console** - the same console, peer table and traffic graph
  as Bitcoin PoS Core.

Getting listed
--------------

Publish from the Discovery tab. A listing costs a small fee, and who pays
decides how long it lasts:

- **Your own wallet pays** - a month or a year, your choice.
- **A relay pays** - for a wallet with no coins. Your node signs the listing
  and sends it over the relay network to the relay it enters through, which
  pays the fee and adds you to the peers it shares its rewards with. A month,
  always.

A listing can be renewed in its last three days and not before. Renewing is
always done by hand: a peer leaves simply by not renewing, and stops costing
its relay when the month runs out.

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
- **Names and Hosting** - shown as planned. Neither is built yet.

Footer
------

Your listing, the relay network, the wallet's lock and staking state with the
yearly rate staking pays, your peers (click to pause the network) and the
block height, with a progress bar while catching up.

New options
===========

| Option | Default | What it does |
|---|---|---|
| `-rosterindex` | on in BPS Relay, off in the node | Keep an index of the roster |
| `-rosterconnect` | on | Offer roster peers to the address manager |
| `-rosterindexstart`, `-rosterindexwindow` | | Where the index starts, and how far back it keeps |
| `-overlay` | on in BPS Relay, off in the node | Run the encrypted relay network |
| `-overlayport` | one above this node's peer-to-peer port (48931 on mainnet) | Its UDP port |
| `-mail` | on | Send and collect mail (needs the overlay) |
| `-mailbox` | on | Hold sealed mail for others (needs the overlay) |
| `-mailboxmaxsize` | 256 | Disk the mailbox may use, in MiB |
| `-acceptlistings` | off | Pay for the listings peers ask this node to publish |
| `-maxlistedusers` | 100 | Most peers to keep listed |
| `-listingwallet` | the only wallet open | Which wallet pays for listings |
| `-relayshare` | 0 | Percent of each block this node stakes, shared with its peers |

The default for `-datacarriersize` rises from 83 to 253 bytes, so this node
relays listings. It is relay policy only; blocks are validated as before.

New RPCs
========

`getrosterinfo`, `getroster`, `getrosterhistory`, `createannouncement`,
`publishrecord`, `requestlisting`, `getoverlayinfo`, `getrosterstaker`,
`dumprosterkey`, `addrosteruser`, `removerosteruser`, `getrelaypayout`, and for
mail `sendmail`, `checkmail`, `listmail`, `readmail`, `deletemail` and
`getmailinfo`. Each has its full description in `help`.

The node also advertises a new service bit, `NODE_ROSTER`, meaning it serves
the blocks a roster is built from, and `-blockfilterindex=roster` builds
compact filters that match listings.

Known issues
============

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
- `getmininginfo` and `getstakinginfo` fail when more than one wallet is open.
- On Linux the window can stay in the process list after quitting.
