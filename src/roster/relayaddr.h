// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_RELAYADDR_H
#define BITCOIN_ROSTER_RELAYADDR_H

#include <fs.h>
#include <roster/record.h>
#include <sync.h>

#include <array>
#include <functional>
#include <map>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

class CKey;
class CNetAddr;
class CService;

/**
 * A relay's current address, announced while it is online instead of written
 * to the chain.
 *
 * The chain lists a relay by its key, with SERVICE_RELAY_CAPABLE and no
 * endpoint: who exists, which is what the chain is for (§0). Where it is now
 * is a short message the relay signs with that key and its peers pass on, as
 * revocations are passed on (§9): newest wins, and it counts for three hours
 * after it was signed. A relay signs a new one every hour while it runs, and
 * as soon as it may when its address changes. So:
 *
 *  - a new address needs no transaction, and takes effect in minutes rather
 *    than at the listing's next renewal;
 *  - no address ever lands on the permanent chain, which §8 says it should
 *    not ("never write anything to the chain that you might one day want to
 *    take back");
 *  - "online" means an announcement signed in the last three hours, which is
 *    what Discovery shows, and a relay that stops running leaves everyone's
 *    paths within those three hours.
 *
 * What the chain no longer gives for the address is agreement: a relay could
 * show different addresses to different peers. Nothing rests on that - the
 * transport proves the key whatever the address (§0), and meeting points are
 * computed from keys the chain lists, not from addresses.
 *
 * Announcements are taken only for keys the roster lists live as relays and
 * has not seen revoked, which is what keeps anyone from filling the table.
 * Records with an endpoint on the chain keep working as before.
 */
namespace roster {

/**
 * How long an announcement counts after it was signed: three refreshes, so a
 * relay that stops running drops out of everyone's paths within three hours,
 * and one whose refresh is lost on the way still counts.
 */
static constexpr int64_t RELAY_ADDR_TTL = 3 * 60 * 60;
/** How often a running relay signs its address again. */
static constexpr int64_t RELAY_ADDR_REFRESH = 60 * 60;
/**
 * The least time between two announcements of one relay that the network
 * takes. Bounds what a listed relay can make everyone pass on to twelve an
 * hour; an address that changes sooner waits for it.
 */
static constexpr int64_t RELAY_ADDR_MIN_INTERVAL = 5 * 60;
/** How far ahead of this node's clock a signing time may be. */
static constexpr int64_t RELAY_ADDR_FUTURE = 10 * 60;
/** Addresses one announcement carries: an IPv4 and an IPv6, at most. */
static constexpr size_t MAX_RELAY_ADDR_ENDPOINTS = 2;
/** The longest announcement: two IPv6 endpoints. */
static constexpr size_t MAX_RELAY_ADDR_SIZE = 1 + 32 + 8 + 1 + 2 * (1 + 16 + 2) + 64;
/** Announcements held at once; one per relay. */
static constexpr size_t MAX_RELAY_ADDRESSES = 50000;
/** Announcements in one message. */
static constexpr size_t MAX_RELAY_ADDRS_PER_MSG = 1000;
/** Announcements handed to a peer that asks, newest first. */
static constexpr size_t RELAY_ADDRS_ON_REQUEST = 10000;

struct RelayAddress {
    KeyBytes key{};
    int64_t time{0};                    //!< unix seconds when signed
    std::vector<Endpoint> endpoints;    //!< IPv4 or IPv6 peer-to-peer endpoints; the overlay is one port above
    std::array<unsigned char, 64> sig{};
};

/** version(1) key(32) time(8, little-endian) count(1) endpoints sig(64). */
std::vector<unsigned char> SerializeRelayAddress(const RelayAddress& a);
/** False for anything malformed, or carrying a network other than IPv4 or IPv6. */
bool ParseRelayAddress(const std::vector<unsigned char>& raw, RelayAddress& out);
/** Sign `a` with `key`, whose x-only public key must be `a.key`. */
bool SignRelayAddress(RelayAddress& a, const CKey& key, const std::string& chain_id);
bool VerifyRelayAddress(const RelayAddress& a, const std::string& chain_id);

class RelayAddressBook
{
public:
    enum class AddResult {
        NEW,       //!< taken, and newer than anything held: pass it on
        KNOWN,     //!< held already, older than what is held, or too soon after it
        STALE,     //!< expired, or signed ahead of this node's clock: clocks differ, so no fault
        INVALID,   //!< malformed or badly signed: the sender's fault
        NOT_RELAY, //!< the roster does not list that key as a relay that announces
    };
    /** Whether the roster lists `key` live, as a relay, and not revoked. */
    using RelayCheck = std::function<bool(const KeyBytes& key)>;

    explicit RelayAddressBook(const std::string& chain_id) : m_chain_id(chain_id) {}

    AddResult Add(const std::vector<unsigned char>& raw, int64_t now, const RelayCheck& is_relay);
    /** The freshest announcement for `key`, if one counts at `now`. */
    bool Current(const KeyBytes& key, int64_t now, RelayAddress& out) const;
    /** Announcements that count at `now`, newest first, at most `max`, as received. */
    std::vector<std::vector<unsigned char>> FreshRaw(int64_t now, size_t max) const;
    /** Changes with every announcement taken or dropped, for readers that cache. */
    uint64_t Generation() const;
    /** Drop what no longer counts. */
    void Expire(int64_t now);
    size_t Size() const;

    /**
     * This node's own key, while it announces as a relay, so a peer that
     * connects is handed its announcement at once: one signed while this
     * node had no peers, after a restart, would otherwise wait for the
     * hourly refresh to go round.
     */
    void SetOwn(const KeyBytes& key);
    /** This node's own announcement, as received, if it holds one that counts at `now`. */
    bool OwnRaw(int64_t now, std::vector<unsigned char>& raw_out) const;

private:
    struct Entry {
        RelayAddress parsed;
        std::vector<unsigned char> raw;
    };
    const std::string m_chain_id;
    mutable Mutex m_mutex;
    std::map<KeyBytes, Entry> m_entries GUARDED_BY(m_mutex);
    uint64_t m_generation GUARDED_BY(m_mutex){0};
    bool m_have_own GUARDED_BY(m_mutex){false};
    KeyBytes m_own GUARDED_BY(m_mutex){};
};

/** Every node's book, or null when the roster index is off. */
extern std::unique_ptr<RelayAddressBook> g_relay_addresses;

/** Whether a parsed announcement record lists a relay that announces its address. */
inline bool IsAnnouncingRelay(uint32_t services) { return (services & SERVICE_RELAY_CAPABLE) != 0; }

/**
 * When a running relay should date its next announcement, or 0 for not now:
 * `now` when it has none that counts or the last is due for refreshing; when
 * its address changed, `now` or RELAY_ADDR_MIN_INTERVAL after the last,
 * whichever is later - the network takes nothing sooner - as long as that is
 * well within how far ahead the network takes it. So a new address goes out
 * at once even just after an announcement, and still no more than about
 * twelve an hour.
 *
 * `last` is the relay's own last announcement, kept across restarts, since
 * the network still holds it after one.
 */
int64_t NextAnnouncementTime(const std::vector<Endpoint>& current, const RelayAddress* last, int64_t now);

/** A relay's own last announcement, kept in `path` so a restart knows it. */
bool ReadOwnRelayAddress(const fs::path& path, const std::string& chain_id, RelayAddress& out,
                         std::vector<unsigned char>& raw_out);
bool WriteOwnRelayAddress(const fs::path& path, const std::vector<unsigned char>& raw);

/**
 * The addresses a relay announces, at most one IPv4 and one IPv6, all at
 * `port`:
 *
 *  - the ones it was told to announce (-relayaddress), and nothing else;
 *  - otherwise the address most of its outbound peers see it at, when at
 *    least two agree: what the rest of the internet sees, so it follows a
 *    home line's address when the provider changes it;
 *  - then, for a family still missing, the best address the node knows of
 *    itself (-externalip, its interfaces, a mapped port), best first in `local`.
 *
 * Only routable addresses unless `allow_local`, which is for regtest.
 */
std::vector<Endpoint> ChooseRelayEndpoints(const std::vector<CService>& fixed, const std::vector<CNetAddr>& seen,
                                           const std::vector<CNetAddr>& local, uint16_t port, bool allow_local);

} // namespace roster

#endif // BITCOIN_ROSTER_RELAYADDR_H
