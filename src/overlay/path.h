// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_PATH_H
#define BITCOIN_OVERLAY_PATH_H

#include <netaddress.h>
#include <pubkey.h>
#include <roster/record.h>

#include <map>
#include <stdint.h>
#include <vector>

/**
 * Forwarding: what a relay does with traffic that is not for it.
 *
 * These messages travel inside an established session, so they are already
 * encrypted and authenticated hop by hop before any of this is parsed. That is
 * why the frame layer is untouched here - it is settled and tested, and routing
 * is a different concern that belongs above it.
 *
 * Paths carry two kinds of traffic and the difference matters. Plain path data
 * is readable by every relay carrying it, which is enough when the only goal is
 * that the far end sees a relay rather than the origin. Traffic sealed for the
 * far end is not: each relay holds a key for its own leg and none for the one
 * beyond, so it forwards ciphertext.
 *
 * With more than one hop that separation becomes the point. The first relay
 * knows who is asking but not who is being reached; the last knows who is being
 * reached but has no address for who is asking - it is spoken to through a
 * path, which is why a peer here is a Hop and not an address. Paths this node
 * builds have three relays (DEFAULT_PATH_HOPS, overlay/select.h); the reason
 * for the middle one is written there.
 */
namespace overlay {

enum class MessageKind : uint8_t {
    APP_DATA = 0x01,   //!< payload addressed to this node
    PATH_BUILD = 0x02, //!< asks a relay to carry traffic onward
    PATH_OK = 0x03,    //!< the relay agreed
    PATH_FAIL = 0x04,  //!< the relay refused
    PATH_DATA = 0x05,  //!< carry this along an established path
    PATH_BIND = 0x06,  //!< a relay telling the far end it is a path's endpoint
    INTRODUCE = 0x07,  //!< a service telling a relay it can be reached this way
    MEET = 0x08,       //!< a client asking a relay to splice it to a service
    INTRODUCED = 0x09, //!< a meeting point answering a registration
};

/**
 * Where a message came from, or is going to.
 *
 * At the first hop that is an address. Past it, it is a path: the second relay
 * in a chain has no address for the client it is working for, and must not -
 * that is the whole reason for a second hop. Both are peers as far as
 * forwarding is concerned, so they share a type.
 */
struct Hop {
    CService addr;    //!< set when this is an adjacent peer
    uint64_t path{0}; //!< set when this is the far end of a path
    bool via_path{false};

    Hop() {}
    static Hop Direct(const CService& a)
    {
        Hop h;
        h.addr = a;
        return h;
    }
    static Hop Path(uint64_t id)
    {
        Hop h;
        h.path = id;
        h.via_path = true;
        return h;
    }
    bool IsValid() const { return via_path ? path != 0 : addr.IsValid(); }
    bool operator==(const Hop& o) const
    {
        if (via_path != o.via_path) return false;
        return via_path ? path == o.path : addr == o.addr;
    }
    bool operator!=(const Hop& o) const { return !(*this == o); }
    bool operator<(const Hop& o) const
    {
        if (via_path != o.via_path) return via_path < o.via_path;
        if (via_path) return path < o.path;
        return addr < o.addr;
    }
};

/** What a relay should do with a datagram on a path. */
enum class Route {
    UNKNOWN,  //!< no such path, or the sender is not one of its ends
    FORWARD,  //!< pass it to the other end
    DELIVER,  //!< this node is the end; hand it to the application
};

/** Encoded as kind(1) || body. */
bool EncodeAppData(const std::vector<unsigned char>& payload,
                   std::vector<unsigned char>& out);
/**
 * kind || path_id(8) || next hop as addrv2 || optionally its key(33).
 *
 * With the key, a relay that has no session with the next hop yet may open
 * one - but only to a relay the roster lists at that address with that key
 * (Relay::SetDialPolicy). Without it, the relay joins only peers it already
 * has a session with, as before.
 */
bool EncodePathBuild(uint64_t path_id, const CService& next_hop,
                     std::vector<unsigned char>& out,
                     const CPubKey& next_key = CPubKey());
bool EncodePathResult(bool ok, uint64_t path_id, std::vector<unsigned char>& out);
bool EncodePathData(uint64_t path_id, const std::vector<unsigned char>& inner,
                    std::vector<unsigned char>& out);
bool EncodePathBind(uint64_t path_id, std::vector<unsigned char>& out);
bool DecodePathBind(const std::vector<unsigned char>& msg, uint64_t& path_id_out);

bool EncodeIntroduce(const roster::KeyBytes& service, std::vector<unsigned char>& out);
bool DecodeIntroduce(const std::vector<unsigned char>& msg, roster::KeyBytes& service_out);
/** The meeting point's answer to INTRODUCE: whether `service` is now registered there. */
bool EncodeIntroduced(bool ok, const roster::KeyBytes& service, std::vector<unsigned char>& out);
bool DecodeIntroduced(const std::vector<unsigned char>& msg, bool& ok_out, roster::KeyBytes& service_out);
bool EncodeMeet(const roster::KeyBytes& service, uint64_t meet_id,
                std::vector<unsigned char>& out);
bool DecodeMeet(const std::vector<unsigned char>& msg, roster::KeyBytes& service_out,
                uint64_t& meet_id_out);

bool DecodeKind(const std::vector<unsigned char>& msg, MessageKind& kind_out);
bool DecodeAppData(const std::vector<unsigned char>& msg,
                   std::vector<unsigned char>& payload_out);
bool DecodePathBuild(const std::vector<unsigned char>& msg, uint64_t& path_id_out,
                     CService& next_hop_out);
bool DecodePathBuild(const std::vector<unsigned char>& msg, uint64_t& path_id_out,
                     CService& next_hop_out, CPubKey& next_key_out);
bool DecodePathResult(const std::vector<unsigned char>& msg, bool& ok_out,
                      uint64_t& path_id_out);
bool DecodePathData(const std::vector<unsigned char>& msg, uint64_t& path_id_out,
                    std::vector<unsigned char>& inner_out);

/**
 * A relay's forwarding table.
 *
 * Each entry joins two peers that already have their own session with this
 * relay. Direction is inferred from who a datagram arrived from, so an entry
 * is usable only by its two ends - a third party knowing the path id cannot
 * inject into it, because it is not either end of it.
 *
 * Both limits below exist because building paths is something strangers ask a
 * relay to do. Without them, memory is free to consume and an abandoned path
 * lives forever.
 */
class PathTable
{
public:
    /** Refused past this many live paths, so a relay's memory is bounded. */
    static constexpr size_t MAX_PATHS = 1024;
    /** Idle paths are dropped after this long, in seconds. */
    static constexpr int64_t PATH_TTL = 600;

    /**
     * Add a path.
     *
     * Refuses a duplicate id rather than replacing it. Replacing would let
     * anyone who guessed or observed an id redirect somebody else's traffic,
     * which is a hijack rather than a collision.
     */
    bool Create(uint64_t path_id, const Hop& upstream, const Hop& downstream,
                int64_t now);

    /**
     * Add a path this node is the far end of.
     *
     * Traffic arriving on it is delivered locally rather than forwarded, and a
     * reply goes back upstream. Without this the destination would drop
     * everything it was sent, having never asked for the path itself.
     */
    bool CreateEndpoint(uint64_t path_id, const Hop& upstream, int64_t now);

    /**
     * What to do with a datagram on this path.
     *
     * UNKNOWN when there is no such path, or when the sender is not one of its
     * ends - knowing an id is not membership of it. Refreshes the path's
     * activity time otherwise, so a path in use is not expired underneath it.
     */
    Route Next(uint64_t path_id, const Hop& from, Hop& to_out, int64_t now);

    /** Drop paths idle for longer than PATH_TTL. Returns how many went. */
    size_t Expire(int64_t now);

    /** Drop one path, when this node is done with a path it built. */
    bool Remove(uint64_t path_id);

    /** Whether this path already joins exactly these two peers. */
    bool Joins(uint64_t path_id, const Hop& upstream, const Hop& downstream) const;

    /**
     * Which hop carries a path we are an end of.
     *
     * Only meaningful at an end: a relay in the middle of a path has two
     * carriers and no reason to ask. False when the path is unknown or when
     * this node is not one of its ends.
     */
    bool Carrier(uint64_t path_id, Hop& out) const;

    bool Has(uint64_t path_id) const;
    size_t Size() const { return m_paths.size(); }

private:
    struct Entry {
        Hop upstream;
        Hop downstream; //!< invalid when this node is the endpoint
        int64_t last_used{0};
    };
    std::map<uint64_t, Entry> m_paths;
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_PATH_H
