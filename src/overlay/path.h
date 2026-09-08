// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_PATH_H
#define BITCOIN_OVERLAY_PATH_H

#include <netaddress.h>

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
 * What this stage does NOT provide is anonymity. A relay forwarding a payload
 * at this point can read it: there is one hop, and the two ends share no key
 * the relay lacks. Layered encryption and longer paths are the next stage, and
 * until then the honest description of a relay is "a router that can see your
 * traffic", not "an anonymity hop".
 */
namespace overlay {

enum class MessageKind : uint8_t {
    APP_DATA = 0x01,   //!< payload addressed to this node
    PATH_BUILD = 0x02, //!< asks a relay to carry traffic onward
    PATH_OK = 0x03,    //!< the relay agreed
    PATH_FAIL = 0x04,  //!< the relay refused
    PATH_DATA = 0x05,  //!< carry this along an established path
    PATH_BIND = 0x06,  //!< a relay telling the far end it is a path's endpoint
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
bool EncodePathBuild(uint64_t path_id, const CService& next_hop,
                     std::vector<unsigned char>& out);
bool EncodePathResult(bool ok, uint64_t path_id, std::vector<unsigned char>& out);
bool EncodePathData(uint64_t path_id, const std::vector<unsigned char>& inner,
                    std::vector<unsigned char>& out);
bool EncodePathBind(uint64_t path_id, std::vector<unsigned char>& out);
bool DecodePathBind(const std::vector<unsigned char>& msg, uint64_t& path_id_out);

bool DecodeKind(const std::vector<unsigned char>& msg, MessageKind& kind_out);
bool DecodeAppData(const std::vector<unsigned char>& msg,
                   std::vector<unsigned char>& payload_out);
bool DecodePathBuild(const std::vector<unsigned char>& msg, uint64_t& path_id_out,
                     CService& next_hop_out);
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
    bool Create(uint64_t path_id, const CService& upstream,
                const CService& downstream, int64_t now);

    /**
     * Add a path this node is the far end of.
     *
     * Traffic arriving on it is delivered locally rather than forwarded, and a
     * reply goes back upstream. Without this the destination would drop
     * everything it was sent, having never asked for the path itself.
     */
    bool CreateEndpoint(uint64_t path_id, const CService& upstream, int64_t now);

    /**
     * What to do with a datagram on this path.
     *
     * UNKNOWN when there is no such path, or when the sender is not one of its
     * ends - knowing an id is not membership of it. Refreshes the path's
     * activity time otherwise, so a path in use is not expired underneath it.
     */
    Route Next(uint64_t path_id, const CService& from, CService& to_out, int64_t now);

    /** Drop paths idle for longer than PATH_TTL. Returns how many went. */
    size_t Expire(int64_t now);

    bool Has(uint64_t path_id) const;
    size_t Size() const { return m_paths.size(); }

private:
    struct Entry {
        CService upstream;
        CService downstream; //!< invalid when this node is the endpoint
        int64_t last_used{0};
    };
    std::map<uint64_t, Entry> m_paths;
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_PATH_H
