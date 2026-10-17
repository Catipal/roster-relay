// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/transport.h>

#include <util/time.h>

#include <cstring>

namespace overlay {

namespace {

/**
 * Wrap a handshake message in a datagram.
 *
 * Handshake datagrams are not sealed by the frame layer - there is no key yet,
 * which is the point of sending them. The header exists so a receiver can tell
 * what arrived, and the message carries its own authentication. Session and
 * counter are zero and are required to be zero on receipt: unused fields that
 * accept any value are tamper surface for nothing in return.
 */
void PackHandshake(FrameType type, const std::vector<unsigned char>& msg,
                   std::vector<unsigned char>& out)
{
    out.clear();
    WriteFrameHeader(type, 0, 0, out);
    out.insert(out.end(), msg.begin(), msg.end());
}

} // namespace

template <typename PeerKey>
TransportT<PeerKey>::TransportT(const CKey& static_key) : m_static(static_key) {}

template <typename PeerKey>
bool TransportT<PeerKey>::Connect(const PeerKey& peer, const CPubKey& peer_static,
                        std::vector<unsigned char>& datagram_out, bool throwaway)
{
    // With `throwaway`, a key made for this handshake proves nothing about who
    // opened the session. Answering is unchanged: a peer that dials this node
    // reached the key it asked for, which only the static key can prove.
    if (throwaway) {
        // Made for this handshake and kept only as long as the handshake is.
        CKey once;
        once.MakeNewKey(true);
        return ConnectAs(peer, peer_static, once, datagram_out);
    }
    return ConnectAs(peer, peer_static, m_static, datagram_out);
}

template <typename PeerKey>
bool TransportT<PeerKey>::ConnectAs(const PeerKey& peer, const CPubKey& peer_static,
                                    const CKey& as, std::vector<unsigned char>& datagram_out)
{
    if (!as.IsValid() || !peer_static.IsValid()) return false;

    // A handshake already in flight is abandoned rather than kept: a peer that
    // never answers must not hold the slot against a later attempt.
    m_pending.erase(peer);

    Pending pending;
    pending.expected = peer_static;
    std::vector<unsigned char> msg1;
    if (!pending.initiator.Start(as, peer_static, msg1)) return false;

    PackHandshake(FrameType::HANDSHAKE_INIT, msg1, datagram_out);
    m_pending[peer] = std::move(pending);
    return true;
}

template <typename PeerKey>
typename TransportT<PeerKey>::Result TransportT<PeerKey>::Receive(const PeerKey& from, const unsigned char* data,
                                     size_t len, std::vector<unsigned char>& reply_out,
                                     std::vector<unsigned char>& payload_out)
{
    reply_out.clear();
    payload_out.clear();

    FrameType type;
    uint64_t session = 0, counter = 0;
    if (!PeekFrame(data, len, type, session, counter)) return TransportT<PeerKey>::Result::IGNORED;

    const unsigned char* body = data + FRAME_HEADER_SIZE;
    const size_t body_len = len - FRAME_HEADER_SIZE;

    switch (type) {
    case FrameType::HANDSHAKE_INIT: {
        if (session != 0 || counter != 0) return TransportT<PeerKey>::Result::IGNORED;

        // Anyone may open a handshake, and this is where a flood would land.
        // Nothing here is expensive enough to be a resource attack on its own,
        // but the socket layer above still has to rate limit by source, because
        // a responder does real key agreement before it learns anything.
        CPubKey initiator;
        std::vector<unsigned char> msg2;
        SessionKeys keys;
        HandshakeResponder responder;
        if (!responder.Accept(m_static, body, body_len, initiator, msg2, keys)) {
            return TransportT<PeerKey>::Result::IGNORED;
        }

        // A completed handshake replaces whatever was there. The peer proved
        // it holds the static key, which is a stronger claim than the age of
        // an existing entry.
        Established est;
        est.session.reset(new Session(keys));
        est.identity = initiator;
        est.heard = GetTime();
        m_sessions[from] = std::move(est);
        m_pending.erase(from);

        PackHandshake(FrameType::HANDSHAKE_RESP, msg2, reply_out);
        return TransportT<PeerKey>::Result::ESTABLISHED;
    }

    case FrameType::HANDSHAKE_RESP: {
        if (session != 0 || counter != 0) return TransportT<PeerKey>::Result::IGNORED;

        typename std::map<PeerKey, Pending>::iterator it = m_pending.find(from);
        if (it == m_pending.end()) return TransportT<PeerKey>::Result::IGNORED;

        SessionKeys keys;
        // A rejected reply leaves the handshake intact, so the pending entry
        // survives to be completed by the real one. Discarding it here would
        // let anyone spoofing the peer's address end a handshake with a single
        // junk datagram.
        if (!it->second.initiator.Finish(body, body_len, keys)) {
            return TransportT<PeerKey>::Result::IGNORED;
        }
        const CPubKey expected = it->second.expected;
        m_pending.erase(it);

        Established est;
        est.session.reset(new Session(keys));
        // The responder authenticated itself by completing the exchange, so
        // its identity is the key we deliberately encrypted to.
        est.identity = expected;
        est.heard = GetTime();
        m_sessions[from] = std::move(est);
        return TransportT<PeerKey>::Result::ESTABLISHED;
    }

    case FrameType::DATA: {
        typename std::map<PeerKey, Established>::iterator it = m_sessions.find(from);
        if (it == m_sessions.end()) return TransportT<PeerKey>::Result::IGNORED;
        // The session id in the header is only a hint for lookup; Open checks
        // it against the authenticated one and verifies the tag.
        if (!it->second.session->Open(data, len, payload_out)) return TransportT<PeerKey>::Result::IGNORED;
        it->second.heard = GetTime();
        it->second.unanswered_since = 0;
        return TransportT<PeerKey>::Result::PAYLOAD;
    }
    }

    return TransportT<PeerKey>::Result::IGNORED;
}

template <typename PeerKey>
bool TransportT<PeerKey>::Send(const PeerKey& peer, const std::vector<unsigned char>& payload,
                     std::vector<unsigned char>& datagram_out, bool pad)
{
    typename std::map<PeerKey, Established>::iterator it = m_sessions.find(peer);
    if (it == m_sessions.end()) return false;
    if (it->second.unanswered_since == 0) it->second.unanswered_since = GetTime();
    return it->second.session->Seal(payload, datagram_out, pad);
}

template <typename PeerKey>
bool TransportT<PeerKey>::HasSession(const PeerKey& peer) const
{
    return m_sessions.find(peer) != m_sessions.end();
}

template <typename PeerKey>
bool TransportT<PeerKey>::Live(const PeerKey& peer, int64_t now) const
{
    typename std::map<PeerKey, Established>::const_iterator it = m_sessions.find(peer);
    if (it == m_sessions.end()) return false;
    const Established& est = it->second;
    if (now - est.heard >= HOP_QUIET) return false;
    return est.unanswered_since == 0 || now - est.unanswered_since < HOP_ANSWER;
}

template <typename PeerKey>
bool TransportT<PeerKey>::HasPendingHandshake(const PeerKey& peer) const
{
    return m_pending.find(peer) != m_pending.end();
}

template <typename PeerKey>
CPubKey TransportT<PeerKey>::PeerIdentity(const PeerKey& peer) const
{
    typename std::map<PeerKey, Established>::const_iterator it = m_sessions.find(peer);
    if (it == m_sessions.end()) return CPubKey();
    return it->second.identity;
}

template <typename PeerKey>
void TransportT<PeerKey>::Forget(const PeerKey& peer)
{
    m_sessions.erase(peer);
    m_pending.erase(peer);
}

// Explicit instantiations: hop sessions keyed by address, path sessions keyed
// by path id. Keeping the definitions here rather than in the header means the
// tested code did not have to move.
template class TransportT<CService>;
template class TransportT<uint64_t>;

} // namespace overlay
