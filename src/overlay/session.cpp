// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/session.h>

#include <support/cleanse.h>

namespace overlay {

Session::Session(const SessionKeys& keys)
    : m_send(keys.send), m_recv(keys.recv), m_id(keys.session_id)
{
}

Session::~Session()
{
    memory_cleanse(m_send.data(), m_send.size());
    memory_cleanse(m_recv.data(), m_recv.size());
}

uint64_t Session::Remaining() const
{
    // Counters run from 1 upwards, so the last usable one is UINT64_MAX.
    return UINT64_MAX - m_next_counter + 1;
}

bool Session::Seal(const std::vector<unsigned char>& payload,
                   std::vector<unsigned char>& datagram_out)
{
    if (payload.size() > MAX_FRAME_PAYLOAD) return false;
    if (Remaining() == 0) return false;

    if (!SealFrame(m_send, FrameType::DATA, m_id, m_next_counter, payload,
                   datagram_out)) {
        return false;
    }
    // Only advance once the frame exists, so a failure cannot burn a counter
    // and leave a gap the peer's replay window would have to tolerate.
    ++m_next_counter;
    return true;
}

bool Session::Open(const unsigned char* data, size_t len,
                   std::vector<unsigned char>& payload_out)
{
    FrameType type;
    uint64_t session = 0, counter = 0;
    std::vector<unsigned char> payload;
    if (!OpenFrame(m_recv, data, len, type, session, counter, payload)) return false;

    // The session id is authenticated, so this cannot be spoofed - but a peer
    // holding several sessions must still not accept one session's frame on
    // another, and the key alone would already prevent that. Checked anyway,
    // because relying on a second mechanism for a first-order property is how
    // the first one quietly stops being load-bearing.
    if (session != m_id) return false;
    if (type != FrameType::DATA) return false;
    if (!m_replay.Accept(counter)) return false;

    payload_out = std::move(payload);
    return true;
}

} // namespace overlay
