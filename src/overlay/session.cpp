// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/session.h>

#include <crypto/common.h>
#include <support/cleanse.h>

namespace overlay {

namespace {
/** Chosen so short control messages stay cheap and everything else collapses. */
const size_t BUCKETS[] = {64, 256, 640, MAX_FRAME_PAYLOAD};
} // namespace

size_t PaddedSize(size_t payload_len)
{
    const size_t needed = payload_len + SESSION_LENGTH_PREFIX;
    for (size_t i = 0; i < sizeof(BUCKETS) / sizeof(BUCKETS[0]); ++i) {
        if (needed <= BUCKETS[i]) return BUCKETS[i];
    }
    return MAX_FRAME_PAYLOAD;
}

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
    if (payload.size() > MAX_SESSION_PAYLOAD) return false;
    if (Remaining() == 0) return false;

    // length(2) || payload || zeros, all inside the encryption, so the real
    // length is recoverable by the far end and by nobody else.
    std::vector<unsigned char> padded(PaddedSize(payload.size()), 0);
    WriteLE16(padded.data(), static_cast<uint16_t>(payload.size()));
    std::copy(payload.begin(), payload.end(), padded.begin() + SESSION_LENGTH_PREFIX);

    if (!SealFrame(m_send, FrameType::DATA, m_id, m_next_counter, padded,
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

    if (payload.size() < SESSION_LENGTH_PREFIX) return false;
    const size_t real = ReadLE16(payload.data());
    // A length claiming more than arrived is a malformed frame from an
    // authenticated peer, which is a bug or a version difference, not an
    // attack - but it is still refused rather than truncated.
    if (real > payload.size() - SESSION_LENGTH_PREFIX) return false;

    payload_out.assign(payload.begin() + SESSION_LENGTH_PREFIX,
                       payload.begin() + SESSION_LENGTH_PREFIX + real);
    return true;
}

} // namespace overlay
