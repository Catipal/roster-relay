// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <companion/protocol.h>

#include <crypto/common.h>
#include <hash.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>

namespace companion {

bool KnownOp(uint8_t raw)
{
    switch (static_cast<Op>(raw)) {
    case Op::PAIR:
    case Op::PAIR_STATUS:
    case Op::STATUS:
    case Op::ADDRESS:
    case Op::HISTORY:
    case Op::PREPARE:
    case Op::SEND:
    case Op::CANCEL:
    case Op::RELAYS:
    case Op::SET_PIN:
    case Op::UNPAIR:
    case Op::RESULT:
    case Op::PAIR_STATE:
    case Op::STATUS_INFO:
    case Op::ADDRESS_INFO:
    case Op::HISTORY_ITEMS:
    case Op::PREPARED:
    case Op::SENT:
    case Op::RELAY_LIST:
        return true;
    }
    return false;
}

std::vector<unsigned char> EncodeMessage(const Message& msg)
{
    std::vector<unsigned char> out;
    out.reserve(9 + msg.body.size());
    out.push_back(static_cast<uint8_t>(msg.op));
    unsigned char req[8];
    WriteLE64(req, msg.req);
    out.insert(out.end(), req, req + 8);
    out.insert(out.end(), msg.body.begin(), msg.body.end());
    return out;
}

bool DecodeMessage(const std::vector<unsigned char>& raw, Message& out)
{
    if (raw.size() < 9 || !KnownOp(raw[0])) return false;
    out.op = static_cast<Op>(raw[0]);
    out.req = ReadLE64(raw.data() + 1);
    out.body.assign(raw.begin() + 9, raw.end());
    return true;
}

Message Result(uint64_t req, bool ok, const std::string& text)
{
    ResultAnswer r;
    r.ok = ok;
    r.text = text.substr(0, MAX_RESULT_TEXT);
    return Make(Op::RESULT, req, r);
}

std::string EncodeTicket(const PairingTicket& ticket)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << ticket;
    const std::vector<unsigned char> raw(s.begin(), s.end());
    std::string text = EncodeBase32(raw, /* pad */ false);
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return std::toupper(c); });
    return TICKET_PREFIX + text;
}

bool DecodeTicket(const std::string& text, PairingTicket& out, std::string& error)
{
    std::string t;
    for (const char c : text) {
        // Pasted codes pick up line breaks and spaces on the way.
        if (!std::isspace(static_cast<unsigned char>(c))) t.push_back(c);
    }
    std::string upper = t;
    std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) { return std::toupper(c); });
    const std::string prefix(TICKET_PREFIX);
    if (upper.compare(0, prefix.size(), prefix) != 0) {
        error = "That is not a pairing code from a BPS home node.";
        return false;
    }
    std::string body = t.substr(prefix.size());
    std::transform(body.begin(), body.end(), body.begin(), [](unsigned char c) { return std::tolower(c); });
    // DecodeBase32 wants the padding a QR code is better off without.
    while (body.size() % 8 != 0) body.push_back('=');
    bool invalid = false;
    const std::vector<unsigned char> raw = DecodeBase32(body.c_str(), &invalid);
    if (invalid || raw.empty()) {
        error = "The pairing code is damaged. Scan it again, or copy all of it.";
        return false;
    }
    try {
        CDataStream s(raw, SER_NETWORK, PROTOCOL_VERSION);
        s >> out;
        if (!s.empty()) throw std::ios_base::failure("trailing bytes");
    } catch (const std::ios_base::failure&) {
        error = "The pairing code is damaged. Scan it again, or copy all of it.";
        return false;
    }
    if (out.version != 1) {
        error = "This pairing code is from a newer home node. Update the app.";
        return false;
    }
    if (!out.node.IsFullyValid() || out.relays.size() > MAX_RELAYS) {
        error = "The pairing code is damaged. Scan it again, or copy all of it.";
        return false;
    }
    return true;
}

std::string PairingCode(const uint256& token, const CPubKey& device, const CPubKey& node)
{
    CHashWriter h = TaggedHash("BPS/companion/pair/v1");
    h << token << device << node;
    const uint256 digest = h.GetSHA256();
    const uint32_t n = ReadLE32(digest.begin()) % 1000000;
    std::string code = std::to_string(n);
    return std::string(6 - code.size(), '0') + code;
}

uint256 SendDigest(const CPubKey& node, const uint256& prepare_id, const CScript& payee, CAmount amount, CAmount fee)
{
    CHashWriter h = TaggedHash("BPS/companion/send/v1");
    h << node << prepare_id << payee << amount << fee;
    return h.GetSHA256();
}

bool ValidPin(const std::string& pin)
{
    if (pin.size() < MIN_PIN || pin.size() > MAX_PIN) return false;
    return std::all_of(pin.begin(), pin.end(), [](char c) { return c >= '0' && c <= '9'; });
}

} // namespace companion
