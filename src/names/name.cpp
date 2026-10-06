// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <names/name.h>

#include <limits>

namespace names {

bool Normalize(const std::string& in, std::string& out)
{
    out.clear();
    out.reserve(in.size());
    for (const char c : in) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u >= 0x80) return false;
        out.push_back((u >= 'A' && u <= 'Z') ? static_cast<char>(u - 'A' + 'a') : c);
    }
    return true;
}

bool IsValidLabel(const std::string& label)
{
    if (label.empty() || label.size() > MAX_LABEL_LENGTH) return false;
    if (label.front() == '-' || label.back() == '-') return false;
    for (size_t i = 0; i < label.size(); ++i) {
        const char c = label[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok) return false;
        // No double hyphen: it is how internationalised names are encoded
        // elsewhere (xn--), and refusing it keeps one spelling per name.
        if (c == '-' && i > 0 && label[i - 1] == '-') return false;
    }
    return true;
}

bool IsValidRoot(const std::string& root)
{
    return IsValidLabel(root) && root.size() >= MIN_ROOT_LENGTH;
}

bool SplitName(const std::string& full, std::string& root, std::string& label)
{
    root.clear();
    label.clear();
    const size_t dot = full.find('.');
    if (dot == std::string::npos) {
        root = full;
        return IsValidRoot(root);
    }
    if (full.find('.', dot + 1) != std::string::npos) return false;
    label = full.substr(0, dot);
    root = full.substr(dot + 1);
    return IsValidLabel(label) && IsValidRoot(root);
}

std::string Skeleton(const std::string& label)
{
    std::string out;
    out.reserve(label.size());
    for (size_t i = 0; i < label.size(); ++i) {
        const char c = label[i];
        const char next = i + 1 < label.size() ? label[i + 1] : '\0';
        if (c == 'r' && next == 'n') {
            out.push_back('m');
            ++i;
        } else if (c == 'v' && next == 'v') {
            out.push_back('w');
            ++i;
        } else if (c == '0') {
            out.push_back('o');
        } else if (c == '1') {
            out.push_back('l');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

CAmount PricePerYear(size_t length)
{
    // Shorter names are scarcer and more fought over; a flat price would hand
    // them to whoever scripts fastest. Burned, not paid to anyone: a fee would
    // go to the staker of the block, who could then register for free.
    if (length < MIN_ROOT_LENGTH || length > MAX_LABEL_LENGTH) return 0;
    if (length == 3) return 100 * COIN;
    if (length == 4) return 20 * COIN;
    if (length == 5) return 5 * COIN;
    return 1 * COIN;
}

CAmount Price(size_t length, uint32_t blocks)
{
    const CAmount per_year = PricePerYear(length);
    if (per_year == 0) return 0;
    // At most 100 coins a year for two years: 2e10 * 350640 fits in 64 bits.
    return (per_year * (CAmount)blocks + BLOCKS_PER_YEAR - 1) / BLOCKS_PER_YEAR;
}

int StartHeight(const std::string& chain_id)
{
    if (chain_id == "main") return std::numeric_limits<int>::max();
    return 0;
}

} // namespace names
