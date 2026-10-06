// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NAMES_RESOLVE_H
#define BITCOIN_NAMES_RESOLVE_H

#include <names/state.h>
#include <roster/record.h>

#include <string>

/**
 * Turning what a person typed into a key.
 *
 * In this order: a key written out in full; a petname from this user's own
 * address book; a registered name. The petname comes first on purpose - it is
 * the user's own word for someone and can only be wrong for them, while a
 * registered name is a stranger's claim to a word.
 */
namespace names {

enum class Source {
    KEY,
    PETNAME,
    NAME,
};
std::string SourceString(Source source);

struct Target {
    roster::KeyBytes key{};
    Source source{Source::KEY};
    std::string label;   //!< the petname or name used, normalised
    Resolution name;     //!< set when source is NAME
    int depth{0};        //!< blocks since the name last changed, when source is NAME
};

/** False with `error` set when `text` is none of the three. */
bool ResolveTarget(const std::string& text, Target& out, std::string& error);

} // namespace names

#endif // BITCOIN_NAMES_RESOLVE_H
