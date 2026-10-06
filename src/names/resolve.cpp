// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <names/resolve.h>

#include <index/nameindex.h>
#include <names/name.h>
#include <names/petnames.h>
#include <util/strencodings.h>
#include <tinyformat.h>
#include <util/string.h>

namespace names {

std::string SourceString(Source source)
{
    switch (source) {
    case Source::KEY: return "key";
    case Source::PETNAME: return "petname";
    case Source::NAME: return "name";
    }
    return "unknown";
}

bool ResolveTarget(const std::string& text, Target& out, std::string& error)
{
    out = Target();
    const std::string trimmed = TrimString(text);
    if (trimmed.empty()) {
        error = "Nothing to resolve.";
        return false;
    }
    if (trimmed.size() == 64 && IsHex(trimmed)) {
        const std::vector<unsigned char> raw = ParseHex(trimmed);
        std::copy(raw.begin(), raw.end(), out.key.begin());
        out.source = Source::KEY;
        return true;
    }
    Petname pet;
    if (g_petnames && g_petnames->Find(trimmed, pet)) {
        out.key = pet.key;
        out.source = Source::PETNAME;
        out.label = pet.label;
        return true;
    }
    if (!g_nameindex) {
        error = strprintf("%s is not a key or a petname, and this node keeps no name index (-nameindex) to look names up in.",
                          trimmed);
        return false;
    }
    std::shared_ptr<const NameState> state;
    int height = 0;
    if (!g_nameindex->GetState(state, height)) {
        error = "The name index could not be read.";
        return false;
    }
    Resolution res;
    std::string why;
    if (!state->Resolve(trimmed, height, res, why)) {
        error = why;
        return false;
    }
    out.key = res.key;
    out.source = Source::NAME;
    out.label = res.name;
    out.name = res;
    out.depth = height - res.changed;
    return true;
}

} // namespace names
