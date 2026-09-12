// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/keystore.h>

#include <fs.h>
#include <logging.h>
#include <support/cleanse.h>

#include <algorithm>
#include <util/system.h>

namespace roster {

namespace {

constexpr size_t SECRET_SIZE = 32;

fs::path KeyPath() { return GetDataDir() / "roster.key"; }

//! Best-effort owner-only permissions. Failure is logged rather than fatal:
//! some filesystems cannot express it, and refusing to run there would be a
//! worse outcome than a key file the operator can still protect themselves.
void RestrictPermissions(const fs::path& path)
{
    try {
        fs::permissions(path, fs::owner_read | fs::owner_write);
    } catch (const fs::filesystem_error& e) {
        LogPrintf("roster: could not restrict permissions on %s (%s)\n", path.string(), e.what());
    }
}

//! Return the even-Y representative of a key.
//!
//! A record publishes 32 bytes - the x coordinate - and drops the parity byte,
//! which is what BIP340 signing wants and what makes a record 33 bytes rather
//! than 34. The cost is that x alone does not say which of the two keys sharing
//! it signed, so anyone deriving an ordinary address from a published roster key
//! has to pick one, and both sides must pick the same one.
//!
//! Negating a key leaves x unchanged, so this changes nothing about the node's
//! published identity or any signature it has ever made. It only fixes which of
//! the two private keys behind that x this node actually holds, so that
//! 0x02 || x is always the pubkey it can spend and stake with.
void CanonicaliseEvenY(CKey& key)
{
    const CPubKey pubkey = key.GetPubKey();
    if (pubkey.size() > 0 && pubkey[0] == 0x03) key.Negate();
}

} // namespace

std::string OperationalKeyPath() { return KeyPath().string(); }

bool StakerPubKeyFromRoster(const KeyBytes& op_key, CPubKey& pubkey_out)
{
    // The even-Y representative, matching what CanonicaliseEvenY leaves in the
    // key file. A published roster key therefore names exactly one ordinary
    // pubkey, and any reader can derive it without asking the peer.
    unsigned char compressed[CPubKey::COMPRESSED_SIZE];
    compressed[0] = 0x02;
    std::copy(op_key.begin(), op_key.end(), compressed + 1);

    pubkey_out.Set(compressed, compressed + sizeof(compressed));
    return pubkey_out.IsFullyValid();
}

bool GetOperationalKey(CKey& key_out, std::string& error)
{
    const fs::path path = KeyPath();

    if (fs::exists(path)) {
        fsbridge::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            error = "Cannot open " + path.string();
            return false;
        }

        unsigned char secret[SECRET_SIZE];
        file.read((char*)secret, SECRET_SIZE);
        const bool complete = file.gcount() == static_cast<std::streamsize>(SECRET_SIZE);
        if (complete) key_out.Set(secret, secret + SECRET_SIZE, /*fCompressedIn=*/true);
        memory_cleanse(secret, sizeof(secret));

        if (!complete) {
            error = path.string() + " is shorter than 32 bytes; refusing to guess at a truncated key";
            return false;
        }
        if (!key_out.IsValid()) {
            // A file of the right length that is not a valid scalar means
            // corruption or the wrong file entirely. Overwriting it would
            // silently change the node's identity, so stop instead.
            error = path.string() + " does not contain a valid key; move it aside to generate a new identity";
            return false;
        }
        CanonicaliseEvenY(key_out);
        return true;
    }

    key_out.MakeNewKey(/*fCompressed=*/true);
    CanonicaliseEvenY(key_out);

    fsbridge::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        error = "Cannot create " + path.string();
        return false;
    }
    file.write((const char*)key_out.begin(), SECRET_SIZE);
    file.close();
    RestrictPermissions(path);

    LogPrintf("roster: created a new operational key at %s\n", path.string());
    return true;
}

} // namespace roster
