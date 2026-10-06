// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NAMES_PETNAMES_H
#define BITCOIN_NAMES_PETNAMES_H

#include <fs.h>
#include <roster/record.h>
#include <sync.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

/**
 * Petnames: this user's own labels for keys - the free tier of section 11.
 *
 * Local, so they cannot conflict, cannot be squatted and cost nothing. A
 * petname can be wrong only for the person who chose it, which is why it wins
 * over a registered name with the same spelling when resolving: the user's own
 * word for someone outranks a stranger's claim to the word.
 *
 * Kept in <datadir>/petnames.json, so the address book is shared by both
 * clients and survives either being reinstalled.
 */
namespace names {

static constexpr size_t MAX_PETNAME_LENGTH = 64;

struct Petname {
    std::string label;
    roster::KeyBytes key{};
};

class Petnames
{
public:
    explicit Petnames(const fs::path& file);

    bool Load(std::string& error);
    bool Set(const std::string& label, const roster::KeyBytes& key, std::string& error);
    bool Remove(const std::string& label);
    /** Case-insensitive. */
    bool Find(const std::string& label, Petname& out) const;
    std::vector<Petname> All() const;
    /** What this user calls a key, if anything. */
    std::vector<std::string> LabelsFor(const roster::KeyBytes& key) const;

private:
    bool Save(std::string& error) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    static std::string Fold(const std::string& label);

    const fs::path m_file;
    mutable Mutex m_mutex;
    std::map<std::string, Petname> m_entries GUARDED_BY(m_mutex);
};

/** Always present once the node has started. */
extern std::unique_ptr<Petnames> g_petnames;

} // namespace names

#endif // BITCOIN_NAMES_PETNAMES_H
