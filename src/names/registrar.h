// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NAMES_REGISTRAR_H
#define BITCOIN_NAMES_REGISTRAR_H

#include <fs.h>
#include <names/record.h>
#include <sync.h>
#include <uint256.h>

#include <functional>
#include <memory>

class UniValue;
#include <string>
#include <vector>

/**
 * Seeing a registration through.
 *
 * Registering takes two transactions some blocks apart: a commitment that
 * hides the name, then the claim that reveals it and burns the price. The
 * second cannot be sent until the first is COMMIT_MIN_AGE blocks deep, which
 * on mainnet is twenty minutes - longer than anyone should have to wait at a
 * prompt. So the commitment is remembered here, with the salt that makes it
 * unguessable, and the claim goes out on its own once it can.
 *
 * Nothing is burned on a claim that would not count: just before sending, the
 * name is checked again against the chain as it stands, and a registration
 * somebody else won meanwhile is marked lost instead.
 *
 * Kept in <datadir>/names_pending.json. Losing the file loses only the
 * commitment fee: the salt is gone, so the claim can never be made, and the
 * name has to be committed again.
 */
namespace names {

struct PendingRegistration {
    std::string name;
    Salt salt{};
    roster::KeyBytes owner{};
    uint32_t years{1};
    std::string wallet;
    uint256 commit_txid;
    int started{0};           //!< height when the commitment was sent
    std::string status;       //!< committed, claimed, done, lost
    uint256 claim_txid;
    int claimed{0};           //!< height when the claim was sent
    std::string note;         //!< what is happening now, for people
};

/**
 * Sends the claim for a matured registration from the wallet that committed.
 * True with the claim's txid; false with why not (a locked wallet, say), in
 * which case it is tried again later.
 */
using ClaimPublisher = std::function<bool(const PendingRegistration& pending, uint256& txid_out,
                                          std::string& error_out)>;

/** Installed by the wallet at startup, before the registrar exists, as the listing publisher is. */
void SetClaimPublisher(ClaimPublisher publisher);

class Registrar
{
public:
    explicit Registrar(const fs::path& file);

    bool Load(std::string& error);

    void Add(const PendingRegistration& pending);
    std::vector<PendingRegistration> All() const;
    /** The registration of `name` still in progress, if any. */
    bool Find(const std::string& name, PendingRegistration& out) const;

    /**
     * Move every registration along: claim those whose commitment has
     * matured, mark the ones that finished or were lost. Called every block or
     * so, and by registername when asked to finish now.
     */
    void Process();

private:
    bool Save() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const fs::path m_file;
    mutable Mutex m_mutex;
    std::vector<PendingRegistration> m_pending GUARDED_BY(m_mutex);
    // One pass at a time: a claim is a spend, and two passes could send it twice.
    Mutex m_process_mutex;
};

extern std::unique_ptr<Registrar> g_registrar;

/** A registration in progress as RPC and the GUI show it. */
UniValue PendingToJSON(const PendingRegistration& pending);

} // namespace names

#endif // BITCOIN_NAMES_REGISTRAR_H
