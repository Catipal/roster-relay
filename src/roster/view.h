// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_VIEW_H
#define BITCOIN_ROSTER_VIEW_H

#include <fs.h>
#include <roster/identity.h>
#include <roster/record.h>
#include <sync.h>
#include <validationinterface.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

class RosterIndex;

/**
 * The roster as this node uses it, beyond what the chain alone says.
 *
 * Design note 001 §9: additions follow the chain, removals stick. A REVOKE
 * counts the moment this node sees it - from a block, from the mempool, or
 * from a peer that passed it on without anyone paying to publish it - and it
 * is kept for good, so a reorg that drops the block carrying it cannot bring
 * a compromised key back. An announcement that is not on the chain, waiting
 * in the mempool or taken out by a reorg, is kept only as a hint of where a
 * known peer can be dialled.
 *
 * And §5: what the node knows of a key's history - how long it has been
 * listed, and which identity runs it - and whether the roster itself is
 * fresh enough to rely on.
 */
namespace roster {

/** Revocations this node has seen, from any source, kept for good. */
class RevocationStore
{
public:
    RevocationStore(const fs::path& file, const std::string& chain_id);

    /** Read what was kept. A missing file is an empty store, not an error. */
    bool Load(std::string& error);

    /**
     * Keep a REVOKE if it parses and its key signed it. True only when it was
     * not kept already, which is what tells a caller to pass it on.
     */
    bool Add(const std::vector<unsigned char>& raw, std::string* error = nullptr);

    bool Contains(const KeyBytes& key) const;
    std::vector<std::vector<unsigned char>> All() const;
    size_t Size() const;

private:
    bool Save() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const fs::path m_file;
    const std::string m_chain_id;
    mutable Mutex m_mutex;
    std::map<KeyBytes, std::vector<unsigned char>> m_records GUARDED_BY(m_mutex);
};

extern std::unique_ptr<RevocationStore> g_revocations;

/** Whether `key` is revoked by anything this node has seen, confirmed or not. */
bool SeenRevoked(const KeyBytes& key);

/** An announcement not on the chain, kept as a dial hint. */
struct Hint {
    std::vector<unsigned char> raw;
    std::string source; //!< "mempool" or "reorg"
    int64_t time{0};
};

/**
 * Dial hints, latest per key, for keys the index already knows - so they
 * cannot be used to fill memory with keys nobody ever paid to list.
 */
class HintStore
{
public:
    static constexpr size_t MAX_HINTS = 10000;
    void Offer(const Record& rec, const std::vector<unsigned char>& raw, const std::string& source);
    /** Drop the hint for `key` once the chain carries that same record. */
    void Confirmed(const KeyBytes& key, const std::vector<unsigned char>& raw);
    std::map<KeyBytes, Hint> All() const;

private:
    mutable Mutex m_mutex;
    std::map<KeyBytes, Hint> m_hints GUARDED_BY(m_mutex);
};

extern HintStore g_hints;

/** Hooked to the roster index: every record it writes, and every one a reorg removes. */
void OnIndexedRecord(const Record& rec, const std::vector<unsigned char>& raw, int height, bool reorged_out);

/** Reads roster records out of transactions as they enter the mempool. */
class MempoolWatcher final : public CValidationInterface
{
protected:
    void TransactionAddedToMempool(const CTransactionRef& tx, uint64_t mempool_sequence) override;
};

extern std::shared_ptr<MempoolWatcher> g_mempool_watcher;

/** Where a key stands at some height. */
struct Standing {
    //! Blocks of continuous history behind it, once that history is AGE_DEPTH deep; else 0.
    int age{0};
    //! The height that history reaches back to, or -1.
    int anchor{-1};
    //! The identity running it, when its own announcements accept one that still delegates to it.
    bool has_identity{false};
    KeyBytes identity{};
    //! Revoked on the chain, or by a revocation this node has seen.
    bool revoked{false};
};

bool GetStanding(const RosterIndex& index, const KeyBytes& key, int tip, Standing& out);

/** How fresh the roster is. */
struct RosterStatus {
    bool enabled{false};
    int height{-1};
    int64_t block_time{0};
    int64_t age_seconds{0};
    //! Older than ROSTER_STALE blocks' worth of time: still dialled, not trusted.
    bool stale{false};
};

RosterStatus GetRosterStatus();

} // namespace roster

#endif // BITCOIN_ROSTER_VIEW_H
