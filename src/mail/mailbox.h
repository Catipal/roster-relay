// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAIL_MAILBOX_H
#define BITCOIN_MAIL_MAILBOX_H

#include <fs.h>
#include <mail/letter.h>
#include <sync.h>
#include <uint256.h>

#include <array>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class CDBWrapper;

/**
 * Holding sealed letters for people who are offline.
 *
 * A mailbox is a relay doing storage for others, which design note 001 §11·5
 * makes part of being a relay: senders reach it through a path, recipients
 * collect through a path, and it holds only what it cannot read.
 *
 * Which relays hold whose mail is arithmetic over the roster (MailboxesFor),
 * as meeting points are, so a sender and a recipient that agree on the roster
 * agree on where mail goes without asking anybody.
 *
 * Everything a mailbox stores is bounded, because storing is something
 * strangers ask it to do: per person, in total, and in time.
 */
namespace mail {

/** Run a mailbox at all. On by default wherever the overlay runs. */
static const bool DEFAULT_MAILBOX = true;
/** Disk a mailbox may use, in MiB. */
static constexpr uint64_t DEFAULT_MAILBOX_MAX_MB = 256;
/** How long a letter is held before it is dropped unread: two weeks. */
static constexpr int64_t RETENTION = 14 * 24 * 60 * 60;
/** Letters held for one person at most, and bytes. */
static constexpr size_t MAX_ITEMS_PER_OWNER = 500;
static constexpr uint64_t MAX_BYTES_PER_OWNER = 8 * 1024 * 1024;
/** How many relays hold each person's mail. */
static constexpr size_t MAILBOX_COUNT = 3;
/**
 * How far a request's clock may be from the mailbox's, in seconds. Requests
 * are signed with a time so a recorded one cannot be replayed later.
 */
static constexpr int64_t AUTH_WINDOW = 10 * 60;

/**
 * The relays that hold `owner`'s mail, from `relays` (the roster's relay set).
 *
 * Rendezvous hashing: each relay scores SHA256(tag || owner || relay) and the
 * highest `count` hold the mail. A relay joining or leaving moves only the
 * owners it scores highest for, so mail is not reshuffled every time the
 * roster changes. The owner never holds its own mail - a mailbox is for when
 * the owner is not there.
 */
std::vector<roster::KeyBytes> MailboxesFor(const roster::KeyBytes& owner,
                                           const std::vector<roster::KeyBytes>& relays,
                                           size_t count = MAILBOX_COUNT);

/** A signed request to read or empty one's own mailbox. */
struct Auth {
    roster::KeyBytes owner{};
    int64_t time{0};
    uint64_t nonce{0};
    std::array<unsigned char, 64> sig{};
};
static constexpr size_t AUTH_SIZE = 32 + 8 + 8 + 64;

std::vector<unsigned char> SerializeAuth(const Auth& auth);
bool ParseAuth(const unsigned char* data, size_t len, Auth& out);
/** Sign a request to the mailbox `mailbox`. Bound to it, so it is worthless at any other. */
bool MakeAuth(const CKey& owner, const roster::KeyBytes& mailbox, const std::string& chain_id,
              int64_t now, Auth& out);

/** What a mailbox says about one letter it holds. */
struct ItemInfo {
    uint256 id;
    uint32_t size{0};
    int64_t received{0};
};

class Mailbox
{
public:
    /**
     * Whether this mailbox takes letters and keys for `owner` at all: yes
     * only for a listed person this relay is one of the mailboxes of. Set by
     * init from the roster; without it, everyone is accepted (unit tests).
     */
    using OwnerCheck = std::function<bool(const roster::KeyBytes& owner)>;

    /**
     * `self` is this relay's roster key, which requests must be signed to.
     * `memory_only` keeps everything in memory, for tests.
     */
    Mailbox(const fs::path& dir, uint64_t max_bytes, const roster::KeyBytes& self,
            const std::string& chain_id, bool memory_only = false);
    ~Mailbox();

    void SetOwnerCheck(OwnerCheck check);

    /** Keep a person's current mail key, if it is theirs and newer than the one held. */
    bool PutPreKey(const PreKey& key, int64_t now, std::string& reason);
    /** The mail key a person last left here, if it has not expired. */
    bool GetPreKey(const roster::KeyBytes& owner, int64_t now, PreKey& out);

    /**
     * Hold a sealed letter. A letter already held is accepted again without
     * being stored twice, so a sender retrying after a lost answer is told
     * yes rather than refused.
     */
    bool Deposit(const std::vector<unsigned char>& envelope, int64_t now, uint256& id_out,
                 std::string& reason);

    /**
     * Check a signed request. A signature, a clock within AUTH_WINDOW, and a
     * nonce not seen before inside it.
     */
    bool CheckAuth(const Auth& auth, int64_t now, std::string& reason);

    std::vector<ItemInfo> List(const roster::KeyBytes& owner);
    bool Fetch(const roster::KeyBytes& owner, const uint256& id, std::vector<unsigned char>& out);
    size_t Remove(const roster::KeyBytes& owner, const std::vector<uint256>& ids);

    /** Drop letters past RETENTION and keys past their expiry. Returns letters dropped. */
    size_t Expire(int64_t now);

    struct Stats {
        size_t owners{0};
        size_t items{0};
        uint64_t bytes{0};
        uint64_t max_bytes{0};
        size_t keys{0};
    };
    Stats GetStats();

    const roster::KeyBytes& Self() const { return m_self; }

private:
    struct Usage {
        size_t items{0};
        uint64_t bytes{0};
    };
    void LoadUsage() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool Allowed(const roster::KeyBytes& owner) LOCKS_EXCLUDED(m_mutex);

    Mutex m_mutex;
    std::unique_ptr<CDBWrapper> m_db GUARDED_BY(m_mutex);
    const uint64_t m_max_bytes;
    const roster::KeyBytes m_self;
    const std::string m_chain_id;
    OwnerCheck m_owner_check GUARDED_BY(m_mutex);
    std::map<roster::KeyBytes, Usage> m_usage GUARDED_BY(m_mutex);
    uint64_t m_total_bytes GUARDED_BY(m_mutex){0};
    size_t m_keys GUARDED_BY(m_mutex){0};
    // Nonces of requests inside AUTH_WINDOW, so none can be replayed.
    std::map<std::pair<roster::KeyBytes, uint64_t>, int64_t> m_seen GUARDED_BY(m_mutex);
};

/** The running mailbox, or null when -mailbox or the overlay is off. */
extern std::unique_ptr<Mailbox> g_mailbox;

} // namespace mail

#endif // BITCOIN_MAIL_MAILBOX_H
