// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAIL_CLIENT_H
#define BITCOIN_MAIL_CLIENT_H

#include <fs.h>
#include <key.h>
#include <mail/letter.h>
#include <mail/protocol.h>
#include <roster/peers.h>
#include <sync.h>
#include <threadinterrupt.h>
#include <uint256.h>

#include <chrono>
#include <map>
#include <memory>
#include <stdint.h>
#include <string>
#include <thread>
#include <utility>
#include <vector>

class CDBWrapper;

/**
 * This node's own mail: its keys, its letters, and the trips to its mailboxes.
 *
 * Every trip goes through a path of three relays (overlay::DEFAULT_PATH_HOPS)
 * to the mailbox and back, so a mailbox learns whose mail it holds but never
 * where that person is, and never who wrote to them.
 */
namespace mail {

/** Send and collect mail at all. On by default wherever the overlay runs. */
static const bool DEFAULT_MAIL = true;
/** Seconds between trips to collect mail. */
static constexpr int64_t DEFAULT_MAIL_POLL = 300;
/** How often a mailbox is reminded of this node's current key even if it has not changed. */
static constexpr int64_t REPUBLISH_INTERVAL = 6 * 60 * 60;

enum class Folder : uint8_t {
    INBOX = 0,
    SENT = 1,
};

/** A letter as this node keeps it, already opened. */
struct StoredLetter {
    uint256 id;
    Folder folder{Folder::INBOX};
    roster::KeyBytes from{};
    roster::KeyBytes to{};
    int64_t sent{0};
    int64_t received{0};
    std::string subject;
    std::string body;
    bool read{false};
    //! For a sent letter, how many of the recipient's mailboxes took it.
    uint8_t delivered{0};
};

std::vector<unsigned char> SerializeStored(const StoredLetter& letter);
bool ParseStored(const std::vector<unsigned char>& raw, StoredLetter& out);

struct SendResult {
    bool ok{false};
    uint256 id;
    int delivered{0};
    int mailboxes{0};
    std::string error;
    std::vector<std::string> notes;
};

struct CheckResult {
    int fetched{0};
    int reached{0};
    int mailboxes{0};
    std::vector<std::string> notes;
};

struct MailInfo {
    roster::KeyBytes address{};
    std::vector<roster::KeyBytes> mailboxes;
    uint64_t key_id{0};
    int64_t key_created{0};
    int64_t key_expires{0};
    size_t keys_held{0};
    size_t inbox{0};
    size_t unread{0};
    size_t sent{0};
    int64_t last_check{0};
    int last_fetched{0};
    int last_reached{0};
};

class MailClient
{
public:
    /**
     * `identity` is the roster key: letters are from and to it, and mail keys
     * are signed by it. `memory_only` keeps keys and letters in memory, for
     * tests.
     */
    MailClient(const fs::path& dir, const CKey& identity, const std::string& chain_id,
               std::chrono::seconds poll, bool memory_only = false);
    ~MailClient();

    /** Collect mail every `poll`, the first time a minute after this. */
    void Start();
    void Stop();

    /**
     * Fetch the recipient's mail key from one of their mailboxes, seal the
     * letter to it, and leave it at every one of their mailboxes that will
     * take it. Blocks for as long as the paths take to build.
     */
    SendResult Send(const roster::KeyBytes& to, const std::string& subject, const std::string& body);

    /**
     * Rotate keys if one is due, remind each mailbox of the current key, and
     * collect whatever they hold. One check at a time.
     */
    CheckResult Check();

    /** Every letter kept, newest first. */
    std::vector<StoredLetter> List();
    bool Get(const uint256& id, StoredLetter& out);
    bool MarkRead(const uint256& id);
    bool Delete(const uint256& id);
    MailInfo Info();
    const roster::KeyBytes& Self() const { return m_self; }

    /**
     * Make a new mail key if the newest is a week old, and delete private keys
     * nothing can still be sealed to. True when anything changed.
     */
    bool RotateKeys(int64_t now);
    /** The mail key senders should be given now. */
    bool CurrentPreKey(PreKey& out);
    /** Open a sealed letter and keep it. */
    OpenResult Receive(const std::vector<unsigned char>& envelope, int64_t now, uint256& id_out);
    bool HaveLetter(const uint256& id);
    size_t KeysHeld();

private:
    /** How a mailbox is reached: through a path, or, if it is this node, directly. */
    struct Circuit {
        overlay::Hop hop;
        std::vector<uint64_t> legs;
        bool local{false};
        //! How long one cell takes on the radio, when the path starts with a radio hop.
        std::chrono::milliseconds radio_cell{0};
    };
    bool Reach(const roster::RelayInfo& box, Circuit& out, std::string& error);
    bool Exchange(const Circuit& c, const Message& request, Message& answer,
                  std::chrono::milliseconds timeout, std::string& error);
    void Close(const Circuit& c);
    bool StoreLetter(const StoredLetter& letter);
    bool LoadKeys() EXCLUSIVE_LOCKS_REQUIRED(m_keys_mutex);
    bool SaveKeys() EXCLUSIVE_LOCKS_REQUIRED(m_keys_mutex);
    void ThreadMail();

    const fs::path m_dir;
    const CKey m_identity;
    const roster::KeyBytes m_self;
    const std::string m_chain_id;
    const std::chrono::seconds m_poll;
    const bool m_memory_only;
    std::unique_ptr<CDBWrapper> m_db;

    Mutex m_keys_mutex;
    std::vector<PreKeySecret> m_secrets GUARDED_BY(m_keys_mutex);

    Mutex m_check_mutex;
    Mutex m_mutex;
    // Which key each mailbox was last given, and when.
    std::map<roster::KeyBytes, std::pair<uint64_t, int64_t>> m_published GUARDED_BY(m_mutex);
    CheckResult m_last GUARDED_BY(m_mutex);
    int64_t m_last_at GUARDED_BY(m_mutex){0};

    std::thread m_thread;
    CThreadInterrupt m_interrupt;
};

/** The running mail client, or null when -mail or the overlay is off. */
extern std::unique_ptr<MailClient> g_mail;

} // namespace mail

#endif // BITCOIN_MAIL_CLIENT_H
