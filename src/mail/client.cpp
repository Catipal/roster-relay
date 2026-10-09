// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mail/client.h>

#include <crypto/common.h>
#include <crypto/mlkem768.h>
#include <crypto/sha256.h>
#include <dbwrapper.h>
#include <logging.h>
#include <overlay/radio.h>
#include <overlay/relay.h>
#include <overlay/select.h>
#include <roster/keystore.h>
#include <roster/listing.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>

#include <algorithm>
#include <cstring>

namespace mail {

std::unique_ptr<MailClient> g_mail;

namespace {

const char DB_LETTER = 'l';
using LetterKey = std::pair<char, uint256>;

const char KEYS_MAGIC[8] = {'B', 'P', 'S', 'M', 'A', 'I', 'L', 'K'};
const uint8_t KEYS_VERSION = 1;
constexpr size_t KEY_ENTRY_SIZE = 8 + 8 + 8 + 32 + mlkem768::SECRET_KEY_SIZE + mlkem768::PUBLIC_KEY_SIZE;

void PutU16(std::vector<unsigned char>& out, uint16_t v)
{
    unsigned char b[2];
    WriteLE16(b, v);
    out.insert(out.end(), b, b + 2);
}

void PutU32(std::vector<unsigned char>& out, uint32_t v)
{
    unsigned char b[4];
    WriteLE32(b, v);
    out.insert(out.end(), b, b + 4);
}

void PutU64(std::vector<unsigned char>& out, uint64_t v)
{
    unsigned char b[8];
    WriteLE64(b, v);
    out.insert(out.end(), b, b + 8);
}

/** A key as people will see it in notes: the first sixteen hex digits. */
std::string Short(const roster::KeyBytes& k)
{
    return HexStr(k).substr(0, 16);
}

/** Overwrite a file in place before it is replaced, so old key bytes do not linger. */
void Scrub(const fs::path& path)
{
    std::error_code ec;
    if (!fs::exists(path)) return;
    const uintmax_t size = fs::file_size(path);
    FILE* f = fsbridge::fopen(path, "rb+");
    if (f == nullptr) return;
    std::vector<unsigned char> zeros(4096, 0);
    uintmax_t left = size;
    while (left > 0) {
        const size_t n = (size_t)std::min<uintmax_t>(left, zeros.size());
        if (fwrite(zeros.data(), 1, n, f) != n) break;
        left -= n;
    }
    FileCommit(f);
    fclose(f);
}

} // namespace

std::vector<unsigned char> SerializeStored(const StoredLetter& l)
{
    std::vector<unsigned char> out;
    out.push_back(1); // version
    out.push_back(static_cast<uint8_t>(l.folder));
    out.insert(out.end(), l.id.begin(), l.id.end());
    out.insert(out.end(), l.from.begin(), l.from.end());
    out.insert(out.end(), l.to.begin(), l.to.end());
    PutU64(out, (uint64_t)l.sent);
    PutU64(out, (uint64_t)l.received);
    out.push_back(l.read ? 1 : 0);
    out.push_back(l.delivered);
    PutU16(out, (uint16_t)l.subject.size());
    out.insert(out.end(), l.subject.begin(), l.subject.end());
    PutU32(out, (uint32_t)l.body.size());
    out.insert(out.end(), l.body.begin(), l.body.end());
    return out;
}

bool ParseStored(const std::vector<unsigned char>& raw, StoredLetter& out)
{
    const size_t fixed = 1 + 1 + 32 + 32 + 32 + 8 + 8 + 1 + 1 + 2;
    if (raw.size() < fixed + 4 || raw[0] != 1) return false;
    const unsigned char* p = raw.data() + 1;
    out.folder = static_cast<Folder>(*p++);
    std::copy(p, p + 32, out.id.begin());
    p += 32;
    std::copy(p, p + 32, out.from.begin());
    p += 32;
    std::copy(p, p + 32, out.to.begin());
    p += 32;
    out.sent = (int64_t)ReadLE64(p);
    p += 8;
    out.received = (int64_t)ReadLE64(p);
    p += 8;
    out.read = *p++ != 0;
    out.delivered = *p++;
    const size_t subject_len = ReadLE16(p);
    p += 2;
    size_t at = p - raw.data();
    if (raw.size() < at + subject_len + 4) return false;
    out.subject.assign(raw.begin() + at, raw.begin() + at + subject_len);
    at += subject_len;
    const size_t body_len = ReadLE32(raw.data() + at);
    at += 4;
    if (raw.size() != at + body_len) return false;
    out.body.assign(raw.begin() + at, raw.end());
    return true;
}

MailClient::MailClient(const fs::path& dir, const CKey& identity, const std::string& chain_id,
                       std::chrono::seconds poll, bool memory_only)
    : m_dir(dir), m_identity(identity), m_self(XOnly(identity.GetPubKey())), m_chain_id(chain_id),
      m_poll(poll), m_memory_only(memory_only)
{
    if (!memory_only) TryCreateDirectories(m_dir);
    m_db.reset(new CDBWrapper(m_dir / "letters", 1 << 20, memory_only, false, false));
    LOCK(m_keys_mutex);
    if (!memory_only) LoadKeys();
}

MailClient::~MailClient()
{
    Stop();
    LOCK(m_keys_mutex);
    for (PreKeySecret& s : m_secrets) memory_cleanse(s.kem_secret.data(), s.kem_secret.size());
}

void MailClient::Start()
{
    if (m_thread.joinable()) return;
    m_interrupt.reset();
    m_thread = std::thread(&TraceThread<std::function<void()>>, "mail",
                           std::function<void()>([this] { ThreadMail(); }));
}

void MailClient::Stop()
{
    m_interrupt();
    if (m_thread.joinable()) m_thread.join();
}

void MailClient::ThreadMail()
{
    // A first trip a minute after start, once the roster has been read, and
    // then every poll. Keys are rotated on each trip.
    int64_t next = GetTime() + std::min<int64_t>(60, m_poll.count());
    while (m_interrupt.sleep_for(std::chrono::seconds{1})) {
        if (GetTime() < next) continue;
        const CheckResult r = Check();
        if (r.fetched > 0) LogPrintf("mail: %d new letters\n", r.fetched);
        next = GetTime() + m_poll.count();
    }
}

bool MailClient::LoadKeys()
{
    const fs::path path = m_dir / "keys.dat";
    if (!fs::exists(path)) return true;
    FILE* f = fsbridge::fopen(path, "rb");
    if (f == nullptr) return false;
    std::vector<unsigned char> raw;
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) raw.insert(raw.end(), buf, buf + n);
    fclose(f);
    memory_cleanse(buf, sizeof(buf));

    bool ok = raw.size() >= 8 + 1 + 4 + 32 && std::memcmp(raw.data(), KEYS_MAGIC, 8) == 0 && raw[8] == KEYS_VERSION;
    size_t count = ok ? ReadLE32(raw.data() + 9) : 0;
    ok = ok && raw.size() == 8 + 1 + 4 + count * KEY_ENTRY_SIZE + 32;
    if (ok) {
        unsigned char check[32];
        CSHA256().Write(raw.data(), raw.size() - 32).Finalize(check);
        ok = std::memcmp(check, raw.data() + raw.size() - 32, 32) == 0;
    }
    if (!ok) {
        LogPrintf("mail: %s is damaged; new mail keys will be made, and mail sealed to the old ones cannot be read\n",
                  path.string());
        memory_cleanse(raw.data(), raw.size());
        return false;
    }
    const unsigned char* p = raw.data() + 13;
    for (size_t i = 0; i < count; ++i) {
        PreKeySecret s;
        s.key_id = ReadLE64(p);
        s.created = (int64_t)ReadLE64(p + 8);
        s.expires = (int64_t)ReadLE64(p + 16);
        s.ec_secret.Set(p + 24, p + 56, true);
        s.kem_secret.assign(p + 56, p + 56 + mlkem768::SECRET_KEY_SIZE);
        s.kem_public.assign(p + 56 + mlkem768::SECRET_KEY_SIZE, p + KEY_ENTRY_SIZE);
        p += KEY_ENTRY_SIZE;
        if (s.ec_secret.IsValid()) m_secrets.push_back(std::move(s));
    }
    memory_cleanse(raw.data(), raw.size());
    return true;
}

bool MailClient::SaveKeys()
{
    if (m_memory_only) return true;
    std::vector<unsigned char> raw(KEYS_MAGIC, KEYS_MAGIC + 8);
    raw.push_back(KEYS_VERSION);
    PutU32(raw, (uint32_t)m_secrets.size());
    for (const PreKeySecret& s : m_secrets) {
        PutU64(raw, s.key_id);
        PutU64(raw, (uint64_t)s.created);
        PutU64(raw, (uint64_t)s.expires);
        raw.insert(raw.end(), s.ec_secret.begin(), s.ec_secret.end());
        raw.insert(raw.end(), s.kem_secret.begin(), s.kem_secret.end());
        raw.insert(raw.end(), s.kem_public.begin(), s.kem_public.end());
    }
    unsigned char check[32];
    CSHA256().Write(raw.data(), raw.size()).Finalize(check);
    raw.insert(raw.end(), check, check + 32);

    const fs::path path = m_dir / "keys.dat";
    const fs::path fresh = m_dir / "keys.dat.new";
    FILE* f = fsbridge::fopen(fresh, "wb");
    bool ok = f != nullptr;
    if (ok) {
        ok = fwrite(raw.data(), 1, raw.size(), f) == raw.size();
        ok = FileCommit(f) && ok;
        fclose(f);
    }
    memory_cleanse(raw.data(), raw.size());
    // The old file held keys that may just have been deleted. Its blocks are
    // overwritten before it is replaced, which is as close to destroying them
    // as a file system allows: forward secrecy rests on deleted keys being
    // gone, not merely unlinked.
    if (ok) Scrub(path);
    ok = ok && RenameOver(fresh, path);
    if (!ok) LogPrintf("mail: could not save mail keys to %s\n", path.string());
    return ok;
}

bool MailClient::RotateKeys(int64_t now)
{
    LOCK(m_keys_mutex);
    bool changed = false;
    uint64_t newest_id = 0;
    int64_t newest_created = 0;
    for (const PreKeySecret& s : m_secrets) {
        if (s.key_id >= newest_id) {
            newest_id = s.key_id;
            newest_created = s.created;
        }
    }
    if (m_secrets.empty() || newest_created + PREKEY_LIFETIME <= now) {
        PreKey pub;
        PreKeySecret secret;
        if (MakePreKey(m_identity, m_chain_id, newest_id + 1, now, pub, secret)) {
            m_secrets.push_back(std::move(secret));
            newest_id = newest_id + 1;
            changed = true;
        }
    }
    // A private key is kept while anything sealed to it could still be waiting
    // in a mailbox: senders stop being given it at `expires`, and a mailbox
    // drops what it holds after RETENTION. After that it can only ever open
    // letters already fetched, so it goes.
    for (std::vector<PreKeySecret>::iterator it = m_secrets.begin(); it != m_secrets.end();) {
        if (it->key_id != newest_id && it->expires + RETENTION < now) {
            memory_cleanse(it->kem_secret.data(), it->kem_secret.size());
            it = m_secrets.erase(it);
            changed = true;
        } else {
            ++it;
        }
    }
    if (changed) SaveKeys();
    return changed;
}

bool MailClient::CurrentPreKey(PreKey& out)
{
    LOCK(m_keys_mutex);
    const PreKeySecret* newest = nullptr;
    for (const PreKeySecret& s : m_secrets) {
        if (newest == nullptr || s.key_id > newest->key_id) newest = &s;
    }
    return newest != nullptr && PublicPreKey(m_identity, m_chain_id, *newest, out);
}

size_t MailClient::KeysHeld()
{
    LOCK(m_keys_mutex);
    return m_secrets.size();
}

bool MailClient::StoreLetter(const StoredLetter& letter)
{
    return m_db->Write(LetterKey(DB_LETTER, letter.id), SerializeStored(letter), true);
}

bool MailClient::HaveLetter(const uint256& id)
{
    return m_db->Exists(LetterKey(DB_LETTER, id));
}

OpenResult MailClient::Receive(const std::vector<unsigned char>& envelope, int64_t now, uint256& id_out)
{
    id_out = EnvelopeId(envelope);
    Letter letter;
    OpenResult res;
    {
        LOCK(m_keys_mutex);
        // Taken under the lock and used only while it is held, by Open below.
        const std::vector<PreKeySecret>& secrets = m_secrets;
        res = Open(envelope, m_self, [&secrets](uint64_t key_id) -> const PreKeySecret* {
            for (const PreKeySecret& s : secrets) {
                if (s.key_id == key_id) return &s;
            }
            return nullptr;
        }, m_chain_id, letter);
    }
    if (res != OpenResult::OK) return res;
    if (HaveLetter(id_out)) return OpenResult::OK;
    StoredLetter stored;
    stored.id = id_out;
    stored.folder = Folder::INBOX;
    stored.from = letter.from;
    stored.to = letter.to;
    stored.sent = letter.sent;
    stored.received = now;
    stored.subject = letter.subject;
    stored.body = letter.body;
    stored.read = false;
    if (!StoreLetter(stored)) return OpenResult::DAMAGED;
    return OpenResult::OK;
}

std::vector<StoredLetter> MailClient::List()
{
    std::vector<StoredLetter> out;
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    for (it->Seek(LetterKey(DB_LETTER, uint256())); it->Valid(); it->Next()) {
        LetterKey key;
        if (!it->GetKey(key) || key.first != DB_LETTER) break;
        std::vector<unsigned char> raw;
        StoredLetter l;
        if (it->GetValue(raw) && ParseStored(raw, l)) out.push_back(std::move(l));
    }
    std::sort(out.begin(), out.end(), [](const StoredLetter& a, const StoredLetter& b) {
        const int64_t ta = a.folder == Folder::SENT ? a.sent : a.received;
        const int64_t tb = b.folder == Folder::SENT ? b.sent : b.received;
        return ta != tb ? ta > tb : a.id < b.id;
    });
    return out;
}

bool MailClient::Get(const uint256& id, StoredLetter& out)
{
    std::vector<unsigned char> raw;
    return m_db->Read(LetterKey(DB_LETTER, id), raw) && ParseStored(raw, out);
}

bool MailClient::MarkRead(const uint256& id)
{
    StoredLetter l;
    if (!Get(id, l)) return false;
    if (l.read) return true;
    l.read = true;
    return StoreLetter(l);
}

bool MailClient::Delete(const uint256& id)
{
    if (!HaveLetter(id)) return false;
    return m_db->Erase(LetterKey(DB_LETTER, id), true);
}

MailInfo MailClient::Info()
{
    MailInfo info;
    info.address = m_self;
    {
        LOCK(m_keys_mutex);
        info.keys_held = m_secrets.size();
        for (const PreKeySecret& s : m_secrets) {
            if (s.key_id >= info.key_id) {
                info.key_id = s.key_id;
                info.key_created = s.created;
                info.key_expires = s.expires;
            }
        }
    }
    for (const StoredLetter& l : List()) {
        if (l.folder == Folder::SENT) {
            ++info.sent;
        } else {
            ++info.inbox;
            if (!l.read) ++info.unread;
        }
    }
    std::vector<roster::KeyBytes> keys;
    for (const roster::RelayInfo& r : roster::FreshRelays()) keys.push_back(r.key);
    info.mailboxes = MailboxesFor(m_self, keys);
    LOCK(m_mutex);
    info.last_check = m_last_at;
    info.last_fetched = m_last.fetched;
    info.last_reached = m_last.reached;
    return info;
}

bool MailClient::Reach(const roster::RelayInfo& box, Circuit& out, std::string& error)
{
    out = Circuit();
    if (box.key == m_self) {
        // This node is one of the mailboxes it needs. Nothing to cross.
        if (!g_mailbox) {
            error = "this node is one of the mailboxes but holds no mail (-mailbox=0)";
            return false;
        }
        out.local = true;
        return true;
    }
    if (!overlay::g_overlay) {
        error = "the overlay is off";
        return false;
    }
    overlay::RelayCandidate dest;
    dest.key = box.key;
    dest.addr = box.addr;
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::vector<overlay::RelayCandidate> chosen;
        {
            LOCK(overlay::g_selector_mutex);
            if (!overlay::g_selector || !overlay::g_selector->Select(overlay::DEFAULT_PATH_HOPS, chosen, dest)) {
                error = strprintf("the roster does not list %u relays run by different people to build a path through",
                                  (unsigned)overlay::DEFAULT_PATH_HOPS);
                return false;
            }
        }
        chosen.push_back(dest);
        std::vector<overlay::Relay::CircuitHop> hops;
        bool slow = false;
        for (const overlay::RelayCandidate& c : chosen) {
            overlay::Relay::CircuitHop h;
            h.addr = roster::OverlayAddressFor(c.addr);
            // The first hop may be a radio neighbour (overlay/radio.h).
            if (hops.empty()) h.addr = overlay::FirstHopAddress(c.key, h.addr, slow);
            if (!roster::StakerPubKeyFromRoster(c.key, h.key)) {
                error = "a relay's listed key is not a point on the curve";
                return false;
            }
            hops.push_back(h);
        }
        uint64_t path = 0;
        // Every step's answer comes back over the first hop, so a radio one
        // slows them all.
        if (overlay::g_overlay->BuildCircuit(hops, path, error,
                                             slow ? overlay::RADIO_STEP_TIMEOUT : std::chrono::milliseconds{4000})) {
            out.hop = overlay::Hop::Path(path);
            out.legs = overlay::g_overlay->CircuitLegs(path);
            return true;
        }
        // An entry relay that does not answer stops being one; the next try
        // picks another. Any other failure is a later relay, chosen afresh.
        if (error.rfind("the entry relay", 0) == 0) {
            LOCK(overlay::g_selector_mutex);
            if (overlay::g_selector) overlay::g_selector->DropGuard(chosen[0].key);
        }
    }
    return false;
}

bool MailClient::Exchange(const Circuit& c, const Message& request, Message& answer,
                          std::chrono::milliseconds timeout, std::string& error)
{
    if (c.local) {
        if (!g_mailbox) {
            error = "this node holds no mail";
            return false;
        }
        answer = Serve(*g_mailbox, request, GetTime());
        answer.req = request.req;
        return true;
    }
    return Ask(c.hop, request, answer, timeout, error);
}

void MailClient::Close(const Circuit& c)
{
    if (!c.local && overlay::g_overlay && !c.legs.empty()) overlay::g_overlay->ClosePath(c.legs);
}

SendResult MailClient::Send(const roster::KeyBytes& to, const std::string& subject, const std::string& body)
{
    SendResult r;
    if (subject.size() > MAX_SUBJECT) {
        r.error = strprintf("The subject is longer than %u bytes.", (unsigned)MAX_SUBJECT);
        return r;
    }
    if (body.size() > MAX_BODY) {
        r.error = strprintf("The letter is longer than %u bytes.", (unsigned)MAX_BODY);
        return r;
    }
    const std::vector<roster::RelayInfo> relays = roster::FreshRelays();
    std::vector<roster::KeyBytes> keys;
    for (const roster::RelayInfo& info : relays) keys.push_back(info.key);
    const std::vector<roster::KeyBytes> boxes = MailboxesFor(to, keys);
    r.mailboxes = (int)boxes.size();
    if (boxes.empty()) {
        r.error = "No relay is listed in the roster yet, so there is nowhere to leave mail.";
        return r;
    }
    auto info_of = [&](const roster::KeyBytes& k) {
        for (const roster::RelayInfo& info : relays) {
            if (info.key == k) return info;
        }
        return roster::RelayInfo();
    };

    // The recipient's current mail key, from the first of its mailboxes that
    // has one. Checked here rather than trusted: a mailbox could hand over a
    // key of its own making, and the signature by the recipient's roster key
    // is what rules that out.
    std::map<roster::KeyBytes, Circuit> open;
    PreKey key;
    bool have_key = false;
    const int64_t now = GetTime();
    for (const roster::KeyBytes& box : boxes) {
        Circuit c;
        std::string err;
        if (!Reach(info_of(box), c, err)) {
            r.notes.push_back(strprintf("mailbox %s: %s", Short(box), err));
            continue;
        }
        open[box] = c;
        Message req;
        req.op = Op::GET_KEY;
        req.body.assign(to.begin(), to.end());
        Message ans;
        if (!Exchange(c, req, ans, std::chrono::seconds{15}, err)) {
            r.notes.push_back(strprintf("mailbox %s: %s", Short(box), err));
            continue;
        }
        if (ans.op != Op::KEY) {
            bool ok = false;
            std::string text;
            ReadResult(ans, ok, text);
            r.notes.push_back(strprintf("mailbox %s: %s", Short(box), text));
            continue;
        }
        PreKey k;
        if (!ParsePreKey(ans.body, k) || k.owner != to || !VerifyPreKey(k, m_chain_id) || k.expires <= now) {
            r.notes.push_back(strprintf("mailbox %s handed over a mail key that does not check out", Short(box)));
            continue;
        }
        key = k;
        have_key = true;
        break;
    }
    if (!have_key) {
        for (const auto& c : open) Close(c.second);
        r.error = "None of the recipient's mailboxes has a current mail key for them. They need to have been "
                  "online with mail on in the last week.";
        return r;
    }

    Letter letter;
    letter.to = to;
    letter.subject = subject;
    letter.body = body;
    std::vector<unsigned char> envelope;
    if (!Seal(m_identity, key, letter, m_chain_id, envelope, r.error)) {
        for (const auto& c : open) Close(c.second);
        return r;
    }
    r.id = EnvelopeId(envelope);

    // The same sealed letter at every mailbox, so the recipient collects it
    // once whichever of them it reaches first.
    for (const roster::KeyBytes& box : boxes) {
        std::string err;
        if (open.find(box) == open.end()) {
            Circuit c;
            if (!Reach(info_of(box), c, err)) {
                r.notes.push_back(strprintf("mailbox %s: %s", Short(box), err));
                continue;
            }
            open[box] = c;
        }
        Message req;
        req.op = Op::DEPOSIT;
        req.body = envelope;
        Message ans;
        if (!Exchange(open[box], req, ans, std::chrono::seconds{30}, err)) {
            r.notes.push_back(strprintf("mailbox %s: %s", Short(box), err));
            continue;
        }
        bool ok = false;
        std::string text;
        if (ReadResult(ans, ok, text) && ok) {
            ++r.delivered;
        } else {
            r.notes.push_back(strprintf("mailbox %s refused: %s", Short(box), text));
        }
    }
    for (const auto& c : open) Close(c.second);

    if (r.delivered == 0) {
        r.error = "No mailbox took the letter.";
        return r;
    }
    StoredLetter sent;
    sent.id = r.id;
    sent.folder = Folder::SENT;
    sent.from = letter.from;
    sent.to = to;
    sent.sent = letter.sent;
    sent.received = letter.sent;
    sent.subject = subject;
    sent.body = body;
    sent.read = true;
    sent.delivered = (uint8_t)r.delivered;
    StoreLetter(sent);
    r.ok = true;
    return r;
}

CheckResult MailClient::Check()
{
    LOCK(m_check_mutex);
    CheckResult r;
    RotateKeys(GetTime());
    PreKey current;
    if (!CurrentPreKey(current)) {
        r.notes.push_back("this node has no mail key");
        return r;
    }

    const std::vector<roster::RelayInfo> relays = roster::FreshRelays();
    std::vector<roster::KeyBytes> keys;
    for (const roster::RelayInfo& info : relays) keys.push_back(info.key);
    const std::vector<roster::KeyBytes> boxes = MailboxesFor(m_self, keys);
    r.mailboxes = (int)boxes.size();

    for (const roster::KeyBytes& box : boxes) {
        if (m_interrupt) break;
        roster::RelayInfo info;
        for (const roster::RelayInfo& i : relays) {
            if (i.key == box) info = i;
        }
        Circuit c;
        std::string err;
        if (!Reach(info, c, err)) {
            r.notes.push_back(strprintf("mailbox %s: %s", Short(box), err));
            continue;
        }

        // Keep the mailbox up to date with the key senders should be given.
        bool publish;
        {
            LOCK(m_mutex);
            std::map<roster::KeyBytes, std::pair<uint64_t, int64_t>>::const_iterator it = m_published.find(box);
            publish = it == m_published.end() || it->second.first != current.key_id ||
                      GetTime() - it->second.second >= REPUBLISH_INTERVAL;
        }
        if (publish) {
            Message req;
            req.op = Op::PUT_KEY;
            req.body = SerializePreKey(current);
            Message ans;
            bool ok = false;
            std::string text;
            if (Exchange(c, req, ans, std::chrono::seconds{15}, err) && ReadResult(ans, ok, text) && ok) {
                LOCK(m_mutex);
                m_published[box] = std::make_pair(current.key_id, GetTime());
            } else {
                r.notes.push_back(strprintf("mailbox %s did not take this node's mail key: %s", Short(box),
                                            err.empty() ? text : err));
            }
        }

        Auth auth;
        Message req;
        req.op = Op::LIST;
        if (!MakeAuth(m_identity, box, m_chain_id, GetTime(), auth)) {
            Close(c);
            continue;
        }
        req.body = SerializeAuth(auth);
        Message ans;
        if (!Exchange(c, req, ans, std::chrono::seconds{15}, err) || ans.op != Op::ITEMS || ans.body.size() < 2) {
            bool ok = false;
            std::string text;
            ReadResult(ans, ok, text);
            r.notes.push_back(strprintf("mailbox %s: %s", Short(box), err.empty() ? text : err));
            Close(c);
            continue;
        }
        ++r.reached;
        const size_t n = ReadLE16(ans.body.data());
        if (ans.body.size() != 2 + n * 44) {
            r.notes.push_back(strprintf("mailbox %s sent a malformed list", Short(box)));
            Close(c);
            continue;
        }
        std::vector<uint256> done;
        for (size_t i = 0; i < n && !m_interrupt; ++i) {
            uint256 id;
            std::copy(ans.body.begin() + 2 + 44 * i, ans.body.begin() + 2 + 44 * i + 32, id.begin());
            if (HaveLetter(id)) {
                done.push_back(id);
                continue;
            }
            Message fetch;
            fetch.op = Op::FETCH;
            if (!MakeAuth(m_identity, box, m_chain_id, GetTime(), auth)) break;
            fetch.body = SerializeAuth(auth);
            fetch.body.insert(fetch.body.end(), id.begin(), id.end());
            Message item;
            if (!Exchange(c, fetch, item, std::chrono::seconds{30}, err) || item.op != Op::ITEM || item.body.size() < 32) {
                r.notes.push_back(strprintf("mailbox %s: could not fetch a letter: %s", Short(box), err));
                continue;
            }
            const std::vector<unsigned char> envelope(item.body.begin() + 32, item.body.end());
            if (EnvelopeId(envelope) != id) {
                r.notes.push_back(strprintf("mailbox %s sent a letter that is not the one asked for", Short(box)));
                continue;
            }
            uint256 got;
            const OpenResult opened = Receive(envelope, GetTime(), got);
            if (opened == OpenResult::OK) {
                ++r.fetched;
            } else {
                // It will never open, so it is not left taking up the
                // recipient's space in somebody else's mailbox.
                r.notes.push_back(strprintf("a letter at mailbox %s was dropped: %s", Short(box), OpenResultString(opened)));
            }
            done.push_back(id);
        }

        // Collected letters are removed from the mailbox: once fetched, the
        // only copy that should exist is this node's.
        for (size_t at = 0; at < done.size(); at += 255) {
            const size_t count = std::min<size_t>(255, done.size() - at);
            Message remove;
            remove.op = Op::REMOVE;
            if (!MakeAuth(m_identity, box, m_chain_id, GetTime(), auth)) break;
            remove.body = SerializeAuth(auth);
            remove.body.push_back((unsigned char)count);
            for (size_t i = 0; i < count; ++i) {
                remove.body.insert(remove.body.end(), done[at + i].begin(), done[at + i].end());
            }
            Message removed;
            Exchange(c, remove, removed, std::chrono::seconds{15}, err);
        }
        Close(c);
    }

    LOCK(m_mutex);
    m_last = r;
    m_last_at = GetTime();
    return r;
}

} // namespace mail
