// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mail/client.h>
#include <mail/letter.h>
#include <mail/mailbox.h>
#include <overlay/relay.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <util/strencodings.h>

#include <string>
#include <vector>

namespace {

mail::MailClient& EnsureMail()
{
    if (!mail::g_mail) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           overlay::g_overlay ? "Mail is off (-mail=0)."
                                              : "Mail travels over the overlay, which is off (-overlay).");
    }
    return *mail::g_mail;
}

roster::KeyBytes ParseKey(const UniValue& v, const std::string& name)
{
    const std::vector<unsigned char> raw = ParseHexV(v, name);
    if (raw.size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be a roster key: 32 bytes of hex, as the roster lists it");
    }
    roster::KeyBytes k;
    std::copy(raw.begin(), raw.end(), k.begin());
    return k;
}

UniValue LetterToJSON(const mail::StoredLetter& l, bool with_body)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("id", l.id.GetHex());
    o.pushKV("folder", l.folder == mail::Folder::SENT ? "sent" : "inbox");
    o.pushKV("from", HexStr(l.from));
    o.pushKV("to", HexStr(l.to));
    o.pushKV("subject", l.subject);
    o.pushKV("sent", l.sent);
    o.pushKV("received", l.received);
    o.pushKV("read", l.read);
    if (l.folder == mail::Folder::SENT) o.pushKV("delivered", (int)l.delivered);
    o.pushKV("size", (uint64_t)l.body.size());
    if (with_body) o.pushKV("body", l.body);
    return o;
}

UniValue Notes(const std::vector<std::string>& notes)
{
    UniValue a(UniValue::VARR);
    for (const std::string& n : notes) a.push_back(n);
    return a;
}

} // namespace

static RPCHelpMan sendmail()
{
    return RPCHelpMan{"sendmail",
        "\nSeal a letter to a roster key and leave it at that person's mailboxes.\n"
        "\nThe recipient's current mail key is fetched from one of their mailboxes and checked against\n"
        "their roster key. The letter is sealed to it with secp256k1 and ML-KEM-768 together, your\n"
        "roster key and signature go inside the seal, and every trip runs through a path of three\n"
        "relays. Blocks while the paths are built.\n",
        {
            {"to", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The recipient's roster key"},
            {"subject", RPCArg::Type::STR, RPCArg::Optional::NO, "Up to 200 bytes"},
            {"body", RPCArg::Type::STR, RPCArg::Optional::NO, "Up to 32 KiB of text"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "id", "The sealed letter's id"},
            {RPCResult::Type::NUM, "delivered", "Mailboxes that took it"},
            {RPCResult::Type::NUM, "mailboxes", "Mailboxes the recipient has"},
            {RPCResult::Type::ARR, "notes", "What went wrong at the others", {{RPCResult::Type::STR, "", ""}}},
        }},
        RPCExamples{HelpExampleCli("sendmail", "\"<key>\" \"Hello\" \"First letter\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    mail::MailClient& client = EnsureMail();
    const roster::KeyBytes to = ParseKey(request.params[0], "to");
    const mail::SendResult r = client.Send(to, request.params[1].get_str(), request.params[2].get_str());
    if (!r.ok) {
        std::string msg = r.error;
        for (const std::string& n : r.notes) msg += " " + n + ".";
        throw JSONRPCError(RPC_MISC_ERROR, msg);
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("id", r.id.GetHex());
    out.pushKV("delivered", r.delivered);
    out.pushKV("mailboxes", r.mailboxes);
    out.pushKV("notes", Notes(r.notes));
    return out;
},
    };
}

static RPCHelpMan checkmail()
{
    return RPCHelpMan{"checkmail",
        "\nCollect mail now instead of waiting for the next trip (-mailpoll).\n"
        "Also gives each mailbox this node's current mail key, making a new one if a week has passed.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "fetched", "New letters"},
            {RPCResult::Type::NUM, "reached", "Mailboxes that answered"},
            {RPCResult::Type::NUM, "mailboxes", "Mailboxes this node has"},
            {RPCResult::Type::ARR, "notes", "What went wrong, if anything", {{RPCResult::Type::STR, "", ""}}},
        }},
        RPCExamples{HelpExampleCli("checkmail", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const mail::CheckResult r = EnsureMail().Check();
    UniValue out(UniValue::VOBJ);
    out.pushKV("fetched", r.fetched);
    out.pushKV("reached", r.reached);
    out.pushKV("mailboxes", r.mailboxes);
    out.pushKV("notes", Notes(r.notes));
    return out;
},
    };
}

static RPCHelpMan listmail()
{
    return RPCHelpMan{"listmail",
        "\nLetters this node keeps, newest first, without their bodies.\n",
        {
            {"folder", RPCArg::Type::STR, /* default */ "\"inbox\"", "inbox, sent or all"},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "id", ""},
                {RPCResult::Type::STR, "folder", "inbox or sent"},
                {RPCResult::Type::STR_HEX, "from", "Sender's roster key"},
                {RPCResult::Type::STR_HEX, "to", "Recipient's roster key"},
                {RPCResult::Type::STR, "subject", ""},
                {RPCResult::Type::NUM_TIME, "sent", "When the sender says it was written"},
                {RPCResult::Type::NUM_TIME, "received", "When this node collected it"},
                {RPCResult::Type::BOOL, "read", ""},
                {RPCResult::Type::NUM, "delivered", /* optional */ true, "Sent letters: mailboxes that took it"},
                {RPCResult::Type::NUM, "size", "Bytes of body"},
            }},
        }},
        RPCExamples{HelpExampleCli("listmail", "") + HelpExampleCli("listmail", "sent")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string folder = request.params[0].isNull() ? "inbox" : request.params[0].get_str();
    if (folder != "inbox" && folder != "sent" && folder != "all") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "folder must be inbox, sent or all");
    }
    UniValue out(UniValue::VARR);
    for (const mail::StoredLetter& l : EnsureMail().List()) {
        if (folder == "inbox" && l.folder != mail::Folder::INBOX) continue;
        if (folder == "sent" && l.folder != mail::Folder::SENT) continue;
        out.push_back(LetterToJSON(l, false));
    }
    return out;
},
    };
}

static RPCHelpMan readmail()
{
    return RPCHelpMan{"readmail",
        "\nOne letter in full. Marks it read.\n",
        {
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The letter's id"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "As listmail, and:"},
            {RPCResult::Type::STR, "body", "The letter"},
        }},
        RPCExamples{HelpExampleCli("readmail", "\"<id>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    mail::MailClient& client = EnsureMail();
    const uint256 id = ParseHashV(request.params[0], "id");
    mail::StoredLetter l;
    if (!client.Get(id, l)) throw JSONRPCError(RPC_INVALID_PARAMETER, "No such letter");
    client.MarkRead(id);
    l.read = true;
    return LetterToJSON(l, true);
},
    };
}

static RPCHelpMan deletemail()
{
    return RPCHelpMan{"deletemail",
        "\nDelete a letter from this node. Copies at mailboxes were removed when it was collected.\n",
        {
            {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The letter's id"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether there was such a letter"},
        RPCExamples{HelpExampleCli("deletemail", "\"<id>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return EnsureMail().Delete(ParseHashV(request.params[0], "id"));
},
    };
}

static RPCHelpMan getmailinfo()
{
    return RPCHelpMan{"getmailinfo",
        "\nThis node's mail address, keys and mailboxes, and the mail it holds for others.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "Whether mail is on"},
            {RPCResult::Type::STR_HEX, "address", /* optional */ true, "This node's mail address: its roster key"},
            {RPCResult::Type::ARR, "mailboxes", /* optional */ true, "Relays that hold this node's mail, derived from the roster",
                {{RPCResult::Type::STR_HEX, "", "Roster key"}}},
            {RPCResult::Type::OBJ, "key", /* optional */ true, "The mail key senders are given now", {
                {RPCResult::Type::NUM, "id", ""},
                {RPCResult::Type::NUM_TIME, "created", ""},
                {RPCResult::Type::NUM_TIME, "expires", "Senders stop being given it then"},
            }},
            {RPCResult::Type::NUM, "keys_held", /* optional */ true, "Private mail keys kept; older ones are deleted"},
            {RPCResult::Type::NUM, "inbox", /* optional */ true, ""},
            {RPCResult::Type::NUM, "unread", /* optional */ true, ""},
            {RPCResult::Type::NUM, "sent", /* optional */ true, ""},
            {RPCResult::Type::NUM_TIME, "last_check", /* optional */ true, "Last trip to the mailboxes, 0 if none yet"},
            {RPCResult::Type::OBJ, "holding", "Mail this node holds for others (-mailbox)", {
                {RPCResult::Type::BOOL, "enabled", ""},
                {RPCResult::Type::NUM, "people", /* optional */ true, ""},
                {RPCResult::Type::NUM, "letters", /* optional */ true, ""},
                {RPCResult::Type::NUM, "bytes", /* optional */ true, ""},
                {RPCResult::Type::NUM, "max_bytes", /* optional */ true, ""},
                {RPCResult::Type::NUM, "keys", /* optional */ true, "Mail keys held for senders to fetch"},
            }},
        }},
        RPCExamples{HelpExampleCli("getmailinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("enabled", mail::g_mail != nullptr);
    if (mail::g_mail) {
        const mail::MailInfo info = mail::g_mail->Info();
        out.pushKV("address", HexStr(info.address));
        UniValue boxes(UniValue::VARR);
        for (const roster::KeyBytes& k : info.mailboxes) boxes.push_back(HexStr(k));
        out.pushKV("mailboxes", boxes);
        UniValue key(UniValue::VOBJ);
        key.pushKV("id", (uint64_t)info.key_id);
        key.pushKV("created", info.key_created);
        key.pushKV("expires", info.key_expires);
        out.pushKV("key", key);
        out.pushKV("keys_held", (uint64_t)info.keys_held);
        out.pushKV("inbox", (uint64_t)info.inbox);
        out.pushKV("unread", (uint64_t)info.unread);
        out.pushKV("sent", (uint64_t)info.sent);
        out.pushKV("last_check", info.last_check);
    }
    UniValue holding(UniValue::VOBJ);
    holding.pushKV("enabled", mail::g_mailbox != nullptr);
    if (mail::g_mailbox) {
        const mail::Mailbox::Stats s = mail::g_mailbox->GetStats();
        holding.pushKV("people", (uint64_t)s.owners);
        holding.pushKV("letters", (uint64_t)s.items);
        holding.pushKV("bytes", s.bytes);
        holding.pushKV("max_bytes", s.max_bytes);
        holding.pushKV("keys", (uint64_t)s.keys);
    }
    out.pushKV("holding", holding);
    return out;
},
    };
}

void RegisterMailRPCCommands(CRPCTable& t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category    name             actor (function)  argNames
  //  ----------  ---------------  ----------------  ----------
    { "mail",     "sendmail",      &sendmail,        {"to","subject","body"} },
    { "mail",     "checkmail",     &checkmail,       {} },
    { "mail",     "listmail",      &listmail,        {"folder"} },
    { "mail",     "readmail",      &readmail,        {"id"} },
    { "mail",     "deletemail",    &deletemail,      {"id"} },
    { "mail",     "getmailinfo",   &getmailinfo,     {} },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
