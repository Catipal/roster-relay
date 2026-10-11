// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// A phone without a screen: the companion client from the command line, for
// testing a home node and for anyone who would rather type than tap. It holds
// a device key and what its home node told it, and nothing else - no chain,
// no wallet, no coin keys.

#include <companion/client.h>
#include <companion/protocol.h>
#include <fs.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <univalue.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/translation.h>

#include <fstream>
#include <iostream>
#include <sstream>

#ifndef WIN32
#include <sys/stat.h>
#endif

using namespace companion;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

namespace {

const char* const USAGE = R"(Usage: bps-companion-cli -datadir=<dir> <command> [arguments]

A paired phone, from the command line. It keeps a device key and its home node in <dir>.

  pair <ticket> <name> <pin>          answer a home node's pairing ticket; shows the code to compare
  pairstatus                          whether the home node has accepted the pairing
  status                              balance, limits, what is left today
  address                             an address to be paid at
  history [skip] [count]              the latest payments
  prepare <to> <amount> [subtractfee] build a payment to an address or a name, without sending it
  send <pin>                          send the payment last prepared
  cancel                              let the payment last prepared go
  pay <to> <amount> <pin>             prepare and send in one go
  relays                              fetch the home node's current relays
  setpin <old> <new>
  unpair
)";

struct State {
    Home home;
    uint256 token;
    bool has_prepared{false};
    PrepareAnswer prepared;
};

UniValue RelaysToJSON(const std::vector<RelayEntry>& relays)
{
    UniValue a(UniValue::VARR);
    for (const RelayEntry& r : relays) {
        UniValue e(UniValue::VARR);
        e.push_back(HexStr(r.key));
        e.push_back(r.addr);
        a.push_back(e);
    }
    return a;
}

bool LoadState(const fs::path& file, State& s)
{
    std::ifstream in(file.string());
    if (!in) return false;
    std::stringstream buf;
    buf << in.rdbuf();
    UniValue v;
    if (!v.read(buf.str()) || !v.isObject()) return false;
    s.home.network = find_value(v, "network").get_str();
    s.home.node = CPubKey(ParseHex(find_value(v, "node").get_str()));
    s.home.node_addr = find_value(v, "node_addr").get_str();
    for (const UniValue& e : find_value(v, "relays").getValues()) {
        RelayEntry r;
        r.key = CPubKey(ParseHex(e[0].get_str()));
        r.addr = e[1].get_str();
        s.home.relays.push_back(r);
    }
    const UniValue& token = find_value(v, "token");
    if (token.isStr()) s.token = uint256S(token.get_str());
    const UniValue& p = find_value(v, "prepared");
    if (p.isObject()) {
        s.has_prepared = true;
        s.prepared.prepare_id = uint256S(find_value(p, "id").get_str());
        s.prepared.amount = find_value(p, "amount").get_int64();
        s.prepared.fee = find_value(p, "fee").get_int64();
        const std::vector<unsigned char> script = ParseHex(find_value(p, "payee_script").get_str());
        s.prepared.payee_script = CScript(script.begin(), script.end());
        s.prepared.payee = find_value(p, "payee").get_str();
        s.prepared.expires = find_value(p, "expires").get_int64();
    }
    return true;
}

void SaveState(const fs::path& file, const State& s)
{
    UniValue v(UniValue::VOBJ);
    v.pushKV("network", s.home.network);
    v.pushKV("node", HexStr(s.home.node));
    v.pushKV("node_addr", s.home.node_addr);
    v.pushKV("relays", RelaysToJSON(s.home.relays));
    if (!s.token.IsNull()) v.pushKV("token", s.token.GetHex());
    if (s.has_prepared) {
        UniValue p(UniValue::VOBJ);
        p.pushKV("id", s.prepared.prepare_id.GetHex());
        p.pushKV("amount", s.prepared.amount);
        p.pushKV("fee", s.prepared.fee);
        p.pushKV("payee_script", HexStr(s.prepared.payee_script));
        p.pushKV("payee", s.prepared.payee);
        p.pushKV("expires", s.prepared.expires);
        v.pushKV("prepared", p);
    }
    std::ofstream out(file.string(), std::ios::trunc);
    out << v.write(2) << "\n";
}

bool LoadOrMakeDeviceKey(const fs::path& file, CKey& key)
{
    std::ifstream in(file.string());
    if (in) {
        std::string hex;
        in >> hex;
        const std::vector<unsigned char> raw = ParseHex(hex);
        if (raw.size() != 32) return false;
        key.Set(raw.begin(), raw.end(), true);
        return key.IsValid();
    }
    key.MakeNewKey(true);
    std::ofstream out(file.string(), std::ios::trunc);
    out << HexStr(Span<const unsigned char>(key.begin(), key.size())) << "\n";
    out.close();
#ifndef WIN32
    chmod(file.string().c_str(), S_IRUSR | S_IWUSR);
#endif
    return true;
}

bool ParseAmount(const std::string& text, CAmount& out)
{
    return ParseMoney(text, out) && out > 0;
}

std::string Coins(CAmount amount)
{
    return FormatMoney(amount);
}

UniValue PreparedToJSON(const PrepareAnswer& p)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("to", p.payee);
    o.pushKV("amount", Coins(p.amount));
    o.pushKV("fee", Coins(p.fee));
    o.pushKV("expires", p.expires);
    return o;
}

int Fail(const std::string& error)
{
    std::cerr << "error: " << error << std::endl;
    return 1;
}

int Run(const fs::path& dir, const std::vector<std::string>& args)
{
    const std::string& cmd = args[0];
    const fs::path state_file = dir / "home.json";
    CKey device;
    if (!LoadOrMakeDeviceKey(dir / "device.key", device)) return Fail("device.key is damaged.");

    State s;
    const bool have_state = LoadState(state_file, s);
    std::string error;

    if (cmd == "pair") {
        if (args.size() != 4) return Fail("pair <ticket> <name> <pin>");
        PairingTicket t;
        if (!DecodeTicket(args[1], t, error)) return Fail(error);
        if (!ValidPin(args[3])) return Fail("A PIN is six to twelve digits.");
        s = State();
        s.home.network = t.network;
        s.home.node = t.node;
        s.home.node_addr = t.node_addr;
        s.home.relays = t.relays;
        s.token = t.token;
        Client client(device, t.network == "regtest");
        if (!client.Start(error)) return Fail(error);
        client.SetHome(s.home);
        if (!client.Pair(t.token, args[2], args[3], error)) return Fail(error);
        SaveState(state_file, s);
        UniValue o(UniValue::VOBJ);
        o.pushKV("code", PairingCode(t.token, device.GetPubKey(), t.node));
        o.pushKV("device", HexStr(device.GetPubKey()));
        o.pushKV("message", error);
        std::cout << o.write(2) << std::endl;
        return 0;
    }

    if (!have_state) return Fail("Not paired: run pair first.");
    Client client(device, s.home.network == "regtest");
    if (!client.Start(error)) return Fail(error);
    client.SetHome(s.home);

    UniValue out(UniValue::VOBJ);
    if (cmd == "pairstatus") {
        PairStateAnswer a;
        if (!client.PairStatus(s.token, a, error)) return Fail(error);
        static const char* const names[] = {"waiting", "accepted", "rejected", "expired", "unknown"};
        out.pushKV("state", names[std::min<uint8_t>(a.state, 4)]);
        if (a.state == (uint8_t)PairState::ACCEPTED) {
            out.pushKV("per_tx", Coins(a.per_tx));
            out.pushKV("per_day", Coins(a.per_day));
            // Paired: learn the home node's current relays while the path is open.
            if (client.RefreshRelays(error)) s.home = client.GetHome();
            s.token.SetNull();
        }
    } else if (cmd == "status") {
        StatusAnswer a;
        if (!client.Status(a, error)) return Fail(error);
        out.pushKV("balance", Coins(a.balance));
        out.pushKV("pending", Coins(a.pending));
        out.pushKV("per_tx", Coins(a.per_tx));
        out.pushKV("per_day", Coins(a.per_day));
        out.pushKV("spent_today", Coins(a.spent_today));
        out.pushKV("left_today", Coins(std::max<CAmount>(0, a.per_day - a.spent_today)));
        out.pushKV("height", a.height);
        out.pushKV("locked", a.locked);
    } else if (cmd == "address") {
        std::string address;
        if (!client.Address(address, error)) return Fail(error);
        out.pushKV("address", address);
    } else if (cmd == "history") {
        const size_t skip = args.size() > 1 ? (size_t)std::max(0, atoi(args[1])) : 0;
        const size_t count = args.size() > 2 ? (size_t)std::max(0, atoi(args[2])) : MAX_HISTORY;
        std::vector<HistoryItem> items;
        if (!client.History(skip, count, items, error)) return Fail(error);
        UniValue a(UniValue::VARR);
        for (const HistoryItem& i : items) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("txid", i.txid.GetHex());
            o.pushKV("amount", Coins(i.amount));
            o.pushKV("fee", Coins(i.fee));
            o.pushKV("time", i.time);
            o.pushKV("confirmations", i.confirmations);
            o.pushKV("counterparty", i.counterparty);
            a.push_back(o);
        }
        out.pushKV("history", a);
    } else if (cmd == "prepare" || cmd == "pay") {
        const bool pay = cmd == "pay";
        if (args.size() < (pay ? 4u : 3u)) return Fail(pay ? "pay <to> <amount> <pin>" : "prepare <to> <amount> [subtractfee]");
        CAmount amount;
        if (!ParseAmount(args[2], amount)) return Fail("That is not an amount.");
        const bool subtract = !pay && args.size() > 3 && args[3] == "subtractfee";
        PrepareAnswer p;
        if (!client.Prepare(args[1], amount, subtract, p, error)) return Fail(error);
        if (pay) {
            uint256 txid;
            if (!client.Send(p, args[3], txid, error)) return Fail(error);
            out = PreparedToJSON(p);
            out.pushKV("txid", txid.GetHex());
            s.has_prepared = false;
        } else {
            out = PreparedToJSON(p);
            s.has_prepared = true;
            s.prepared = p;
        }
    } else if (cmd == "send") {
        if (args.size() != 2) return Fail("send <pin>");
        if (!s.has_prepared) return Fail("Nothing is prepared.");
        uint256 txid;
        if (!client.Send(s.prepared, args[1], txid, error)) return Fail(error);
        out = PreparedToJSON(s.prepared);
        out.pushKV("txid", txid.GetHex());
        s.has_prepared = false;
    } else if (cmd == "cancel") {
        if (!s.has_prepared) return Fail("Nothing is prepared.");
        if (!client.Cancel(s.prepared.prepare_id, error)) return Fail(error);
        s.has_prepared = false;
        out.pushKV("cancelled", true);
    } else if (cmd == "relays") {
        if (!client.RefreshRelays(error)) return Fail(error);
        s.home = client.GetHome();
        out.pushKV("relays", (uint64_t)s.home.relays.size());
    } else if (cmd == "setpin") {
        if (args.size() != 3) return Fail("setpin <old> <new>");
        if (!client.SetPin(args[1], args[2], error)) return Fail(error);
        out.pushKV("message", error);
    } else if (cmd == "unpair") {
        if (!client.Unpair(error)) return Fail(error);
        fs::remove(state_file);
        out.pushKV("message", error);
        std::cout << out.write(2) << std::endl;
        return 0;
    } else {
        std::cerr << USAGE;
        return 1;
    }
    SaveState(state_file, s);
    std::cout << out.write(2) << std::endl;
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    SetupEnvironment();
    RandomInit();
    ECC_Start();
    ECCVerifyHandle verify;

    fs::path dir;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a.rfind("-datadir=", 0) == 0) {
            dir = fs::path(a.substr(9));
        } else if (a == "-h" || a == "-help" || a == "--help") {
            std::cout << USAGE;
            ECC_Stop();
            return 0;
        } else {
            args.push_back(a);
        }
    }
    if (dir.empty() || args.empty()) {
        std::cerr << USAGE;
        ECC_Stop();
        return 1;
    }
    TryCreateDirectories(dir);
    int ret = 1;
    try {
        ret = Run(dir, args);
    } catch (const std::exception& e) {
        ret = Fail(e.what());
    }
    ECC_Stop();
    return ret;
}
