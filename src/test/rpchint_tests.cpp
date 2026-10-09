// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/hint.h>
#include <rpc/server.h>
#include <util/ref.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace rpchint;

BOOST_FIXTURE_TEST_SUITE(rpchint_tests, TestingSetup)

namespace {

// Help texts in the shape RPCHelpMan prints them.
const char* HELP_SENDTONAME =
    "sendtoname \"to\" amount ( allow_unsettled )\n"
    "\nPay a name, a petname or a roster key, at an address nobody else can link to it.\n"
    "\nThe payee must have turned on payments by name (setnamepayments).\n"
    "\nArguments:\n"
    "1. to                 (string, required) A name, label.name, petname or roster key\n"
    "2. amount             (numeric or string, required) What to send, in BPS\n"
    "3. allow_unsettled    (boolean, optional, default=false) Pay even though the name changed recently\n"
    "\nResult:\n{\n  \"txid\" : \"hex\",\n}\n"
    "\nExamples:\n> bitcoin-pos-cli sendtoname \"pilot\" 1.5\n";

const char* HELP_SENDTOADDRESS =
    "sendtoaddress \"address\" amount ( \"comment\" )\n"
    "\nSend an amount to a given address.\n"
    "\nArguments:\n"
    "1. address    (string, required) The bitcoin address to send to.\n"
    "2. amount     (numeric or string, required) The amount in BPS to send. eg 0.1\n"
    "3. comment    (string, optional) A comment used to store what the transaction is for.\n";

const char* HELP_GETBALANCE =
    "getbalance ( \"dummy\" minconf )\n"
    "\nReturns the total available balance.\n"
    "\nArguments:\n"
    "1. dummy      (string, optional) Remains for backward compatibility.\n"
    "2. minconf    (numeric, optional, default=0) Only include transactions confirmed at least this many times.\n";

const char* HELP_GETCONNECTIONCOUNT =
    "getconnectioncount\n"
    "\nReturns the number of connections to other nodes.\n";

const char* HELP_GETPEERINFO =
    "getpeerinfo\n"
    "\nReturns data about each connected network node as a json array of objects.\n";

const char* HELP_TRANSFERNAME =
    "transfername \"name\" \"to\"\n"
    "\nGive a name this node holds to another roster key. Cannot be undone from here.\n"
    "\nArguments:\n"
    "1. name    (string, required) The name\n"
    "2. to      (string, required) The new holder: a roster key, a petname or a name\n";

const char* HELP_GETBLOCKHASH =
    "getblockhash height\n"
    "\nReturns hash of block in best-block-chain at height provided.\n"
    "\nArguments:\n"
    "1. height    (numeric, required) The height index\n";

const char* HELP_GETTRANSACTION =
    "gettransaction \"txid\" ( include_watchonly verbose )\n"
    "\nGet detailed information about in-wallet transaction <txid>\n"
    "\nArguments:\n"
    "1. txid                 (string, required) The transaction id\n"
    "2. include_watchonly    (boolean, optional, default=true) Whether to include watch-only addresses\n";

const char* HELP_WALLETPASSPHRASE =
    "walletpassphrase \"passphrase\" timeout\n"
    "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
    "\nArguments:\n"
    "1. passphrase    (string, required) The wallet passphrase\n"
    "2. timeout       (numeric, required) The time to keep the decryption key in seconds\n";

Index Sample()
{
    Index index;
    index.Add(ParseHelp("sendtoname", HELP_SENDTONAME));
    index.Add(ParseHelp("sendtoaddress", HELP_SENDTOADDRESS));
    index.Add(ParseHelp("getbalance", HELP_GETBALANCE));
    index.Add(ParseHelp("getconnectioncount", HELP_GETCONNECTIONCOUNT));
    index.Add(ParseHelp("getpeerinfo", HELP_GETPEERINFO));
    index.Add(ParseHelp("transfername", HELP_TRANSFERNAME));
    index.Add(ParseHelp("getblockhash", HELP_GETBLOCKHASH));
    index.Add(ParseHelp("gettransaction", HELP_GETTRANSACTION));
    index.Add(ParseHelp("walletpassphrase", HELP_WALLETPASSPHRASE));
    return index;
}

std::string First(const Index& index, const std::string& typed)
{
    const std::vector<Suggestion> s = index.Suggest(typed);
    return s.empty() ? std::string() : s.front().line;
}

} // namespace

BOOST_AUTO_TEST_CASE(help_text_is_read_into_its_parts)
{
    const CommandDoc doc = ParseHelp("sendtoname", HELP_SENDTONAME);
    BOOST_CHECK_EQUAL(doc.syntax, "sendtoname \"to\" amount ( allow_unsettled )");
    BOOST_CHECK_EQUAL(doc.summary, "Pay a name, a petname or a roster key, at an address nobody else can link to it.");
    BOOST_REQUIRE_EQUAL(doc.args.size(), 3U);
    BOOST_CHECK_EQUAL(doc.args[0].name, "to");
    BOOST_CHECK_EQUAL(doc.args[0].type, "string");
    BOOST_CHECK(doc.args[0].required);
    BOOST_CHECK_EQUAL(doc.args[1].type, "numeric or string");
    BOOST_CHECK(!doc.args[2].required);
    // The result and examples are not description.
    BOOST_CHECK(doc.description.find("txid") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(command_names_split_into_words)
{
    BOOST_CHECK(SplitName("getnewaddress") == std::vector<std::string>({"get", "new", "address"}));
    BOOST_CHECK(SplitName("listnamepayments") == std::vector<std::string>({"list", "name", "payments"}));
    BOOST_CHECK(SplitName("getblockcount") == std::vector<std::string>({"get", "block", "count"}));
    BOOST_CHECK(SplitName("walletpassphrase") == std::vector<std::string>({"wallet", "passphrase"}));
    // Words in other languages lead to the same thing as the English.
    BOOST_CHECK_EQUAL(Concept("saldo"), "balance");
    BOOST_CHECK_EQUAL(Concept("Pagare"), "send");
    BOOST_CHECK_EQUAL(Concept("connexions"), "peer");
    BOOST_CHECK_EQUAL(Concept("Blöcke"), "block");
}

BOOST_AUTO_TEST_CASE(what_was_typed_becomes_a_command_line)
{
    const Index index = Sample();
    // The values typed go where the command wants them, and a name is not an address.
    BOOST_CHECK_EQUAL(First(index, "send 2 coins to pilot"), "sendtoname pilot 2");
    BOOST_CHECK_EQUAL(First(index, "paga 2,5 a pilot"), "sendtoname pilot 2.5");
    BOOST_CHECK_EQUAL(First(index, "saldo"), "getbalance");
    BOOST_CHECK_EQUAL(First(index, "quanti peer?"), "getconnectioncount");
    BOOST_CHECK_EQUAL(First(index, "mostra il blocco 1000"), "getblockhash 1000");
    const std::string txid(64, 'a');
    BOOST_CHECK_EQUAL(First(index, "show transaction " + txid), "gettransaction " + txid);
    BOOST_CHECK_EQUAL(First(index, "unlock the wallet"), "walletpassphrase");
    BOOST_CHECK_EQUAL(First(index, "give pilot to bob"), "transfername pilot bob");

    const std::vector<Suggestion> s = index.Suggest("send 2 coins to pilot");
    BOOST_REQUIRE(!s.empty());
    BOOST_CHECK(s.front().complete);
    BOOST_CHECK_EQUAL(s.front().summary, "Pay a name, a petname or a roster key, at an address nobody else can link to it.");
}

BOOST_AUTO_TEST_CASE(a_known_command_needs_no_suggestion_and_a_typo_gets_one)
{
    const Index index = Sample();
    BOOST_CHECK(index.Suggest("sendtoname pilot 2").empty());
    BOOST_CHECK(index.Suggest("GetBalance").empty());
    BOOST_CHECK_EQUAL(First(index, "getbalanse"), "getbalance");
    BOOST_CHECK_EQUAL(First(index, "sendtonam pilot 2"), "sendtoname pilot 2");
    // Nothing anybody would ask for.
    BOOST_CHECK(index.Suggest("xyzzy").empty());
    BOOST_CHECK(index.Suggest("").empty());
}

BOOST_AUTO_TEST_CASE(every_registered_command_reads_and_common_questions_find_them)
{
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    Index index;
    for (const std::string& name : tableRPC.listCommands()) {
        util::Ref context{m_node};
        JSONRPCRequest request(context);
        request.strMethod = "help";
        request.params = UniValue(UniValue::VARR);
        request.params.push_back(name);
        UniValue help;
        try {
            help = tableRPC.execute(request);
        } catch (const UniValue& e) {
            BOOST_TEST_MESSAGE(name + ": " + e.write());
            continue;
        }
        if (!help.isStr()) continue;
        const CommandDoc doc = ParseHelp(name, help.get_str());
        BOOST_CHECK_MESSAGE(doc.syntax.compare(0, name.size(), name) == 0, name + ": " + doc.syntax);
        index.Add(doc);
    }
    BOOST_CHECK_GT(index.Size(), 50U);
    auto offers = [&](const std::string& typed, const std::string& command) {
        for (const Suggestion& s : index.Suggest(typed)) {
            if (s.command == command) return true;
        }
        return false;
    };
    // Questions as people ask them come first; the rest are offered.
    BOOST_CHECK_EQUAL(First(index, "how many blocks"), "getblockcount");
    BOOST_CHECK_EQUAL(First(index, "show my peers"), "getpeerinfo");
    BOOST_CHECK_EQUAL(First(index, "mempool info"), "getmempoolinfo");
    BOOST_CHECK(offers("shut down the node", "stop"));
    BOOST_CHECK(offers("quanti blocchi", "getblockcount"));
}

BOOST_AUTO_TEST_SUITE_END()
