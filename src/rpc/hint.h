// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_HINT_H
#define BITCOIN_RPC_HINT_H

#include <map>
#include <set>
#include <string>
#include <vector>

/**
 * Suggesting console commands from what someone typed, offline.
 *
 * Not a language model, and nothing leaves the computer: people type
 * passphrases and private keys into the console. What it knows is each
 * command's own help text, plus a short table of everyday words in several
 * languages for what people most often want ("pay", "saldo", "peers").
 * Commands are ranked by how many of the typed words their name, summary and
 * arguments use, rarer words counting for more; the values typed - an amount,
 * a name, a transaction id, an address - are put where the command's arguments
 * want them. A suggestion is only ever put in the input line, never run.
 */
namespace rpchint {

struct Arg {
    std::string name;
    std::string type;      //!< as help prints it: string, numeric, boolean, ...
    bool required{false};
};

struct CommandDoc {
    std::string name;
    std::string syntax;    //!< the first line of help: the command and its arguments
    std::string summary;   //!< the first line of its description
    std::string description;
    std::vector<Arg> args;
};

/** What `help <name>` prints, read into its parts. */
CommandDoc ParseHelp(const std::string& name, const std::string& help);

struct Suggestion {
    std::string command;
    std::string line;      //!< what goes in the input: the command and what could be filled in
    std::string summary;
    std::string syntax;
    bool complete{false};  //!< every required argument was filled from what was typed
    double score{0};
};

class Index
{
public:
    void Add(const CommandDoc& doc);
    const CommandDoc* Find(const std::string& command) const;
    size_t Size() const { return m_docs.size(); }

    /**
     * Commands that fit `typed`, best first. Empty when `typed` already starts
     * with a command this index knows, or when nothing fits.
     */
    std::vector<Suggestion> Suggest(const std::string& typed, size_t max = 3) const;

private:
    std::vector<CommandDoc> m_docs;
    std::map<std::string, size_t> m_by_name;
    //! Per command, the weight of each concept in its name, summary, arguments and description.
    std::vector<std::map<std::string, double>> m_weights;
    //! Per command, the words its name is made of, as written.
    std::vector<std::set<std::string>> m_name_words;
    //! How many commands use each concept.
    std::map<std::string, int> m_df;
};

/** The concept a word stands for: its synonym group's head, or the word itself, lightly stemmed. */
std::string Concept(const std::string& word);

/** A command name split into words: "listnamepayments" -> list, name, payments. */
std::vector<std::string> SplitName(const std::string& name);

} // namespace rpchint

#endif // BITCOIN_RPC_HINT_H
