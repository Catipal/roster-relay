// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/hint.h>

#include <key_io.h>

#include <algorithm>
#include <cmath>
#include <set>

namespace rpchint {

namespace {

// ---------------------------------------------------------------- words

/**
 * Everyday words for what people ask the console, in the languages the
 * interface speaks most, each group led by the word the help texts use.
 * Kept to verbs and nouns that pick out commands; nothing here is a command
 * name on its own.
 */
const std::vector<std::vector<std::string>>& Groups()
{
    static const std::vector<std::vector<std::string>> groups = {
        {"send", "sends", "sending", "sent", "pay", "pays", "paying", "paid", "invia", "inviare", "manda", "mandare",
         "paga", "pagare", "envia", "envía", "enviar", "pagar", "envoyer", "envoie", "payer", "paie", "senden",
         "sende", "schicken", "zahlen", "bezahlen", "überweisen"},
        {"payment", "payments", "pagamento", "pagamenti", "pago", "pagos", "paiement", "paiements", "zahlung",
         "zahlungen"},
        {"balance", "balances", "saldo", "saldi", "solde", "soldes", "guthaben", "kontostand", "fondi", "fondos",
         "fonds", "disponibile", "disponible"},
        {"coin", "coins", "bps", "money", "soldi", "denaro", "moneta", "monete", "dinero", "moneda", "monedas",
         "argent", "geld", "münze", "münzen", "amount", "importo", "cantidad", "montant", "betrag", "quantia"},
        {"address", "addresses", "indirizzo", "indirizzi", "dirección", "direccion", "direcciones", "adresse",
         "adresses", "adressen", "endereço", "endereco"},
        {"new", "nuovo", "nuova", "nuovi", "nuevo", "nueva", "nouveau", "nouvelle", "neu", "neue", "neuen", "novo",
         "nova", "create", "creates", "crea", "creare", "crear", "cria", "criar", "créer", "creer", "erstellen",
         "make", "fresh"},
        {"peer", "peers", "node", "nodes", "connection", "connections", "connected", "nodo", "nodi", "connessione",
         "connessioni", "connesso", "nodos", "conexión", "conexion", "conexiones", "nœud", "noeud", "nœuds",
         "noeuds", "connexion", "connexions", "knoten", "verbindung", "verbindungen", "conexão", "conexões"},
        {"block", "blocks", "blocco", "blocchi", "bloque", "bloques", "bloc", "blocs", "bloco", "blocos", "blöcke"},
        {"count", "number", "numero", "numeri", "número", "quanti", "quante", "quantos", "quantas",
         "cuántos", "cuantos", "cuántas", "combien", "anzahl", "wieviele", "total", "totale"},
        {"height", "altezza", "altura", "hauteur", "höhe"},
        {"transaction", "transactions", "tx", "txs", "transazione", "transazioni", "transacción", "transaccion",
         "transacciones", "transação", "transacao", "transações", "transaktion", "transaktionen"},
        {"list", "lists", "show", "display", "view", "see", "mostra", "mostrare", "elenca", "elencare", "elenco",
         "lista", "vedi", "vedere", "mostrar", "listar", "ver", "afficher", "affiche", "voir", "liste", "lister",
         "zeige", "zeigen", "anzeigen", "auflisten"},
        {"info", "information", "informazioni", "informazione", "información", "informacion", "informations",
         "informação", "informacao", "details", "dettagli", "detalles", "détails", "status", "stato", "estado",
         "état", "zustand", "stats"},
        {"stake", "stakes", "staking", "staked", "minting"},
        {"delegate", "delegation", "delegated", "cold", "delega", "delegare", "delegar", "déléguer", "delegieren"},
        {"name", "names", "nome", "nomi", "nombre", "nombres", "nom", "noms", "namen"},
        {"mail", "mails", "email", "letter", "letters", "message", "messages", "inbox", "posta", "lettera",
         "lettere", "messaggio", "messaggi", "correo", "carta", "cartas", "mensaje", "mensajes", "courrier",
         "lettre", "lettres", "brief", "briefe", "nachricht", "nachrichten", "mensagem", "mensagens"},
        {"key", "keys", "chiave", "chiavi", "clave", "claves", "clé", "cle", "clés", "schlüssel", "chave", "chaves"},
        {"wallet", "wallets", "portafoglio", "portafogli", "billetera", "cartera", "monedero", "portefeuille",
         "brieftasche", "carteira"},
        {"passphrase", "password", "passwords", "unlock", "unlocks", "sblocca", "sbloccare", "contraseña",
         "contrasena", "desbloquear", "déverrouiller", "deverrouiller", "entsperren", "passwort", "kennwort",
         "senha"},
        {"lock", "locks", "blocca", "bloccare", "bloquea", "bloquear", "verrouiller", "sperren", "trancar"},
        {"receive", "receives", "received", "receiving", "ricevi", "ricevere", "ricevuto", "ricevuti", "recibir",
         "recibido", "recibidos", "recevoir", "reçu", "recu", "empfangen", "erhalten", "receber", "recebido"},
        {"stop", "shutdown", "shut", "quit", "exit", "ferma", "fermare", "spegni", "spegnere", "chiudi", "chiudere", "parar",
         "detener", "apagar", "arrêter", "arreter", "quitter", "beenden", "desligar"},
        {"help", "aiuto", "ayuda", "aide", "hilfe", "ajuda"},
        {"mempool", "pending", "unconfirmed", "waiting", "attesa", "pendenti", "pendente", "pendiente",
         "pendientes", "attente", "ausstehend"},
        {"sign", "signs", "signature", "firma", "firmare", "firmar", "signer", "signieren", "unterschreiben",
         "assinar", "assinatura"},
        {"verify", "check", "checks", "verifica", "verificare", "controlla", "controllare", "verificar",
         "comprobar", "vérifier", "verifier", "prüfen", "überprüfen"},
        {"backup", "backups", "copia", "respaldo", "sauvegarde", "sauvegarder", "sicherung", "sichern"},
        {"import", "imports", "importa", "importare", "importar", "importer", "importieren"},
        {"dump", "export", "esporta", "esportare", "exportar", "exporter", "exportieren"},
        {"fee", "fees", "commissione", "commissioni", "tariffa", "comisión", "comision", "tarifa", "frais",
         "gebühr", "gebühren", "taxa"},
        {"listing", "listings", "announce", "announcement", "announcements", "listed", "annuncio", "annunci",
         "inserzione", "anuncio", "anunciar", "annonce", "annoncer", "eintrag"},
        {"renew", "renews", "renewal", "renewed", "rinnova", "rinnovare", "rinnovo", "renovar", "renovación",
         "renouveler", "renouvellement", "erneuern", "verlängern"},
        {"register", "registers", "registra", "registrare", "registrar", "registro", "enregistrer", "registrieren",
         "anmelden"},
        {"buy", "buys", "purchase", "compra", "comprare", "acquista", "acquistare", "comprar", "acheter", "kaufen"},
        {"sell", "sells", "sale", "vendi", "vendere", "vendita", "vender", "venta", "vendre", "vente", "verkaufen",
         "venda"},
        {"transfer", "transfers", "give", "trasferisci", "trasferire", "cedi", "cedere", "transferir",
         "transférer", "transferer", "céder", "übertragen"},
        {"cancel", "annulla", "annullare", "cancelar", "annuler", "abbrechen", "stornieren"},
        {"resolve", "lookup", "look", "find", "who", "cerca", "cercare", "trova", "trovare", "risolvi", "buscar",
         "encontrar", "quién", "chercher", "trouver", "suchen", "finden", "wer", "procurar"},
        {"network", "networks", "net", "rete", "reti", "red", "redes", "réseau", "reseau", "netzwerk", "rede"},
        {"relay", "relays", "overlay", "ripetitore", "relais"},
        {"radio", "radios", "reticulum", "rnode", "lora", "rádio"},
        {"version", "versione", "versión", "versão"},
        {"generate", "mine", "mining", "mina", "minare", "minar", "miner", "minen"},
        {"label", "labels", "etichetta", "etichette", "etiqueta", "etiquetas", "étiquette", "etikett"},
        {"history", "storia", "cronologia", "historial", "historique", "verlauf", "histórico"},
        {"identity", "identità", "identidad", "identité", "identität", "identidade"},
        {"revoke", "revocation", "revocations", "revoked", "revoca", "revocare", "revocar", "révoquer",
         "widerrufen"},
        {"disconnect", "disconnetti", "desconectar", "déconnecter", "trennen"},
        {"add", "adds", "aggiungi", "aggiungere", "añadir", "agregar", "ajouter", "hinzufügen", "adicionar"},
        {"remove", "delete", "deletes", "removes", "rimuovi", "rimuovere", "elimina", "eliminare", "cancella",
         "cancellare", "eliminar", "borrar", "supprimer", "enlever", "entfernen", "löschen", "remover"},
        {"read", "open", "leggi", "leggere", "apri", "leer", "abrir", "lire", "ouvrir", "lesen", "öffnen", "ler"},
        {"petname", "petnames", "contact", "contacts", "contatto", "contatti", "rubrica", "contacto", "contactos",
         "kontakt", "kontakte", "contato", "contatos"},
        {"estimate", "stima", "stimare", "estimar", "estimer", "schätzen"},
        {"difficulty", "difficoltà", "dificultad", "difficulté", "schwierigkeit"},
        {"chain", "blockchain", "catena", "cadena", "chaîne", "kette", "cadeia"},
        {"sync", "synchronise", "synchronize", "progress", "sincronizza", "sincronizzazione", "sincronizar",
         "synchroniser", "synchronisieren"},
        {"memory", "memoria", "mémoire", "speicher"},
        {"encrypt", "encrypts", "encryption", "cifra", "cifrare", "crittografa", "cifrar", "encriptar", "chiffrer",
         "verschlüsseln", "criptografar"},
        {"rescan", "rescans", "riscansiona", "rescanear", "rescanner"},
    };
    return groups;
}

/** Words that say nothing about which command is meant. */
const std::set<std::string>& Stopwords()
{
    static const std::set<std::string> words = {
        // English
        "a", "an", "the", "to", "of", "for", "in", "on", "at", "by", "with", "from", "and", "or", "my", "me", "i",
        "you", "it", "is", "are", "be", "do", "does", "did", "can", "could", "would", "should", "please", "how",
        "what", "which", "where", "when", "want", "need", "like", "some", "any", "this", "that", "these", "those",
        "there", "here", "all", "much", "about", "into", "its", "your", "our", "get", "set",
        // Italian
        "il", "lo", "la", "i", "gli", "le", "un", "uno", "una", "di", "da", "del", "della", "dei", "delle", "al",
        "alla", "ai", "agli", "nel", "nella", "con", "su", "per", "tra", "fra", "e", "o", "mio", "mia", "miei",
        "mie", "tuo", "tua", "come", "cosa", "che", "chi", "quale", "quanto", "voglio", "vorrei", "posso", "puoi",
        "mi", "ti", "si", "è", "sono", "tutti", "tutte", "mostrami", "dammi",
        // Spanish
        "el", "los", "las", "unos", "unas", "de", "en", "por", "para", "y", "mis", "tu", "cómo", "qué", "que",
        "quiero", "puedo", "me", "es", "son", "todos", "todas",
        // French
        "les", "une", "des", "du", "au", "aux", "à", "avec", "pour", "par", "et", "ou", "mon", "ma", "mes", "ton",
        "comment", "quoi", "je", "veux", "peux", "est", "sont", "tous", "toutes",
        // German
        "der", "die", "das", "den", "dem", "ein", "eine", "einen", "einem", "mit", "für", "von", "zu", "an",
        "auf", "und", "oder", "mein", "meine", "wie", "ich", "will", "kann", "mir", "ist", "sind", "alle",
        // Portuguese
        "os", "as", "um", "uma", "dos", "das", "no", "na", "com", "meu", "minha", "quero", "é", "são",
    };
    return words;
}

/**
 * Words command names are made of, beyond those in the help texts, so that
 * "getblockcount" splits into get, block and count.
 */
const std::vector<std::string>& NameParts()
{
    static const std::vector<std::string> parts = {
        "get", "set", "list", "send", "to", "name", "names", "new", "address", "addresses", "block", "count",
        "hash", "header", "chain", "tx", "out", "raw", "transaction", "transactions", "wallet", "wallets",
        "passphrase", "info", "peer", "connection", "net", "network", "mining", "mempool", "entry", "ancestors",
        "descendants", "fee", "estimate", "smart", "sign", "message", "verify", "dump", "import", "priv", "key",
        "keys", "backup", "encrypt", "lock", "unlock", "roster", "mail", "by", "label", "labels", "received",
        "receive", "unspent", "balance", "balances", "create", "multisig", "decode", "script", "psbt", "combine",
        "finalize", "analyze", "join", "utxo", "update", "convert", "abandon", "bump", "rescan", "abort", "load",
        "unload", "upgrade", "keypool", "refill", "stake", "staking", "cold", "delegation", "register", "renew",
        "transfer", "subname", "sell", "buy", "cancel", "sale", "pet", "petname", "petnames", "resolve",
        "payments", "publish", "record", "announcement", "request", "listing", "check", "read", "delete",
        "identity", "rotation", "veto", "revocation", "revocations", "age", "proof", "snapshot", "membership",
        "overlay", "relay", "payout", "user", "add", "remove", "ping", "ban", "banned", "clear", "disconnect",
        "node", "added", "uptime", "stop", "help", "echo", "logging", "memory", "generate", "submit", "template",
        "difficulty", "prioritise", "tips", "best", "precious", "invalidate", "reconsider", "wait", "for",
        "scan", "prune", "save", "stats", "filter", "descriptor", "derive", "addresses", "group", "groupings",
        "ize", "since", "radio", "price", "registrations", "payout", "staker", "with", "json", "hd", "seed",
        "fund", "test", "accept", "zmq", "notifications", "spent", "chaintips", "util", "wallet", "dir",
        "settings", "pos", "relayshare", "users", "commitment", "snapshot",
    };
    return parts;
}

std::string Lower(const std::string& in)
{
    std::string out = in;
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned char c = out[i];
        if (c >= 'A' && c <= 'Z') {
            out[i] = c + 32;
        } else if (c == 0xC3 && i + 1 < out.size()) {
            // Latin-1 capitals in UTF-8 (À..Þ, not ×) to their small letters.
            const unsigned char d = out[i + 1];
            if (d >= 0x80 && d <= 0x9E && d != 0x97) out[i + 1] = d + 0x20;
            ++i;
        }
    }
    return out;
}

bool IsWordByte(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80;
}

/** Lowercase words of a text, split on anything not a letter or digit. */
std::vector<std::string> Words(const std::string& text)
{
    std::vector<std::string> words;
    std::string current;
    for (unsigned char c : text) {
        if (IsWordByte(c)) {
            current += c;
        } else if (!current.empty()) {
            words.push_back(Lower(current));
            current.clear();
        }
    }
    if (!current.empty()) words.push_back(Lower(current));
    return words;
}

/** Two-word names for one thing, made one word so they match the commands' own. */
std::string Phrases(const std::string& text)
{
    static const std::vector<std::pair<std::string, std::string>> phrases = {
        {"memory pool", "mempool"}, {"block chain", "blockchain"}, {"shut down", "shutdown"},
        {"private key", "privkey"}, {"how many", "count"}, {"key pool", "keypool"},
    };
    // Found in a lowercase copy, replaced in both, so values typed keep their case.
    std::string out = text;
    std::string lower = Lower(text);
    for (const auto& p : phrases) {
        size_t at = 0;
        while ((at = lower.find(p.first, at)) != std::string::npos) {
            out.replace(at, p.first.size(), p.second);
            lower.replace(at, p.first.size(), p.second);
            at += p.second.size();
        }
    }
    return out;
}

std::string Stem(const std::string& w)
{
    if (w.size() > 4 && w.compare(w.size() - 3, 3, "ies") == 0) return w.substr(0, w.size() - 3) + "y";
    if (w.size() > 3 && w.back() == 's') {
        const char before = w[w.size() - 2];
        if (before != 's' && before != 'u' && before != 'i') return w.substr(0, w.size() - 1);
    }
    return w;
}

const std::map<std::string, std::string>& SynonymMap()
{
    static const std::map<std::string, std::string> map = [] {
        std::map<std::string, std::string> m;
        for (const auto& group : Groups()) {
            for (const auto& word : group) m.emplace(Lower(word), group.front());
        }
        return m;
    }();
    return map;
}

bool IsStopword(const std::string& lower)
{
    return Stopwords().count(lower) > 0;
}

bool IsSynonym(const std::string& lower)
{
    const auto& syn = SynonymMap();
    return syn.count(lower) || syn.count(Stem(lower));
}

/** Concepts that ask for something to be done, rather than shown. */
bool IsAction(const std::string& c)
{
    static const std::set<std::string> actions = {
        "send", "new", "remove", "add", "stop", "transfer", "sell", "buy", "register", "renew", "sign", "import",
        "dump", "backup", "encrypt", "lock", "passphrase", "disconnect", "cancel", "revoke", "generate", "rescan",
        "delegate", "read"};
    return actions.count(c) > 0;
}

int EditDistance(const std::string& a, const std::string& b)
{
    std::vector<int> prev(b.size() + 1), cur(b.size() + 1);
    for (size_t j = 0; j <= b.size(); ++j) prev[j] = j;
    for (size_t i = 1; i <= a.size(); ++i) {
        cur[0] = i;
        for (size_t j = 1; j <= b.size(); ++j) {
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1)});
        }
        std::swap(prev, cur);
    }
    return prev[b.size()];
}

// ---------------------------------------------------------------- typed values

enum class Kind { INT, DEC, HEX64, ADDRESS, WORD, QUOTED, BOOL };

struct Value {
    std::string text;
    Kind kind;
};

bool IsHex(const std::string& s)
{
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}

/** "2", "2.5" and "2,5" - the comma being how much of Europe writes a decimal. */
bool ReadNumber(const std::string& s, std::string& normal, bool& decimal)
{
    if (s.empty()) return false;
    normal.clear();
    decimal = false;
    for (char c : s) {
        if (c >= '0' && c <= '9') {
            normal += c;
        } else if ((c == '.' || c == ',') && !decimal && !normal.empty()) {
            normal += '.';
            decimal = true;
        } else {
            return false;
        }
    }
    return normal.back() != '.';
}

/** The input split as the console splits it: on spaces, with quotes keeping text together. */
std::vector<std::pair<std::string, bool>> Tokens(const std::string& typed)
{
    std::vector<std::pair<std::string, bool>> tokens;
    std::string current;
    bool quoted = false, in_quote = false;
    char quote = 0;
    for (char c : typed) {
        if (in_quote) {
            if (c == quote) {
                in_quote = false;
            } else {
                current += c;
            }
        } else if (c == '"' || c == '\'') {
            in_quote = true;
            quoted = true;
            quote = c;
        } else if (c == ' ' || c == '\t' || c == '(' || c == ')' || (c == ',' && current.empty())) {
            if (!current.empty() || quoted) tokens.emplace_back(current, quoted);
            current.clear();
            quoted = false;
        } else {
            current += c;
        }
    }
    if (!current.empty() || quoted) tokens.emplace_back(current, quoted);
    return tokens;
}

std::string Quote(const std::string& s)
{
    if (s.find(' ') == std::string::npos && !s.empty()) return s;
    return "\"" + s + "\"";
}

bool NameIs(const std::string& name, std::initializer_list<const char*> options)
{
    for (const char* o : options) {
        if (name == o) return true;
    }
    return false;
}

bool Contains(const std::string& s, const char* part)
{
    return s.find(part) != std::string::npos;
}

/** Whether a typed value can stand for an argument. */
bool Fits(const Arg& arg, const Value& v)
{
    const std::string name = Lower(arg.name);
    const std::string& type = arg.type;
    if (Contains(type, "boolean")) return v.kind == Kind::BOOL;
    if (Contains(type, "numeric")) {
        if (v.kind == Kind::INT) return true;
        if (v.kind != Kind::DEC) return false;
        // Heights, counts and indexes are whole numbers.
        return !NameIs(name, {"height", "nblocks", "blocks", "count", "minconf", "maxconf", "n", "vout", "index",
                              "years", "nrequired", "maxtries", "verbosity", "conf_target", "timeout", "verbose"});
    }
    if (!Contains(type, "string")) return false;
    if (Contains(name, "txid") || Contains(name, "hash") || name == "op_key" || name == "key" || name == "owner") {
        return v.kind == Kind::HEX64 || (name == "owner" && v.kind == Kind::WORD);
    }
    if (Contains(name, "address") || name == "destination") return v.kind == Kind::ADDRESS;
    if (NameIs(name, {"to", "name", "subname", "label", "petname", "who", "target"})) {
        return v.kind == Kind::WORD || v.kind == Kind::QUOTED || v.kind == Kind::HEX64 ||
               (name == "to" && v.kind == Kind::ADDRESS);
    }
    if (Contains(name, "hex") || Contains(name, "psbt") || Contains(name, "privkey") || Contains(name, "passphrase")) {
        return false;
    }
    return v.kind == Kind::WORD || v.kind == Kind::QUOTED;
}

/** Put typed values into a command's arguments, in order, as the console reads them. */
Suggestion Fill(const CommandDoc& doc, const std::vector<Value>& values, size_t& used_out)
{
    Suggestion s;
    s.command = doc.name;
    s.summary = doc.summary;
    s.syntax = doc.syntax;
    s.line = doc.name;
    std::vector<bool> used(values.size(), false);
    bool complete = true;
    for (const Arg& arg : doc.args) {
        size_t found = values.size();
        for (size_t i = 0; i < values.size(); ++i) {
            if (!used[i] && Fits(arg, values[i])) {
                found = i;
                break;
            }
        }
        if (found == values.size()) {
            if (arg.required) complete = false;
            // Arguments are positional: nothing after a gap can be given.
            break;
        }
        used[found] = true;
        ++used_out;
        s.line += " " + Quote(values[found].text);
    }
    s.complete = complete;
    return s;
}

} // namespace

// ---------------------------------------------------------------- public

std::string Concept(const std::string& word)
{
    const std::string lower = Lower(word);
    const auto& syn = SynonymMap();
    auto it = syn.find(lower);
    if (it != syn.end()) return it->second;
    const std::string stem = Stem(lower);
    it = syn.find(stem);
    if (it != syn.end()) return it->second;
    return stem;
}

std::vector<std::string> SplitName(const std::string& raw)
{
    const std::string name = Lower(raw);
    static const std::set<std::string> vocab(NameParts().begin(), NameParts().end());
    // best[i]: the best split of name[0, i), scored by squared word lengths
    // so that long known words beat runs of short ones.
    const size_t n = name.size();
    std::vector<int> best(n + 1, -1000000), from(n + 1, 0);
    best[0] = 0;
    for (size_t i = 1; i <= n; ++i) {
        for (size_t j = 0; j < i; ++j) {
            if (best[j] <= -1000000) continue;
            const std::string part = name.substr(j, i - j);
            int score;
            if (vocab.count(part) || SynonymMap().count(part)) {
                score = (int)(part.size() * part.size());
            } else if (part.size() == 1) {
                score = -3;
            } else {
                continue;
            }
            if (best[j] + score > best[i]) {
                best[i] = best[j] + score;
                from[i] = j;
            }
        }
    }
    std::vector<std::string> parts;
    for (size_t i = n; i > 0; i = from[i]) parts.push_back(name.substr(from[i], i - from[i]));
    std::reverse(parts.begin(), parts.end());
    // Letters no word explained are kept together as one part.
    std::vector<std::string> merged;
    for (const std::string& p : parts) {
        const bool known = vocab.count(p) || SynonymMap().count(p);
        if (!known && !merged.empty() && !vocab.count(merged.back()) && !SynonymMap().count(merged.back())) {
            merged.back() += p;
        } else {
            merged.push_back(p);
        }
    }
    return merged;
}

CommandDoc ParseHelp(const std::string& name, const std::string& help)
{
    CommandDoc doc;
    doc.name = name;
    std::vector<std::string> lines;
    size_t start = 0;
    while (start <= help.size()) {
        const size_t end = help.find('\n', start);
        lines.push_back(help.substr(start, end == std::string::npos ? std::string::npos : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (lines.empty()) return doc;
    doc.syntax = lines[0];
    enum { DESCRIPTION, ARGUMENTS, REST } part = DESCRIPTION;
    for (size_t i = 1; i < lines.size(); ++i) {
        const std::string& line = lines[i];
        if (line == "Arguments:") {
            part = ARGUMENTS;
            continue;
        }
        if (line.compare(0, 6, "Result") == 0 || line == "Examples:") {
            part = REST;
            continue;
        }
        if (part == DESCRIPTION) {
            if (doc.summary.empty() && !line.empty()) doc.summary = line;
            doc.description += line + "\n";
        } else if (part == ARGUMENTS) {
            // "1. name    (type, required) what it is"; nested fields are indented.
            size_t p = 0;
            while (p < line.size() && line[p] >= '0' && line[p] <= '9') ++p;
            if (p == 0 || p + 1 >= line.size() || line[p] != '.' || line[p + 1] != ' ') continue;
            size_t q = p + 2;
            const size_t name_end = line.find(' ', q);
            Arg arg;
            arg.name = line.substr(q, name_end == std::string::npos ? std::string::npos : name_end - q);
            if (!arg.name.empty() && arg.name.front() == '"') arg.name = arg.name.substr(1, arg.name.size() - 2);
            const size_t open = line.find('(', q);
            const size_t close = open == std::string::npos ? std::string::npos : line.find(')', open);
            if (open != std::string::npos && close != std::string::npos) {
                const std::string inside = line.substr(open + 1, close - open - 1);
                const size_t comma = inside.find(',');
                arg.type = inside.substr(0, comma);
                arg.required = inside.find("required") != std::string::npos;
            }
            doc.args.push_back(arg);
        }
    }
    return doc;
}

void Index::Add(const CommandDoc& doc)
{
    std::map<std::string, double> weights;
    auto add_field = [&](const std::vector<std::string>& words, double weight) {
        std::set<std::string> seen;
        for (const std::string& w : words) {
            if (w.size() < 2 || IsStopword(w)) continue;
            const std::string c = Concept(w);
            if (seen.insert(c).second) weights[c] += weight;
        }
    };
    const std::vector<std::string> name_parts = SplitName(doc.name);
    add_field(name_parts, 3.0);
    std::set<std::string> name_words;
    for (const std::string& part : name_parts) name_words.insert(Stem(part));
    add_field(Words(Phrases(doc.summary)), 2.0);
    std::vector<std::string> arg_words;
    for (const Arg& a : doc.args) {
        for (const std::string& w : Words(a.name)) {
            for (const std::string& part : SplitName(w)) arg_words.push_back(part);
        }
    }
    add_field(arg_words, 1.5);
    add_field(Words(Phrases(doc.description)), 1.0);

    auto existing = m_by_name.find(doc.name);
    if (existing != m_by_name.end()) {
        // Replacing: take the old command's concepts out of the counts.
        for (const auto& w : m_weights[existing->second]) --m_df[w.first];
        m_docs[existing->second] = doc;
        m_weights[existing->second] = weights;
        m_name_words[existing->second] = name_words;
    } else {
        m_by_name[doc.name] = m_docs.size();
        m_docs.push_back(doc);
        m_weights.push_back(weights);
        m_name_words.push_back(name_words);
    }
    for (const auto& w : weights) ++m_df[w.first];
}

const CommandDoc* Index::Find(const std::string& command) const
{
    const auto it = m_by_name.find(Lower(command));
    return it == m_by_name.end() ? nullptr : &m_docs[it->second];
}

std::vector<Suggestion> Index::Suggest(const std::string& typed, size_t max) const
{
    std::vector<Suggestion> out;
    const std::vector<std::pair<std::string, bool>> tokens = Tokens(Phrases(typed));
    if (tokens.empty() || m_docs.empty()) return out;
    if (!tokens[0].second && Find(tokens[0].first)) return out;

    // A command name typed slightly wrong: "getbalanse".
    const std::string first = Lower(tokens[0].first);
    if (!tokens[0].second && first.size() >= 4) {
        std::vector<std::pair<int, size_t>> close;
        for (size_t i = 0; i < m_docs.size(); ++i) {
            const int d = EditDistance(first, m_docs[i].name);
            if (d <= (first.size() < 8 ? 1 : 2)) close.emplace_back(d, i);
        }
        std::sort(close.begin(), close.end());
        for (const auto& c : close) {
            if (out.size() >= max) break;
            const CommandDoc& doc = m_docs[c.second];
            Suggestion s;
            s.command = doc.name;
            s.summary = doc.summary;
            s.syntax = doc.syntax;
            s.line = doc.name;
            for (size_t t = 1; t < tokens.size(); ++t) s.line += " " + Quote(tokens[t].first);
            s.complete = true;
            s.score = 1000 - c.first;
            out.push_back(s);
        }
        if (!out.empty()) return out;
    }

    // Split what was typed into words that say what is wanted and values.
    std::vector<std::string> concepts;
    std::vector<std::string> stems; //!< the words as typed, for matching names literally
    std::vector<Value> values;
    for (const auto& token : tokens) {
        const std::string& text = token.first;
        if (token.second) {
            values.push_back({text, Kind::QUOTED});
            continue;
        }
        std::string number;
        bool decimal = false;
        if (ReadNumber(text, number, decimal)) {
            values.push_back({number, decimal ? Kind::DEC : Kind::INT});
            continue;
        }
        if (text.size() == 64 && IsHex(text)) {
            values.push_back({Lower(text), Kind::HEX64});
            continue;
        }
        if (text.size() >= 26 && text.size() <= 90 && IsValidDestinationString(text)) {
            values.push_back({text, Kind::ADDRESS});
            continue;
        }
        const std::string lower = Lower(text);
        if (lower == "true" || lower == "false") {
            values.push_back({lower, Kind::BOOL});
            continue;
        }
        bool any = false;
        for (const std::string& w : Words(text)) {
            if (IsStopword(w)) {
                any = true;
                continue;
            }
            const std::string c = Concept(w);
            if (IsSynonym(w) || m_df.count(c)) {
                concepts.push_back(c);
                stems.push_back(Stem(w));
                any = true;
            }
        }
        // Whatever no command speaks of is taken for a value: a name, a label.
        if (!any) {
            std::string word = text;
            while (!word.empty() && std::string(",.;:!?").find(word.back()) != std::string::npos) word.pop_back();
            if (!word.empty()) values.push_back({word, Kind::WORD});
        }
    }
    std::sort(concepts.begin(), concepts.end());
    concepts.erase(std::unique(concepts.begin(), concepts.end()), concepts.end());
    std::vector<std::pair<std::string, double>> query;
    bool action = false;
    for (const std::string& c : concepts) {
        const auto df = m_df.find(c);
        if (df == m_df.end() || df->second <= 0) continue;
        query.emplace_back(c, std::log(1.0 + (double)m_docs.size() / df->second));
        if (IsAction(c)) action = true;
    }
    if (query.empty()) return out;
    // "Show", "list" and "info" say how, not what: with anything else asked,
    // they should not outweigh it.
    if (query.size() > 1) {
        for (auto& q : query) {
            if (q.first == "list" || q.first == "info") q.second *= 0.25;
        }
    }

    std::vector<Suggestion> ranked;
    for (size_t i = 0; i < m_docs.size(); ++i) {
        double score = 0, matched = 0, total = 0;
        for (const auto& q : query) {
            total += q.second;
            const auto w = m_weights[i].find(q.first);
            if (w == m_weights[i].end()) continue;
            score += q.second * w->second;
            matched += q.second;
        }
        if (score <= 0) continue;
        // The words typed are the command's own name: "mempool info" is
        // getmempoolinfo more than anything else that mentions the mempool.
        size_t named = 0, name_size = 0;
        for (const std::string& part : m_name_words[i]) {
            if (part == "get" || part == "list" || part == "to" || part == "by") continue;
            ++name_size;
            if (std::find(stems.begin(), stems.end(), part) != stems.end()) ++named;
        }
        if (name_size > 0) score *= 1.0 + (double)named / name_size;
        // Covering the rarer words asked for counts for more than the common ones.
        score *= 0.5 + 0.5 * matched / total;
        // Asked about something rather than to do something: showing beats changing.
        const std::string& name = m_docs[i].name;
        if (!action && (name.compare(0, 3, "get") == 0 || name.compare(0, 4, "list") == 0)) score *= 1.15;
        size_t used = 0;
        Suggestion s = Fill(m_docs[i], values, used);
        // The values typed say as much as the words: a command that can take
        // them all, and needs nothing more, is likelier what was meant.
        score *= (1.0 + used) / (1.0 + values.size());
        if (s.complete && !values.empty()) score *= 1.3;
        s.score = score;
        ranked.push_back(s);
    }
    std::stable_sort(ranked.begin(), ranked.end(), [](const Suggestion& a, const Suggestion& b) {
        return a.score > b.score;
    });
    if (ranked.size() > max) ranked.resize(max);
    return ranked;
}

} // namespace rpchint
