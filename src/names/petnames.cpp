// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <names/petnames.h>

#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>

#include <cstdio>
#include <fstream>

namespace names {

std::unique_ptr<Petnames> g_petnames;

Petnames::Petnames(const fs::path& file) : m_file(file) {}

std::string Petnames::Fold(const std::string& label)
{
    std::string out = label;
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

bool Petnames::Load(std::string& error)
{
    LOCK(m_mutex);
    m_entries.clear();
    if (!fs::exists(m_file)) return true;
    fsbridge::ifstream in(m_file);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue doc;
    if (!doc.read(text) || !doc.isObject()) {
        error = "the address book file is not valid JSON";
        return false;
    }
    const UniValue& list = find_value(doc, "petnames");
    if (!list.isArray()) return true;
    for (size_t i = 0; i < list.size(); ++i) {
        const UniValue& label = find_value(list[i], "label");
        const UniValue& key = find_value(list[i], "key");
        if (!label.isStr() || !key.isStr() || !IsHex(key.get_str())) continue;
        const std::vector<unsigned char> raw = ParseHex(key.get_str());
        if (raw.size() != 32) continue;
        Petname p;
        p.label = label.get_str();
        std::copy(raw.begin(), raw.end(), p.key.begin());
        m_entries[Fold(p.label)] = p;
    }
    return true;
}

bool Petnames::Save(std::string& error)
{
    UniValue list(UniValue::VARR);
    for (const auto& entry : m_entries) {
        UniValue item(UniValue::VOBJ);
        item.pushKV("label", entry.second.label);
        item.pushKV("key", HexStr(entry.second.key));
        list.push_back(item);
    }
    UniValue doc(UniValue::VOBJ);
    doc.pushKV("version", 1);
    doc.pushKV("petnames", list);

    const fs::path fresh = m_file.string() + ".new";
    {
        fsbridge::ofstream out(fresh);
        out << doc.write(2) << "\n";
        if (!out.good()) {
            error = "could not write the address book";
            return false;
        }
    }
    if (!RenameOver(fresh, m_file)) {
        error = "could not replace the address book file";
        return false;
    }
    return true;
}

bool Petnames::Set(const std::string& label, const roster::KeyBytes& key, std::string& error)
{
    const std::string trimmed = TrimString(label);
    if (trimmed.empty() || trimmed.size() > MAX_PETNAME_LENGTH) {
        error = "A petname is 1 to 64 characters.";
        return false;
    }
    for (const char c : trimmed) {
        if (static_cast<unsigned char>(c) < 0x20) {
            error = "A petname cannot contain control characters.";
            return false;
        }
    }
    LOCK(m_mutex);
    Petname p;
    p.label = trimmed;
    p.key = key;
    m_entries[Fold(trimmed)] = p;
    return Save(error);
}

bool Petnames::Remove(const std::string& label)
{
    LOCK(m_mutex);
    if (m_entries.erase(Fold(TrimString(label))) == 0) return false;
    std::string error;
    return Save(error);
}

bool Petnames::Find(const std::string& label, Petname& out) const
{
    LOCK(m_mutex);
    const auto it = m_entries.find(Fold(TrimString(label)));
    if (it == m_entries.end()) return false;
    out = it->second;
    return true;
}

std::vector<Petname> Petnames::All() const
{
    LOCK(m_mutex);
    std::vector<Petname> out;
    for (const auto& entry : m_entries) out.push_back(entry.second);
    return out;
}

std::vector<std::string> Petnames::LabelsFor(const roster::KeyBytes& key) const
{
    LOCK(m_mutex);
    std::vector<std::string> out;
    for (const auto& entry : m_entries) {
        if (entry.second.key == key) out.push_back(entry.second.label);
    }
    return out;
}

} // namespace names
