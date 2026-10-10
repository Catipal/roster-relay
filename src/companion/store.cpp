// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <companion/store.h>

#include <dbwrapper.h>
#include <random.h>

#include <utility>

namespace companion {

namespace {

const char DB_SECRET = 's';
const char DB_DEVICE = 'd';

} // namespace

Store::Store(const fs::path& dir, bool memory_only)
{
    m_db.reset(new CDBWrapper(dir, 1 << 20, memory_only, false, false));
    if (!m_db->Read(DB_SECRET, m_secret) || m_secret.IsNull()) {
        GetStrongRandBytes(m_secret.begin(), m_secret.size());
        m_db->Write(DB_SECRET, m_secret, /* fSync */ true);
    }
}

Store::~Store() {}

bool Store::Get(const CPubKey& key, Device& out)
{
    return m_db->Read(std::make_pair(DB_DEVICE, key), out);
}

bool Store::Put(const Device& device)
{
    return m_db->Write(std::make_pair(DB_DEVICE, device.key), device, /* fSync */ true);
}

bool Store::Erase(const CPubKey& key)
{
    return m_db->Erase(std::make_pair(DB_DEVICE, key), /* fSync */ true);
}

std::vector<Device> Store::All()
{
    std::vector<Device> out;
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    for (it->Seek(std::make_pair(DB_DEVICE, CPubKey())); it->Valid(); it->Next()) {
        std::pair<char, CPubKey> key;
        if (!it->GetKey(key) || key.first != DB_DEVICE) break;
        Device d;
        if (it->GetValue(d)) out.push_back(std::move(d));
    }
    return out;
}

} // namespace companion
