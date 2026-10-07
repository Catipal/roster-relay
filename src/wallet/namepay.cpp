// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/namepay.h>

#include <names/payment.h>
#include <key_io.h>
#include <roster/keystore.h>
#include <script/standard.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/wallet.h>

#include <algorithm>

namespace namepay {

const std::string SPEND_KEY_TAG = "namepay_spend";
const std::string PAYMENT_TAG = "namepay";
const std::string PAYMENT_LABEL = "Paid by name";

namespace {

/** The spend keys this wallet published. */
std::vector<CPubKey> SpendKeys(const CWallet& wallet, const LegacyScriptPubKeyMan& spk)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::vector<CPubKey> keys;
    for (const auto& entry : wallet.m_address_book) {
        if (!entry.second.destdata.count(SPEND_KEY_TAG)) continue;
        const PKHash* hash = boost::get<PKHash>(&entry.first);
        CPubKey pub;
        if (hash && spk.GetPubKey(ToKeyID(*hash), pub) && pub.IsCompressed()) keys.push_back(pub);
    }
    return keys;
}

/** Add the key for `dest`, b + t, when the wallet can get at b. */
bool ImportKey(CWallet& wallet, const LegacyScriptPubKeyMan& spk, const CPubKey& spend, const uint256& tweak,
               const CPubKey& dest) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (wallet.IsLocked()) return false;
    CKey b, d;
    if (!spk.GetKey(spend.GetID(), b) || !b.TweakAdd(tweak.begin(), d) || d.GetPubKey() != dest) return false;
    return wallet.ImportPrivKeys({{dest.GetID(), d}}, GetTime());
}

} // namespace

void ScanTransaction(CWallet& wallet, const CTransaction& tx)
{
    AssertLockHeld(wallet.cs_wallet);
    CPubKey one_time;
    if (!names::ReadPaymentMarker(tx, one_time)) return;
    LegacyScriptPubKeyMan* spk = wallet.GetLegacyScriptPubKeyMan();
    if (!spk) return;
    const std::vector<CPubKey> spend_keys = SpendKeys(wallet, *spk);
    if (spend_keys.empty()) return;
    // The scan key is the roster key the payer resolved, held by this node.
    CKey scan;
    if (!roster::ReadOperationalKey(scan)) return;

    for (const CPubKey& spend : spend_keys) {
        uint256 tweak;
        CPubKey dest;
        if (!names::PaymentTweak(scan, one_time, spend, tweak) || !spend.TweakAdd(tweak.begin(), dest)) continue;
        const PKHash address(dest);
        const CScript script = GetScriptForDestination(address);
        if (std::none_of(tx.vout.begin(), tx.vout.end(), [&](const CTxOut& out) { return out.scriptPubKey == script; })) {
            continue;
        }
        if (!wallet.FindAddressBookEntry(address)) {
            wallet.SetAddressBook(address, PAYMENT_LABEL, AddressBook::AddressBookPurpose::RECEIVE);
        }
        if (!wallet.GetDestData(address, PAYMENT_TAG, nullptr)) {
            WalletBatch batch(wallet.GetDatabase());
            wallet.AddDestData(batch, address, PAYMENT_TAG, HexStr(tweak) + HexStr(spend));
        }
        if (spk->HaveKey(dest.GetID())) continue;
        if (ImportKey(wallet, *spk, spend, tweak, dest)) {
            if (spk->HaveWatchOnly(script)) spk->RemoveWatchOnly(script);
        } else {
            // Locked: the wallet sees the payment now and can spend it once unlocked.
            wallet.ImportScriptPubKeys(PAYMENT_LABEL, {script}, /* have_solving_data */ false,
                                       /* apply_label */ false, GetTime());
        }
        wallet.WalletLogPrintf("Payment by name to %s in %s\n", EncodeDestination(address), tx.GetHash().ToString());
    }
}

void ImportPending(CWallet& wallet)
{
    LOCK(wallet.cs_wallet);
    LegacyScriptPubKeyMan* spk = wallet.GetLegacyScriptPubKeyMan();
    if (!spk || wallet.IsLocked()) return;
    bool imported = false;
    for (const auto& entry : wallet.m_address_book) {
        const auto data = entry.second.destdata.find(PAYMENT_TAG);
        if (data == entry.second.destdata.end()) continue;
        const PKHash* hash = boost::get<PKHash>(&entry.first);
        if (!hash || spk->HaveKey(ToKeyID(*hash))) continue;
        const std::vector<unsigned char> raw = ParseHex(data->second);
        if (raw.size() != 32 + CPubKey::COMPRESSED_SIZE) continue;
        const uint256 tweak(std::vector<unsigned char>(raw.begin(), raw.begin() + 32));
        const CPubKey spend(raw.begin() + 32, raw.end());
        CPubKey dest;
        if (!spend.TweakAdd(tweak.begin(), dest) || PKHash(dest) != *hash) continue;
        if (!ImportKey(wallet, *spk, spend, tweak, dest)) continue;
        const CScript script = GetScriptForDestination(*hash);
        if (spk->HaveWatchOnly(script)) spk->RemoveWatchOnly(script);
        imported = true;
    }
    // Balances were worked out with these as watch-only.
    if (imported) wallet.MarkDirty();
}

} // namespace namepay
