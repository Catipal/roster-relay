// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <names/sale.h>

#include <hash.h>
#include <policy/policy.h>
#include <script/script_error.h>

namespace names {

CScript SaleCoinScript(const CPubKey& pubkey)
{
    return CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
}

bool SaleKey(const CKey& owner_key, const std::string& name, const CScript& payout, CKey& key_out)
{
    if (!owner_key.IsValid()) return false;
    // A fresh payout script per sale makes a fresh key per sale, and the seller
    // can always work it out again from the SELL record and its own key, which
    // is what cancelling a sale needs.
    CHashWriter writer = TaggedHash("BPS/name-sale-key/v1");
    writer.write((const char*)owner_key.begin(), owner_key.size());
    writer << name;
    writer.write((const char*)payout.data(), payout.size());
    const uint256 secret = writer.GetSHA256();
    key_out.Set(secret.begin(), secret.end(), true);
    return key_out.IsValid();
}

CMutableTransaction SaleTemplate(const COutPoint& coin, CAmount payout_value, const CScript& payout)
{
    CMutableTransaction tx;
    tx.nVersion = CTransaction::CURRENT_VERSION;
    tx.nLockTime = 0;
    tx.vin.emplace_back(coin, CScript(), (uint32_t)CTxIn::SEQUENCE_FINAL);
    tx.vout.emplace_back(payout_value, payout);
    return tx;
}

bool SignSale(const CKey& sale_key, const COutPoint& coin, const CScript& coin_script, CAmount payout_value,
              const CScript& payout, std::vector<unsigned char>& sig_out)
{
    const CMutableTransaction tx = SaleTemplate(coin, payout_value, payout);
    // A legacy input: the amount is not part of the hash.
    const uint256 hash = SignatureHash(coin_script, tx, 0, SALE_SIGHASH, SALE_COIN_VALUE, SigVersion::BASE);
    if (!sale_key.Sign(hash, sig_out)) return false;
    sig_out.push_back((unsigned char)SALE_SIGHASH);
    return true;
}

CScript SaleScriptSig(const std::vector<unsigned char>& sig)
{
    return CScript() << sig;
}

bool CheckSale(const COutPoint& coin, const CTxOut& coin_out, CAmount payout_value, const CScript& payout,
               const std::vector<unsigned char>& sig)
{
    if (sig.empty() || sig.back() != (unsigned char)SALE_SIGHASH) return false;
    CMutableTransaction tx = SaleTemplate(coin, payout_value, payout);
    tx.vin[0].scriptSig = SaleScriptSig(sig);
    ScriptError error;
    return VerifyScript(tx.vin[0].scriptSig, coin_out.scriptPubKey, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS,
                        MutableTransactionSignatureChecker(&tx, 0, coin_out.nValue), &error);
}

} // namespace names
