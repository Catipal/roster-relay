// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <names/payment.h>

#include <hash.h>
#include <names/record.h>
#include <roster/extract.h>
#include <roster/keystore.h>

namespace names {

namespace {

uint256 Tweak(const uint256& shared, const CPubKey& spend_key)
{
    CHashWriter writer = TaggedHash("BPS/name-pay/v1");
    writer.write((const char*)shared.begin(), shared.size());
    writer.write((const char*)spend_key.begin(), spend_key.size());
    return writer.GetSHA256();
}

} // namespace

std::vector<unsigned char> PaymentMarker(const CPubKey& one_time)
{
    NameRecord rec;
    rec.type = NameRecordType::PAYMENT;
    rec.point = one_time;
    return SerializeNameRecord(rec);
}

bool ReadPaymentMarker(const CTransaction& tx, CPubKey& one_time_out)
{
    for (const CTxOut& out : tx.vout) {
        std::vector<unsigned char> payload;
        if (!roster::ExtractOpReturnPayload(out.scriptPubKey, payload)) continue;
        NameRecord rec;
        if (!ParseNameRecord(payload, rec) || rec.type != NameRecordType::PAYMENT) continue;
        one_time_out = rec.point;
        return true;
    }
    return false;
}

bool ScanPubKey(const roster::KeyBytes& key, CPubKey& out)
{
    // The even-Y convention every roster key follows (roster/keystore.h).
    return roster::StakerPubKeyFromRoster(key, out);
}

bool PaymentDestination(const roster::KeyBytes& scan_key, const CPubKey& spend_key, const CKey& one_time,
                        CPubKey& dest_out)
{
    CPubKey scan;
    if (!ScanPubKey(scan_key, scan) || !spend_key.IsFullyValid() || !one_time.IsValid()) return false;
    uint256 shared;
    if (!scan.ECDH(one_time.begin(), shared)) return false;
    const uint256 t = Tweak(shared, spend_key);
    return spend_key.TweakAdd(t.begin(), dest_out);
}

bool PaymentTweak(const CKey& scan_key, const CPubKey& one_time, const CPubKey& spend_key, uint256& tweak_out)
{
    if (!scan_key.IsValid() || !one_time.IsFullyValid() || !spend_key.IsFullyValid()) return false;
    // Payers use the even-Y key the 32 bytes name; its odd twin shares x but
    // not the shared point's parity.
    CKey k = scan_key;
    if (k.GetPubKey()[0] == 0x03 && !k.Negate()) return false;
    uint256 shared;
    if (!one_time.ECDH(k.begin(), shared)) return false;
    tweak_out = Tweak(shared, spend_key);
    return true;
}

} // namespace names
