// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/chain.h>
#include <key.h>
#include <names/payment.h>
#include <node/context.h>
#include <roster/keystore.h>
#include <script/standard.h>
#include <wallet/namepay.h>
#include <wallet/wallet.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <set>

BOOST_FIXTURE_TEST_SUITE(namepay_tests, BasicTestingSetup)

namespace {

roster::KeyBytes XOnly(const CKey& key)
{
    const CPubKey pub = key.GetPubKey();
    roster::KeyBytes x;
    std::copy(pub.begin() + 1, pub.begin() + 33, x.begin());
    return x;
}

/** A payment of one coin to (scan, spend), as sendtoname makes it, and where it went. */
std::pair<CMutableTransaction, CPubKey> Payment(const roster::KeyBytes& scan, const CPubKey& spend)
{
    CKey e;
    e.MakeNewKey(true);
    CPubKey dest;
    BOOST_REQUIRE(names::PaymentDestination(scan, spend, e, dest));
    CMutableTransaction mtx;
    mtx.vout.emplace_back(COIN, GetScriptForDestination(PKHash(dest)));
    mtx.vout.emplace_back(0, CScript() << OP_RETURN << names::PaymentMarker(e.GetPubKey()));
    return {mtx, dest};
}

} // namespace

BOOST_AUTO_TEST_CASE(a_payment_by_name_reaches_only_its_payee)
{
    // The payee: a roster key, which finds payments, and a wallet key, which spends them.
    CKey payee, stranger, spend;
    payee.MakeNewKey(true);
    stranger.MakeNewKey(true);
    spend.MakeNewKey(true);
    const CPubKey spend_pub = spend.GetPubKey();

    std::set<CPubKey> seen;
    for (int i = 0; i < 8; ++i) {
        CKey e;
        e.MakeNewKey(true);
        CPubKey dest;
        BOOST_REQUIRE(names::PaymentDestination(XOnly(payee), spend_pub, e, dest));
        BOOST_CHECK(dest.IsCompressed());
        // Every payment to the same payee lands at an address of its own.
        BOOST_CHECK(seen.insert(dest).second);
        BOOST_CHECK(dest != spend_pub);
        // The payee finds it from the one-time key alone, whichever Y its
        // roster key happens to have, and can spend it.
        uint256 t;
        BOOST_REQUIRE(names::PaymentTweak(payee, e.GetPubKey(), spend_pub, t));
        CPubKey found;
        BOOST_REQUIRE(spend_pub.TweakAdd(t.begin(), found));
        BOOST_CHECK(found == dest);
        CKey d;
        BOOST_REQUIRE(spend.TweakAdd(t.begin(), d));
        BOOST_CHECK(d.GetPubKey() == dest);
        // Anyone else's roster key works out a different address.
        uint256 other;
        BOOST_REQUIRE(names::PaymentTweak(stranger, e.GetPubKey(), spend_pub, other));
        BOOST_CHECK(other != t);
    }

    // The one-time key travels in the payment's own transaction.
    const auto payment = Payment(XOnly(payee), spend_pub);
    CPubKey read;
    BOOST_REQUIRE(names::ReadPaymentMarker(CTransaction(payment.first), read));
    CMutableTransaction plain = payment.first;
    plain.vout.pop_back();
    BOOST_CHECK(!names::ReadPaymentMarker(CTransaction(plain), read));
}

BOOST_AUTO_TEST_CASE(a_wallet_takes_the_payments_made_to_it_by_name)
{
    NodeContext node;
    std::unique_ptr<interfaces::Chain> chain = interfaces::MakeChain(node);
    CWallet wallet(chain.get(), "", CreateDummyWalletDatabase());
    LegacyScriptPubKeyMan& keyman = *wallet.GetOrCreateLegacyScriptPubKeyMan();

    // This node's roster key, which payers resolve its names to.
    CKey roster_key;
    std::string error;
    BOOST_REQUIRE(roster::GetOperationalKey(roster_key, error));
    const roster::KeyBytes scan = XOnly(roster_key);
    CKey b, other;
    b.MakeNewKey(true);
    other.MakeNewKey(true);
    const CPubKey spend = b.GetPubKey();
    BOOST_REQUIRE(keyman.AddKeyPubKey(b, spend));

    LOCK(wallet.cs_wallet);
    const auto payment = Payment(scan, spend);
    const CTxDestination paid_to = PKHash(payment.second);
    const CScript paid_script = GetScriptForDestination(paid_to);

    // Holding the spending key is not enough: the wallet has to have published it.
    namepay::ScanTransaction(wallet, CTransaction(payment.first));
    BOOST_CHECK(!keyman.HaveKey(payment.second.GetID()));

    {
        WalletBatch batch(wallet.GetDatabase());
        BOOST_REQUIRE(wallet.AddDestData(batch, PKHash(spend), namepay::SPEND_KEY_TAG, "1"));
    }
    namepay::ScanTransaction(wallet, CTransaction(payment.first));
    BOOST_CHECK(keyman.HaveKey(payment.second.GetID()));
    BOOST_CHECK_EQUAL(wallet.IsMine(paid_script), ISMINE_SPENDABLE);
    const AddressBook::CAddressBookData* entry = wallet.FindAddressBookEntry(paid_to);
    BOOST_REQUIRE(entry);
    BOOST_CHECK_EQUAL(entry->GetLabel(), namepay::PAYMENT_LABEL);
    BOOST_CHECK(wallet.GetDestData(paid_to, namepay::PAYMENT_TAG, nullptr));
    // Seeing it again, as when it confirms after the mempool, changes nothing.
    namepay::ScanTransaction(wallet, CTransaction(payment.first));
    BOOST_CHECK_EQUAL(wallet.IsMine(paid_script), ISMINE_SPENDABLE);

    // Payments to another spending key, or to another roster key, are not ours.
    const auto elsewhere = Payment(scan, other.GetPubKey());
    namepay::ScanTransaction(wallet, CTransaction(elsewhere.first));
    BOOST_CHECK(!keyman.HaveKey(elsewhere.second.GetID()));
    CKey someone;
    someone.MakeNewKey(true);
    const auto to_someone = Payment(XOnly(someone), spend);
    namepay::ScanTransaction(wallet, CTransaction(to_someone.first));
    BOOST_CHECK(!keyman.HaveKey(to_someone.second.GetID()));
    BOOST_CHECK_EQUAL(wallet.IsMine(GetScriptForDestination(PKHash(to_someone.second))), ISMINE_NO);
}

BOOST_AUTO_TEST_SUITE_END()
