// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/overlaypage.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>

#include <miner.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>

#include <univalue.h>

#include <QDateTime>
#include <QFont>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace {
const char* TAG_OVERLAY = "ov:info";
const char* TAG_ROSTER = "ov:roster";
const char* TAG_SUBSIDY = "ov:subsidy";
const int REFRESH_MS = 5000;

//! Blocks a day at the chain's 180-second spacing.
const int BLOCKS_PER_DAY = 24 * 60 * 60 / BpsUtil::SECONDS_PER_BLOCK;

QLabel* MakeField(QGridLayout* grid, int row, int column, const QString& caption)
{
    QLabel* head = new QLabel(caption);
    QFont head_font = head->font();
    head_font.setPointSizeF(head_font.pointSizeF() * 0.85);
    head->setFont(head_font);
    head->setEnabled(false);

    QLabel* value = new QLabel(QString::fromUtf8("\xe2\x80\x94"));
    QFont value_font = value->font();
    value_font.setBold(true);
    value->setFont(value_font);

    grid->addWidget(head, row, column * 2);
    grid->addWidget(value, row, column * 2 + 1);
    return value;
}

void FillKeys(QListWidget* list, const UniValue& array, const QString& empty_text)
{
    list->clear();
    if (!array.isArray() || array.size() == 0) {
        QListWidgetItem* item = new QListWidgetItem(empty_text);
        item->setFlags(Qt::NoItemFlags);
        list->addItem(item);
        return;
    }
    for (size_t i = 0; i < array.size(); ++i) {
        if (!array[i].isStr()) continue;
        const QString key = QString::fromStdString(array[i].get_str());
        QListWidgetItem* item = new QListWidgetItem(BpsUtil::ShortKey(key));
        item->setFont(BpsUtil::FixedPitchFont());
        item->setToolTip(key);
        list->addItem(item);
    }
}
} // namespace

OverlayPage::OverlayPage(BpsRpc& rpc, QWidget* parent) : QWidget(parent), m_rpc(rpc)
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(6);

    QLabel* title = new QLabel(tr("Overlay"), this);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);
    outer->addWidget(title);

    QLabel* subtitle = new QLabel(
        tr("An encrypted layer of BPS's own, carrying traffic through other peers so that "
           "the far end never learns where you are."),
        this);
    subtitle->setWordWrap(true);
    subtitle->setEnabled(false);
    outer->addWidget(subtitle);

    m_off_note = new QLabel(this);
    m_off_note->setWordWrap(true);
    m_off_note->setVisible(false);
    outer->addWidget(m_off_note);
    outer->addSpacing(8);

    QFormLayout* form = new QFormLayout();
    m_state = new QLabel(tr("asking\xe2\x80\xa6"), this);
    m_listening = new QLabel(tr("\xe2\x80\x94"), this);
    m_paths = new QLabel(tr("\xe2\x80\x94"), this);
    m_introductions = new QLabel(tr("\xe2\x80\x94"), this);
    m_candidates = new QLabel(tr("\xe2\x80\x94"), this);
    m_epoch = new QLabel(tr("\xe2\x80\x94"), this);
    form->addRow(tr("Running"), m_state);
    form->addRow(tr("Listening on"), m_listening);
    form->addRow(tr("Routes open"), m_paths);
    form->addRow(tr("Services meeting here"), m_introductions);
    form->addRow(tr("Relays available"), m_candidates);
    form->addRow(tr("Today's round"), m_epoch);
    outer->addLayout(form);
    outer->addSpacing(8);

    QHBoxLayout* lists = new QHBoxLayout();

    QGroupBox* guards_box = new QGroupBox(tr("Your way in"), this);
    QVBoxLayout* guards_layout = new QVBoxLayout(guards_box);
    QLabel* guards_note = new QLabel(
        tr("The peers your traffic always enters through. They are kept rather than "
           "swapped: picking a new one each time would eventually hand a watcher a turn."),
        guards_box);
    guards_note->setWordWrap(true);
    guards_note->setEnabled(false);
    m_guards = new QListWidget(guards_box);
    guards_layout->addWidget(guards_note);
    guards_layout->addWidget(m_guards);
    lists->addWidget(guards_box);

    QGroupBox* rv_box = new QGroupBox(tr("Where people can meet you"), this);
    QVBoxLayout* rv_layout = new QVBoxLayout(rv_box);
    QLabel* rv_note = new QLabel(
        tr("Worked out from the roster, not looked up. Anyone trying to reach you does the "
           "same sum and gets the same answer, so there is nobody to ask and nobody who "
           "could answer differently. They change each day."),
        rv_box);
    rv_note->setWordWrap(true);
    rv_note->setEnabled(false);
    m_rendezvous = new QListWidget(rv_box);
    rv_layout->addWidget(rv_note);
    rv_layout->addWidget(m_rendezvous);
    lists->addWidget(rv_box);

    outer->addLayout(lists, 1);

    // --- what relaying pays ------------------------------------------------
    QGroupBox* pay = new QGroupBox(tr("What relaying pays"), this);
    QVBoxLayout* pay_layout = new QVBoxLayout(pay);

    QGridLayout* pay_grid = new QGridLayout();
    pay_grid->setHorizontalSpacing(12);
    m_issued = MakeField(pay_grid, 0, 0, tr("Issued per day"));
    m_payable = MakeField(pay_grid, 0, 1, tr("Of that, payable"));
    m_relays = MakeField(pay_grid, 0, 2, tr("Relays"));
    m_users = MakeField(pay_grid, 1, 0, tr("Users"));
    m_per_relay = MakeField(pay_grid, 1, 1, tr("Users per relay"));
    m_share = MakeField(pay_grid, 1, 2, tr("Share per user"));
    m_share_amount = MakeField(pay_grid, 2, 0, tr("About, per day"));
    pay_grid->setColumnStretch(7, 1);
    pay_layout->addLayout(pay_grid);

    QLabel* pay_note = new QLabel(
        tr("A relay pays a user by delegating stake to the key that user published, so what "
           "reaches the user is the cold-staker fee on the blocks that delegation wins \xe2\x80\x94 "
           "%1% of the reward, not all of it. That is the ceiling on this whole mechanism: "
           "the rest of the issuance stays with whoever staked it. A user's share of it is "
           "one divided by how many users their relay carries, so taking a share of the "
           "network's users still costs a share of the stake.")
            .arg(COLD_STAKER_FEE),
        pay);
    pay_note->setWordWrap(true);
    pay_note->setEnabled(false);
    pay_layout->addWidget(pay_note);

    outer->addWidget(pay);

    QLabel* caveat = new QLabel(
        tr("Not yet reviewed by anyone who did not write it, and it hides where you are "
           "rather than when you speak: someone watching both ends can still line up the "
           "timing. Treat it as unfinished."),
        this);
    caveat->setWordWrap(true);
    caveat->setEnabled(false);
    outer->addWidget(caveat);

    connect(&m_rpc, &BpsRpc::result, this, &OverlayPage::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &OverlayPage::onRpcFailed);

    m_timer = new QTimer(this);
    m_timer->setInterval(REFRESH_MS);
    connect(m_timer, &QTimer::timeout, this, &OverlayPage::Refresh);
}

void OverlayPage::setClientModel(ClientModel* model)
{
    m_client_model = model;
    if (!model) {
        m_timer->stop();
        return;
    }

    if (model->getOptionsModel()) {
        m_display_unit = model->getOptionsModel()->getDisplayUnit();
        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this,
                [this](int unit) {
                    m_display_unit = unit;
                    UpdatePay();
                });
    }

    m_timer->start();
    Refresh();
}

void OverlayPage::Refresh()
{
    m_rpc.Call(TAG_OVERLAY, "getoverlayinfo");
    m_rpc.Call(TAG_ROSTER, "getrosterinfo");

    // Not getmininginfo, which would be the obvious source for a block reward:
    // this fork made it ask the wallet for a stake weight through
    // GetWalletForJSONRPCRequest, which throws when no wallet is open and when
    // two are. getblockstats is chain-only, and one field of it is cheap.
    if (!m_client_model) return;
    const int height = m_client_model->getNumBlocks();
    if (height <= 0) return; // genesis carries no undo data to read

    UniValue params(UniValue::VARR);
    params.push_back(height);
    UniValue fields(UniValue::VARR);
    fields.push_back("subsidy");
    params.push_back(fields);
    m_rpc.Call(TAG_SUBSIDY, "getblockstats", params);
}

void OverlayPage::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_ROSTER) {
        const UniValue& live = find_value(value, "live_peers");
        m_listed = live.isNum() ? live.get_int() : -1;
        UpdatePay();
        return;
    }

    if (tag == TAG_SUBSIDY) {
        const UniValue& reward = find_value(value, "subsidy");
        m_subsidy = reward.isNum() ? reward.get_int64() : -1;
        UpdatePay();
        return;
    }

    if (tag != TAG_OVERLAY) return;

    const UniValue& enabled = find_value(value, "enabled");
    const bool on = enabled.isBool() && enabled.get_bool();
    m_state->setText(on ? tr("yes") : tr("no"));

    if (!on) {
        m_off_note->setVisible(true);
        m_off_note->setText(tr("The overlay is switched off. This client turns it on by itself, so "
                               "something has turned it back off, with -overlay=0 on the "
                               "command line or in the configuration file."));
        m_listening->setText(tr("\xe2\x80\x94"));
        m_paths->setText(tr("\xe2\x80\x94"));
        m_introductions->setText(tr("\xe2\x80\x94"));
        m_candidates->setText(tr("\xe2\x80\x94"));
        m_epoch->setText(tr("\xe2\x80\x94"));
        FillKeys(m_guards, UniValue(UniValue::VARR), tr("nothing while the overlay is off"));
        FillKeys(m_rendezvous, UniValue(UniValue::VARR), tr("nothing while the overlay is off"));
        return;
    }

    m_off_note->setVisible(false);

    const UniValue& listening = find_value(value, "listening");
    m_listening->setText(listening.isStr() ? QString::fromStdString(listening.get_str()) : tr("\xe2\x80\x94"));

    const UniValue& paths = find_value(value, "paths");
    m_paths->setText(paths.isNum() ? QString::number(paths.get_int()) : tr("\xe2\x80\x94"));

    const UniValue& introductions = find_value(value, "introductions");
    m_introductions->setText(introductions.isNum() ? QString::number(introductions.get_int()) : tr("\xe2\x80\x94"));

    const UniValue& candidates = find_value(value, "relay_candidates");
    m_relay_count = candidates.isNum() ? candidates.get_int() : -1;
    // Zero is a real state on a young network and while the relay list waits
    // for its refresh, so it is worded rather than printed as a bare 0.
    m_candidates->setText(m_relay_count > 0 ? QString::number(m_relay_count) : tr("none yet"));
    UpdatePay();

    const UniValue& epoch = find_value(value, "epoch");
    m_epoch->setText(epoch.isNum() ? QString::number(epoch.get_int64()) : tr("\xe2\x80\x94"));

    FillKeys(m_guards, find_value(value, "guards"), tr("none chosen yet"));
    FillKeys(m_rendezvous, find_value(value, "rendezvous"),
             tr("none \xe2\x80\x94 the roster has no relays to derive them from"));
}

void OverlayPage::onRpcFailed(const QString& tag, const QString& message)
{
    if (tag == TAG_ROSTER) { m_listed = -1; UpdatePay(); return; }
    if (tag == TAG_SUBSIDY) { m_subsidy = -1; UpdatePay(); return; }
    if (tag != TAG_OVERLAY) return;
    m_state->setText(message);
    m_relay_count = -1;
    UpdatePay();
}

void OverlayPage::UpdatePay()
{
    const QString unknown = QString::fromUtf8("\xe2\x80\x94");

    const qint64 issued = m_subsidy < 0 ? -1 : m_subsidy * (qint64)BLOCKS_PER_DAY;
    // Only the cold-staker fee reaches a user: a relay pays by delegating
    // stake, and consensus fixes the staker's cut at exactly this percentage.
    const qint64 payable = issued < 0 ? -1 : (issued * COLD_STAKER_FEE) / 100;

    m_issued->setText(issued < 0 ? unknown
                                 : BitcoinUnits::formatWithUnit(m_display_unit, issued));
    m_payable->setText(payable < 0 ? unknown
                                   : BitcoinUnits::formatWithUnit(m_display_unit, payable));
    m_relays->setText(m_relay_count < 0 ? unknown : QString::number(m_relay_count));

    // Everyone listed who is not a relay is somebody a relay could be carrying.
    // The roster does not record which relay listed whom - a record names a key
    // and an endpoint, nothing about who paid for it - so this is the network
    // average rather than any particular relay's roll.
    const int users = (m_listed < 0 || m_relay_count < 0) ? -1 : m_listed - m_relay_count;
    m_users->setText(users < 0 ? unknown : QString::number(users));

    if (users < 0 || m_relay_count <= 0) {
        m_per_relay->setText(unknown);
        m_share->setText(m_relay_count == 0 ? tr("no relays yet") : unknown);
        m_share_amount->setText(unknown);
        return;
    }

    const double per_relay = (double)users / (double)m_relay_count;
    m_per_relay->setText(QString::number(per_relay, 'f', 1));

    // One user on a relay takes all of it; fewer than one is still all of it,
    // not more, so the share is capped rather than allowed past 100%.
    const double share = per_relay <= 1.0 ? 100.0 : 100.0 / per_relay;
    m_share->setText(QString::number(share, 'f', share < 10.0 ? 2 : 1) + "%");

    if (payable < 0 || users == 0) {
        m_share_amount->setText(users == 0 ? tr("nobody to pay") : unknown);
        return;
    }
    m_share_amount->setText(BitcoinUnits::formatWithUnit(m_display_unit, payable / (qint64)users));
}
