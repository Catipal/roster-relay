// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/publishdialog.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>
#include <qt/bps/serverpage.h>

#ifdef ENABLE_WALLET
#include <interfaces/wallet.h>
#include <qt/bitcoinunits.h>
#include <qt/optionsmodel.h>
#include <qt/walletcontroller.h>
#include <rpc/server.h>
#endif

#include <amount.h>
#include <chainparams.h>
#include <net.h>
#include <overlay/gateway.h>
#include <overlay/select.h>
#include <overlay/socket.h>
#include <roster/listing.h>
#include <util/system.h>
#include <roster/record.h>
#include <span.h>
#include <univalue.h>

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QStringList>
#include <QUrl>
#include <QVBoxLayout>

namespace {

const char* TAG_OVERLAY = "publish:overlay";
const char* TAG_CREATE = "publish:create";
const char* TAG_PUBLISH = "publish:send";
const char* TAG_REQUEST = "publish:relay";

const QString RELAY = QStringLiteral("relay");
const QString WALLET_PREFIX = QStringLiteral("wallet:");

//! Below this a wallet is not picked as the payer by default. A listing costs
//! a few thousand satoshi; the margin is for the fee estimate moving.
const CAmount MIN_PAYER_BALANCE = 10000;

QLabel* SmallNote(const QString& text, QWidget* parent)
{
    QLabel* note = new QLabel(text, parent);
    note->setWordWrap(true);
    QFont small = note->font();
    small.setPointSizeF(small.pointSizeF() * 0.9);
    note->setFont(small);
    return note;
}
} // namespace

PublishDialog::PublishDialog(BpsRpc& rpc, WalletController* wallets, int tip, bool renewing,
                             const QString& note, QWidget* parent, bool updating)
    : QDialog(parent), m_rpc(rpc), m_wallets(wallets), m_tip(tip), m_updating(updating)
{
    setWindowTitle(updating ? tr("Update your listing")
                            : renewing ? tr("Renew your listing") : tr("Publish your listing"));
    setMinimumWidth(540);

    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setSizeConstraint(QLayout::SetMinimumSize);

    QLabel* intro = new QLabel(
        updating
            ? tr("Updating writes a fresh record to the chain that replaces your listing, so it says "
                 "what the Server page now says about relaying. Until it confirms, the old one still "
                 "counts. It is paid from a wallet: a relay pays only for a renewal.")
        : renewing
            ? tr("Renewing writes a fresh record to the chain. Until it confirms, the "
                 "old one still counts.")
            : tr("This writes a short record to the chain saying that you exist, and "
                 "optionally a line about you."),
        this);
    intro->setWordWrap(true);
    outer->addWidget(intro);

    // --- what the listing says ------------------------------------------
    // No address: a listing says who you are and not where you run, and the
    // chain would keep an address for good. A line of the owner's own text
    // stands where an address used to.
    QGroupBox* says = new QGroupBox(tr("What your listing says"), this);
    QVBoxLayout* says_layout = new QVBoxLayout(says);

    QLabel* overlay_note = SmallNote(
        tr("Your listing says who you are and not where you run: it carries no address. Peers "
           "reach you over the overlay, meeting you at points both sides work out from the "
           "roster, which change every day; Discovery shows today's. Your listing also names "
           "one relay where you can be met for as long as it lasts, and each renewal names a "
           "new one."),
        says);
    says_layout->addWidget(overlay_note);

    // Relaying is a setting of the node, on the Server page, not a choice made
    // with each listing: the listing only takes it over
    // when it is published, since others find relays by it. Sharing the
    // internet is not in the listing at all.
    if (ServerPage::RelaySwitchedOn()) {
        QLabel* switches_note = SmallNote(
            tr("This node carries others' paths as a relay, as set on the Server page, so the "
               "listing says so. Its address is announced while it runs, never written to the chain.") +
                " " + tr("A change there reaches the roster with your next listing."),
            says);
        says_layout->addWidget(switches_note);
    }

    QHBoxLayout* note_row = new QHBoxLayout();
    QLabel* note_label = new QLabel(tr("Note"), says);
    m_note = new QLineEdit(says);
    m_note->setPlaceholderText(tr("optional: a line shown beside your key"));
    m_note->setText(note);
    note_label->setBuddy(m_note);
    m_note_count = new QLabel(says);
    note_row->addWidget(note_label);
    note_row->addWidget(m_note, 1);
    note_row->addWidget(m_note_count);
    says_layout->addLayout(note_row);

    QLabel* note_warning = SmallNote(
        tr("Anyone can read it, and the chain keeps it for good, even after the listing ends. "
           "Leave out anything that says where you are or who you are, if that matters to you."),
        says);
    says_layout->addWidget(note_warning);
    outer->addWidget(says);

    // --- who pays, and how long ----------------------------------------
    QFormLayout* form = new QFormLayout();

    m_payer = new QComboBox(this);
    form->addRow(tr("Who pays the fee"), m_payer);

    // The length follows who pays, from the relay economics: a listing a relay
    // pays for runs a month, so a peer that has left stops costing its relay
    // within the month; a node paying for itself - which is how a relay lists -
    // may take a year. Never a free slider, which would invite a length that
    // does not match the role.
    QWidget* length = new QWidget(this);
    QHBoxLayout* length_row = new QHBoxLayout(length);
    length_row->setContentsMargins(0, 0, 0, 0);
    m_length_fixed = new QLabel(tr("A month, then it needs renewing"), length);
    m_length = new QComboBox(length);
    m_length->addItem(tr("A month, then it needs renewing"));
    m_length->addItem(tr("A year, then it needs renewing"));
    length_row->addWidget(m_length_fixed);
    length_row->addWidget(m_length);
    length_row->addStretch(1);
    form->addRow(tr("How long it lasts"), length);
    outer->addLayout(form);

    m_payer_note = SmallNote(QString(), this);
    outer->addWidget(m_payer_note);

    m_ask_entry = new QCheckBox(tr("Ask my entry relay directly \xe2\x80\x94 it will see my IP address"), this);
    m_ask_entry->setVisible(false);
    outer->addWidget(m_ask_entry);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outer->addWidget(m_status);

    m_buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
    m_publish = m_buttons->addButton(updating ? tr("Update") : renewing ? tr("Renew") : tr("Publish"),
                                     QDialogButtonBox::AcceptRole);
    m_publish->setDefault(true);
    outer->addWidget(m_buttons);

    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_publish, &QPushButton::clicked, this, &PublishDialog::onPublish);
    connect(m_note, &QLineEdit::textChanged, this, &PublishDialog::onNoteChanged);
    connect(m_payer, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, &PublishDialog::onPayerChanged);
    connect(m_ask_entry, &QCheckBox::toggled, this, &PublishDialog::onPayerChanged);
    connect(&m_rpc, &BpsRpc::result, this, &PublishDialog::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &PublishDialog::onRpcFailed);

    FillPayers();
    onNoteChanged();

    // Whether a relay can be asked at all depends on the overlay, so find out
    // before the user picks.
    m_rpc.Call(TAG_OVERLAY, "getoverlayinfo");
}

PublishDialog::~PublishDialog() = default;

void PublishDialog::FillPayers()
{
    m_payer->blockSignals(true);
    m_payer->clear();
    int preferred = -1;
#ifdef ENABLE_WALLET
    if (m_wallets) {
        for (WalletModel* model : m_wallets->getOpenWallets()) {
            const CAmount balance = model->wallet().getBalances().balance;
            const int unit = model->getOptionsModel() ? model->getOptionsModel()->getDisplayUnit()
                                                      : (int)BitcoinUnits::BPS;
            m_payer->addItem(tr("%1 \xe2\x80\x94 %2").arg(model->getDisplayName(),
                                                           BitcoinUnits::formatWithUnit(unit, balance)),
                             WALLET_PREFIX + model->getWalletName());
            if (preferred < 0 && balance >= MIN_PAYER_BALANCE) preferred = m_payer->count() - 1;
        }
    }
#endif
    // Offered, and the default when no wallet can pay: the user signs, the
    // relay pays, which is how a node with no coins gets listed at all. Not
    // for an early update, which a relay refuses as a renewal before its time.
    if (!m_updating) m_payer->addItem(tr("A relay pays \xe2\x80\x94 needs no coins"), RELAY);
    m_payer->setCurrentIndex(preferred >= 0 ? preferred : m_payer->count() - 1);
    m_payer->setEnabled(m_payer->count() > 1);
    m_payer->blockSignals(false);
    onPayerChanged();
}

bool PublishDialog::RelayChosen() const
{
    return m_payer->currentData().toString() == RELAY;
}

void PublishDialog::onPayerChanged()
{
    bool can_publish = true;
    QString note;
    m_length->setVisible(!RelayChosen());
    m_length_fixed->setVisible(RelayChosen());
    // This node enters the overlay through up to PathSelector::GUARD_COUNT
    // relays and never asks those through a path; with no more relays listed
    // than that, the only way is to ask one of them directly.
    const bool only_entry = m_overlay_on && m_relays > 0 && m_relays <= (int)overlay::PathSelector::GUARD_COUNT;
    m_ask_entry->setVisible(RelayChosen() && only_entry);

    if (m_payer->count() == 0) {
        note = tr("No wallet is open to pay for the update. Open one with a little BPS in it.");
        can_publish = false;
    } else if (RelayChosen()) {
        if (!m_overlay_on) {
            note = tr("The overlay is off, so there is no relay to ask. Turn it on in Settings, "
                      "or pay from a wallet.");
            can_publish = false;
        } else if (m_relays == 0) {
            note = tr("No relay is listed in the roster yet, so there is nobody to ask. Pay from a "
                      "wallet, or try again once a relay has listed itself.");
            can_publish = false;
        } else if (only_entry) {
            note = tr("The roster lists too few relays to reach one through a path: this node enters "
                      "the overlay through them, and asks only a relay it does not enter through, so "
                      "that no relay learns both where you are and who you are. Until there are at "
                      "least three, you can ask your entry relay directly. It then sees your IP "
                      "address together with your key. Or pay from a wallet.");
            can_publish = m_ask_entry->isChecked();
        } else {
            note = tr("Your node signs the listing and sends it through a path to a relay it does not "
                      "enter through, so that relay learns who you are and not where. A relay that pays "
                      "for listings puts yours into a block it stakes itself, so it confirms even while "
                      "most nodes would not pass it on, and adds you to the peers it shares its rewards "
                      "with. If it later stops paying, your listing lapses within the month; you can "
                      "always renew from a funded wallet yourself.");
        }
    }
#ifdef ENABLE_WALLET
    else if (m_wallets) {
        // Settled 2026-09-07: a listing is bigger than a 0.21 node passes on,
        // so until most stakers upgrade it reaches a block through a staker
        // running this version - this node, if it stakes.
        bool staking = false;
        OwnConfirmWindow(staking);
        if (!staking) {
            note = tr("This node isn't staking. A listing is bigger than older nodes pass on, so "
                      "until most stakers upgrade it confirms only when a staker running this "
                      "version includes it, which can take a while. Staking puts it in your own "
                      "next block; a relay that pays stakes it into its own.");
        }
        const QString name = m_payer->currentData().toString().mid(WALLET_PREFIX.size());
        for (WalletModel* model : m_wallets->getOpenWallets()) {
            if (model->getWalletName() != name) continue;
            const WalletModel::EncryptionStatus status = model->getEncryptionStatus();
            if (status == WalletModel::Unlocked && model->getWalletUnlockStakingOnly()) {
                if (!note.isEmpty()) note += "\n\n";
                note += tr("This wallet is unlocked for staking only. Paying asks for its passphrase, "
                          "and the wallet locks again afterwards, which stops staking until you "
                          "unlock it for staking again.");
            } else if (status == WalletModel::Locked) {
                if (!note.isEmpty()) note += "\n\n";
                note += tr("Paying asks for this wallet's passphrase.");
            }
        }
    }
#endif

    m_payer_note->setText(note);
    m_payer_note->setVisible(!note.isEmpty());
    m_publish->setEnabled(can_publish && m_note_fits);
    // A dialog does not grow by itself when a label gains text, and the notes
    // above would otherwise be clipped to whatever height it opened at.
    adjustSize();
}

void PublishDialog::onNoteChanged()
{
    // Counted the way the record counts it, in bytes of UTF-8, so a note with
    // accents or other scripts is told how much room it really has.
    const int used = m_note->text().trimmed().toUtf8().size();
    const int room = (int)roster::MAX_NOTE_SIZE;
    m_note_fits = used <= room;
    m_note_count->setText(tr("%1 / %2 bytes").arg(used).arg(room));
    m_note_count->setStyleSheet(m_note_fits ? QString() : QStringLiteral("color:#a3282c;"));
    m_note_count->setToolTip(m_note_fits ? QString()
                                         : tr("Too long: letters outside plain English take two to four bytes each."));
    onPayerChanged();
}

void PublishDialog::SetBusy(bool busy)
{
    m_publish->setEnabled(!busy);
    m_note->setEnabled(!busy);
    m_payer->setEnabled(!busy && m_payer->count() > 1);
    m_length->setEnabled(!busy);
    m_ask_entry->setEnabled(!busy);
    if (!busy) onPayerChanged();
}

void PublishDialog::ShowError(const QString& message)
{
    m_status->setText("<span style='color:#a3282c;'>" + message.toHtmlEscaped() + "</span>");
}

void PublishDialog::Done()
{
#ifdef ENABLE_WALLET
    // Relocks the wallet if this dialog was what unlocked it.
    m_unlock.reset();
#endif
}

bool PublishDialog::BuildOptions(UniValue& options)
{
    options = UniValue(UniValue::VOBJ);
    if (ServerPage::RelaySwitchedOn()) options.pushKV("relay", true);
    const QByteArray note = m_note->text().trimmed().toUtf8();
    if (!note.isEmpty()) {
        if (!roster::IsValidNote(MakeUCharSpan(note))) {
            ShowError(note.size() > (int)roster::MAX_NOTE_SIZE
                          ? tr("The note is too long.")
                          : tr("The note can't contain control characters or marks that change the "
                               "direction of text."));
            return false;
        }
        options.pushKV("note", std::string(note.constData(), note.size()));
    }
    // A month, plus the blocks it may wait to confirm and still count. Paid
    // from this node's wallet, the block is this node's own if it stakes, so
    // the wait is sized to its stake; a relay that needs longer asks, and
    // requestlisting signs again.
    if (!RelayChosen() && m_length->currentIndex() == 1) {
        // A year from the first block it could confirm in. Valid for a block
        // anywhere up to MAX_TTL - MIN_TTL later, so the wait to confirm needs
        // no allowance of its own.
        options.pushKV("expiry_height", m_tip + (int)roster::MAX_TTL);
        return true;
    }
    uint32_t window = roster::DEFAULT_CONFIRM_WINDOW;
    if (!RelayChosen()) {
        bool staking = false;
        const uint32_t own = OwnConfirmWindow(staking);
        if (staking && own > 0) window = own;
    }
    options.pushKV("expiry_height", m_tip + (int)roster::MIN_TTL + (int)window);
    return true;
}

uint32_t PublishDialog::OwnConfirmWindow(bool& staking) const
{
    staking = false;
#ifdef ENABLE_WALLET
    if (!m_wallets) return 0;
    uint64_t weight = 0;
    for (WalletModel* model : m_wallets->getOpenWallets()) {
        if (!model->wallet().getEnabledStaking() || !model->wallet().getLastCoinStakeSearchInterval()) continue;
        weight += model->getStakeWeight();
    }
    staking = weight > 0;
    return roster::NeededConfirmWindow(weight, (uint64_t)GetPoSKernelPS());
#else
    return 0;
#endif
}

void PublishDialog::onPublish()
{
    UniValue options;
    if (!BuildOptions(options)) return;
    UniValue params(UniValue::VARR);
    params.push_back(options);

    if (RelayChosen()) {
        SetBusy(true);
        if (m_ask_entry->isVisible() && m_ask_entry->isChecked()) {
            UniValue choice(UniValue::VOBJ);
            choice.pushKV("entry", true);
            params.push_back(choice);
            m_status->setText(tr("Asking your entry relay to publish it\xe2\x80\xa6 this can take a minute."));
        } else {
            m_status->setText(tr("Asking a relay through a path to publish it\xe2\x80\xa6 this can take a minute."));
        }
        m_rpc.Call(TAG_REQUEST, "requestlisting", params);
        return;
    }

#ifdef ENABLE_WALLET
    // Ask for the passphrase here, where the user can see why, rather than
    // letting the node refuse with a message about walletpassphrase.
    const QString name = m_payer->currentData().toString().mid(WALLET_PREFIX.size());
    WalletModel* payer = nullptr;
    if (m_wallets) {
        for (WalletModel* model : m_wallets->getOpenWallets()) {
            if (model->getWalletName() == name) payer = model;
        }
    }
    if (!payer) {
        ShowError(tr("That wallet is no longer open."));
        FillPayers();
        return;
    }
    const WalletModel::EncryptionStatus status = payer->getEncryptionStatus();
    if (status == WalletModel::Locked ||
        (status == WalletModel::Unlocked && payer->getWalletUnlockStakingOnly())) {
        m_unlock.reset(new WalletModel::UnlockContext(payer->requestUnlock()));
        if (!m_unlock->isValid()) {
            m_unlock.reset();
            ShowError(tr("The wallet is still locked, so nothing was paid."));
            return;
        }
    }
#endif

    SetBusy(true);
    m_status->setText(tr("Signing the record\xe2\x80\xa6"));
    m_rpc.Call(TAG_CREATE, "createannouncement", params);
}

void PublishDialog::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_OVERLAY) {
        const UniValue& enabled = find_value(value, "enabled");
        m_overlay_on = enabled.isBool() && enabled.get_bool();
        const UniValue& relays = find_value(value, "relay_candidates");
        m_relays = relays.isNum() ? relays.get_int() : (m_overlay_on ? -1 : 0);
        onPayerChanged();
        return;
    }

    if (tag == TAG_CREATE) {
        const UniValue& hex = find_value(value, "hex");
        if (!hex.isStr()) {
            Done();
            SetBusy(false);
            ShowError(tr("The node returned a record this client did not understand."));
            return;
        }
        m_status->setText(tr("Paying to publish it\xe2\x80\xa6"));

        const QString name = m_payer->currentData().toString().mid(WALLET_PREFIX.size());
        UniValue params(UniValue::VARR);
        params.push_back(hex.get_str());
        m_rpc.Call(TAG_PUBLISH, "publishrecord", params,
                   "/wallet/" + QString::fromUtf8(QUrl::toPercentEncoding(name)));
        return;
    }

    if (tag == TAG_PUBLISH) {
        Done();
        SetBusy(false);
        const UniValue& txid = find_value(value, "txid");
        if (txid.isStr()) Q_EMIT published(QString::fromStdString(txid.get_str()), false);
        accept();
        return;
    }

    if (tag == TAG_REQUEST) {
        SetBusy(false);
        const UniValue& status = find_value(value, "status");
        const UniValue& txid = find_value(value, "txid");
        const UniValue& reason = find_value(value, "reason");
        const QString why = reason.isStr() ? QString::fromStdString(reason.get_str()) : QString();
        if (status.isStr() && status.get_str() == "published" && txid.isStr()) {
            Q_EMIT published(QString::fromStdString(txid.get_str()), true);
            accept();
        } else if (status.isStr() && status.get_str() == "refused") {
            ShowError(tr("The relay declined: %1").arg(why));
        } else {
            ShowError(tr("No answer from the relay. %1").arg(why));
        }
        return;
    }
}

void PublishDialog::onRpcFailed(const QString& tag, const QString& message)
{
    if (tag == TAG_OVERLAY) {
        m_overlay_on = false;
        m_relays = 0;
        onPayerChanged();
        return;
    }
    if (tag != TAG_CREATE && tag != TAG_PUBLISH && tag != TAG_REQUEST) return;

    Done();
    SetBusy(false);
    ShowError(message);
}
