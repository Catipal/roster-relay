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
#include <overlay/socket.h>
#include <roster/listing.h>
#include <util/system.h>
#include <roster/record.h>
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
#include <QRadioButton>
#include <QSpinBox>
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
                             QWidget* parent, bool gateway_key)
    : QDialog(parent), m_rpc(rpc), m_wallets(wallets), m_tip(tip), m_gateway_key(gateway_key)
{
    setWindowTitle(gateway_key ? tr("List this relay's gateway")
                               : renewing ? tr("Renew your listing") : tr("Publish your listing"));
    setMinimumWidth(540);

    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setSizeConstraint(QLayout::SetMinimumSize);

    QLabel* intro = new QLabel(
        gateway_key
            ? tr("A relay's own listing carries its address, so its gateway is listed under a second "
                 "key with no address, apart from it. Nobody can tell from the roster that the two belong "
                 "to one computer. Visitors reach the gateway through relays, so it never learns who they "
                 "are; the websites they visit see this computer's address.")
        : renewing
            ? tr("Renewing writes a fresh record to the chain. Until it confirms, the "
                 "old one still counts.")
            : tr("This writes a short record to the chain saying that you exist, and "
                 "optionally where to find you."),
        this);
    intro->setWordWrap(true);
    outer->addWidget(intro);

    // --- where ---------------------------------------------------------
    QGroupBox* where = new QGroupBox(tr("How should peers reach you?"), this);
    QVBoxLayout* where_layout = new QVBoxLayout(where);

    // The overlay comes first and is the default. Publishing an address is the
    // exception, not the starting point: a listing with no address is legal,
    // useful and private, and a default that leaks your location is a default
    // most people will never change.
    m_nowhere = new QRadioButton(tr("Through the overlay \xe2\x80\x94 publish no address"), where);
    where_layout->addWidget(m_nowhere);
    QLabel* nowhere_note = SmallNote(
        tr("Your listing says who you are and not where you run. Peers reach you over "
           "the overlay, meeting you at points both sides work out from the roster, "
           "which change every day; Discovery shows today's. Your listing also names "
           "one relay where you can be met for as long as it lasts, and each renewal "
           "names a new one. This is what this client turns on by default."),
        where);
    nowhere_note->setContentsMargins(24, 0, 0, 0);
    where_layout->addWidget(nowhere_note);

    // Relaying and the gateway are settings of the node, on the Server page,
    // not choices made with each listing: the listing
    // only takes over what they are when it is published, since others find
    // relays and gateways by it. Never both on one key: a relay's address is
    // public, and the gateway beside it would be an exit at that address, so
    // a relay lists its gateway under a second key, from the Server page.
    QString settings_note;
    if (ServerPage::RelaySwitchedOn()) {
        settings_note = tr("This node carries others' paths as a relay, as set on the Server page, so the "
                           "listing says so. Its address is announced while it runs, never written to the chain.");
    } else if (ServerPage::GatewaySwitchedOn()) {
        settings_note = tr("This node shares its internet connection as a gateway, as set on the Server page, "
                           "so the listing says so.");
    } else {
        settings_note = tr("This node neither relays for others nor shares its internet connection, as set "
                           "on the Server page.");
    }
    QLabel* switches_note = SmallNote(settings_note + " " + tr("A change there reaches the roster with your next listing."), where);
    switches_note->setContentsMargins(24, 0, 0, 0);
    where_layout->addWidget(switches_note);

    m_at_address = new QRadioButton(tr("At an address I publish"), where);
    where_layout->addWidget(m_at_address);

    m_address_row = new QWidget(where);
    QHBoxLayout* row = new QHBoxLayout(m_address_row);
    row->setContentsMargins(24, 0, 0, 0);
    m_network = new QComboBox(m_address_row);
    m_network->addItem(tr("IPv4"), "ipv4");
    m_network->addItem(tr("IPv6"), "ipv6");
    m_network->addItem(tr("Onion"), "onion");
    m_network->addItem(tr("I2P"), "i2p");
    m_network->addItem(tr("cjdns"), "cjdns");
    m_address = new QLineEdit(m_address_row);
    m_address->setPlaceholderText(tr("address other peers can reach"));
    m_port = new QSpinBox(m_address_row);
    m_port->setRange(1, 65535);
    m_port->setValue(Params().GetDefaultPort());
    row->addWidget(m_network);
    row->addWidget(m_address, 1);
    row->addWidget(m_port);
    where_layout->addWidget(m_address_row);

    QLabel* address_note = SmallNote(
        tr("Anyone can see it, and the chain keeps it permanently. An onion address "
           "publishes a location nobody can trace back to you and works from behind "
           "NAT; an IP address does neither. A node that publishes an IP address can "
           "be chosen as a relay by others."),
        where);
    address_note->setContentsMargins(24, 0, 0, 0);
    where_layout->addWidget(address_note);

    m_nowhere->setChecked(true);
    outer->addWidget(where);
    // A gateway key has no address to choose.
    if (gateway_key) where->setVisible(false);

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

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outer->addWidget(m_status);

    m_buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
    m_publish = m_buttons->addButton(renewing ? tr("Renew") : tr("Publish"), QDialogButtonBox::AcceptRole);
    m_publish->setDefault(true);
    outer->addWidget(m_buttons);

    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_publish, &QPushButton::clicked, this, &PublishDialog::onPublish);
    connect(m_at_address, &QRadioButton::toggled, this, &PublishDialog::onAddressChoiceChanged);
    connect(m_payer, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, &PublishDialog::onPayerChanged);
    connect(&m_rpc, &BpsRpc::result, this, &PublishDialog::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &PublishDialog::onRpcFailed);

    onAddressChoiceChanged();
    FillPayers();

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
    // Never this node's wallet for a gateway key: its coins are the ones that
    // paid for the relay's own listing, so the chain would tie the gateway to
    // the relay's address. Another relay pays, asked through a path.
    if (m_wallets && !m_gateway_key) {
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
    // Always offered, and the default when no wallet can pay: the user signs,
    // the relay pays, which is how a node with no coins gets listed at all.
    m_payer->addItem(m_gateway_key ? tr("Another relay pays, asked through a path")
                                   : tr("A relay pays \xe2\x80\x94 needs no coins"),
                     RELAY);
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

    if (RelayChosen()) {
        if (!m_overlay_on) {
            note = tr("The overlay is off, so there is no relay to ask. Turn it on in Settings, "
                      "or pay from a wallet.");
            can_publish = false;
        } else if (m_relays == 0) {
            note = tr("No relay is listed in the roster yet, so there is nobody to ask. Pay from a "
                      "wallet, or try again once a relay has listed itself.");
            can_publish = false;
        } else if (m_gateway_key) {
            note = tr("Your node signs the gateway's listing and sends it through relays to another relay, "
                      "which pays for it and puts it into a block it stakes. That relay learns the gateway's "
                      "key and never this computer's address. Paying from this node's own wallet would tie "
                      "the gateway to this relay on the chain, and so to its address.");
        } else {
            note = tr("Your node signs the listing and sends it over the overlay to the relay it "
                      "enters through. A relay that pays for listings puts yours into a block it "
                      "stakes itself, so it confirms even while most nodes would not pass it on, and "
                      "adds you to the peers it shares its rewards with. If it later stops paying, your "
                      "listing lapses within the month; you can always renew from a funded wallet "
                      "yourself.");
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
    m_publish->setEnabled(can_publish);
    // A dialog does not grow by itself when a label gains text, and the notes
    // above would otherwise be clipped to whatever height it opened at.
    adjustSize();
}

void PublishDialog::onAddressChoiceChanged()
{
    m_address_row->setEnabled(m_at_address->isChecked());
}

void PublishDialog::SetBusy(bool busy)
{
    m_publish->setEnabled(!busy);
    m_network->setEnabled(!busy && m_at_address->isChecked());
    m_address->setEnabled(!busy && m_at_address->isChecked());
    m_port->setEnabled(!busy && m_at_address->isChecked());
    m_payer->setEnabled(!busy && m_payer->count() > 1);
    m_length->setEnabled(!busy);
    m_nowhere->setEnabled(!busy);
    m_at_address->setEnabled(!busy);
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
    if (m_gateway_key) {
        options.pushKV("key", "gateway");
    } else if (m_nowhere->isChecked() && ServerPage::RelaySwitchedOn()) {
        options.pushKV("relay", true);
    } else if (m_nowhere->isChecked() && ServerPage::GatewaySwitchedOn()) {
        // Never a gateway at a published address: that would say where an exit is.
        options.pushKV("gateway", true);
    }
    if (!m_gateway_key && m_at_address->isChecked()) {
        const QString address = m_address->text().trimmed();
        if (address.isEmpty()) {
            ShowError(tr("Enter an address, or choose not to publish one."));
            return false;
        }
        UniValue endpoint(UniValue::VOBJ);
        endpoint.pushKV("network", m_network->currentData().toString().toStdString());
        endpoint.pushKV("address", address.toStdString());
        endpoint.pushKV("port", m_port->value());
        UniValue endpoints(UniValue::VARR);
        endpoints.push_back(endpoint);
        options.pushKV("endpoints", endpoints);
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
        m_status->setText(m_gateway_key
                              ? tr("Asking a relay through a path to publish it\xe2\x80\xa6 this can take a minute.")
                              : tr("Asking your relay to publish it\xe2\x80\xa6 this can take up to half a minute."));
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
