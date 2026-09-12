// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/publishdialog.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>

#include <chainparams.h>
#include <roster/record.h>
#include <univalue.h>

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
#include <QVBoxLayout>

namespace {
//! Blocks between the record being built and the transaction confirming. The
//! RPC's own default; repeated here because the longer choices set an explicit
//! expiry and would otherwise lose the margin.
const int CONFIRM_MARGIN = 144;

const char* TAG_WALLETS = "publish:wallets";
const char* TAG_CREATE = "publish:create";
const char* TAG_PUBLISH = "publish:send";
} // namespace

PublishDialog::PublishDialog(BpsRpc& rpc, int tip, bool renewing, QWidget* parent)
    : QDialog(parent), m_rpc(rpc), m_tip(tip)
{
    setWindowTitle(renewing ? tr("Renew your listing") : tr("Publish your listing"));
    setMinimumWidth(520);

    QVBoxLayout* outer = new QVBoxLayout(this);

    QLabel* intro = new QLabel(
        renewing
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

    QLabel* nowhere_note = new QLabel(
        tr("Your listing says who you are and not where you run. Peers reach you over "
           "the overlay instead, meeting you at points both sides work out from the "
           "roster. This is what this client turns on by default."),
        where);
    nowhere_note->setWordWrap(true);
    nowhere_note->setContentsMargins(24, 0, 0, 0);
    QFont small = nowhere_note->font();
    small.setPointSizeF(small.pointSizeF() * 0.9);
    nowhere_note->setFont(small);
    where_layout->addWidget(nowhere_note);

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

    QLabel* address_note = new QLabel(
        tr("Anyone can see it, and the chain keeps it permanently. An onion address "
           "publishes a location nobody can trace back to you and works from behind "
           "NAT; an IP address does neither."),
        where);
    address_note->setWordWrap(true);
    address_note->setContentsMargins(24, 0, 0, 0);
    QFont address_font = address_note->font();
    address_font.setPointSizeF(address_font.pointSizeF() * 0.9);
    address_note->setFont(address_font);
    where_layout->addWidget(address_note);

    m_nowhere->setChecked(true);
    outer->addWidget(where);

    // --- how long, and who pays ----------------------------------------
    QFormLayout* form = new QFormLayout();

    // Not a choice. A listing runs a month and is then renewed - that is the
    // cadence the relay economics are built on, where a relay pays for its
    // users' monthly renewals and a relay's own listing runs yearly. Offering a
    // slider here would invite an operator to pick a length that does not match
    // the role they are in.
    QLabel* duration = new QLabel(tr("A month, then it needs renewing"), this);
    form->addRow(tr("How long it lasts"), duration);

    m_wallet = new QComboBox(this);
    m_wallet->setEnabled(false);
    m_wallet->addItem(tr("looking for a wallet\xe2\x80\xa6"));
    form->addRow(tr("Pay the fee from"), m_wallet);

    outer->addLayout(form);

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
    connect(&m_rpc, &BpsRpc::result, this, &PublishDialog::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &PublishDialog::onRpcFailed);

    onAddressChoiceChanged();

    // Which wallets are loaded decides whether publishing is possible at all,
    // so ask before the user fills anything in.
    m_rpc.Call(TAG_WALLETS, "listwallets");
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
    m_wallet->setEnabled(!busy && m_wallet->count() > 1);
}

void PublishDialog::ShowError(const QString& message)
{
    m_status->setText("<span style='color:#a3282c;'>" + message.toHtmlEscaped() + "</span>");
}

void PublishDialog::onPublish()
{
    if (!m_wallet->currentData().isValid()) {
        ShowError(tr("No wallet is loaded, so there is nothing to pay the fee from. "
                     "Open a wallet in the core client first."));
        return;
    }

    UniValue options(UniValue::VOBJ);

    if (m_at_address->isChecked()) {
        const QString address = m_address->text().trimmed();
        if (address.isEmpty()) {
            ShowError(tr("Enter an address, or choose not to publish one."));
            return;
        }
        UniValue endpoint(UniValue::VOBJ);
        endpoint.pushKV("network", m_network->currentData().toString().toStdString());
        endpoint.pushKV("address", address.toStdString());
        endpoint.pushKV("port", m_port->value());
        UniValue endpoints(UniValue::VARR);
        endpoints.push_back(endpoint);
        options.pushKV("endpoints", endpoints);
    }

    // A month, plus slack for the transaction to confirm - the same default
    // createannouncement would apply on its own, stated here rather than left
    // implicit because the height is what actually goes on the chain.
    options.pushKV("expiry_height", m_tip + (int)roster::MIN_TTL + CONFIRM_MARGIN);

    UniValue params(UniValue::VARR);
    params.push_back(options);

    SetBusy(true);
    m_status->setText(tr("Signing the record\xe2\x80\xa6"));
    m_rpc.Call(TAG_CREATE, "createannouncement", params);
}

void PublishDialog::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_WALLETS) {
        m_wallet->clear();
        if (value.isArray() && value.size() > 0) {
            for (size_t i = 0; i < value.size(); ++i) {
                if (!value[i].isStr()) continue;
                const std::string name = value[i].get_str();
                m_wallet->addItem(name.empty() ? tr("(default wallet)") : QString::fromStdString(name),
                                  QString::fromStdString(name));
            }
            m_wallet->setEnabled(m_wallet->count() > 1);
        } else {
            m_wallet->addItem(tr("no wallet is open"));
            m_wallet->setEnabled(false);
        }
        return;
    }

    if (tag == TAG_CREATE) {
        const UniValue& hex = find_value(value, "hex");
        if (!hex.isStr()) {
            SetBusy(false);
            ShowError(tr("The node returned a record this client did not understand."));
            return;
        }

        const UniValue& warnings = find_value(value, "warnings");
        if (warnings.isArray() && warnings.size() > 0) {
            QStringList lines;
            for (size_t i = 0; i < warnings.size(); ++i) {
                if (warnings[i].isStr()) lines << QString::fromStdString(warnings[i].get_str());
            }
            if (!lines.isEmpty()) m_status->setText(lines.join("\n"));
        } else {
            m_status->setText(tr("Paying to publish it\xe2\x80\xa6"));
        }

        UniValue params(UniValue::VARR);
        params.push_back(hex.get_str());
        m_rpc.Call(TAG_PUBLISH, "publishrecord", params,
                   "/wallet/" + m_wallet->currentData().toString());
        return;
    }

    if (tag == TAG_PUBLISH) {
        SetBusy(false);
        const UniValue& txid = find_value(value, "txid");
        if (txid.isStr()) Q_EMIT published(QString::fromStdString(txid.get_str()));
        accept();
        return;
    }
}

void PublishDialog::onRpcFailed(const QString& tag, const QString& message)
{
    if (tag == TAG_WALLETS) {
        m_wallet->clear();
        m_wallet->addItem(tr("no wallet is open"));
        m_wallet->setEnabled(false);
        return;
    }
    if (tag != TAG_CREATE && tag != TAG_PUBLISH) return;

    SetBusy(false);
    ShowError(message);
}
