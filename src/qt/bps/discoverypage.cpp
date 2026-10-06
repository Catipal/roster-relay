// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/discoverypage.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>
#include <qt/bps/publishdialog.h>
#include <qt/bps/rostermodel.h>

#include <qt/clientmodel.h>

#include <roster/listing.h>

#include <univalue.h>

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>

namespace {
const char* TAG_INFO = "disc:info";
const char* TAG_HISTORY = "disc:history";
const char* TAG_ROSTER = "disc:roster";

//! How many entries the table holds. The roster is bounded by the rolling
//! window rather than by the chain, but it can still be larger than anyone
//! wants to scroll, and the whole of it is one RPC call away when it matters.
const int ROSTER_PAGE = 500;

//! The roster moves at block pace, so polling faster than this buys nothing.
const int REFRESH_MS = 20000;

QLabel* MakeTile(QGridLayout* grid, int column, const QString& caption)
{
    QLabel* head = new QLabel(caption);
    QFont head_font = head->font();
    head_font.setPointSizeF(head_font.pointSizeF() * 0.85);
    head->setFont(head_font);
    head->setEnabled(false);

    QLabel* value = new QLabel();
    QFont value_font = value->font();
    value_font.setBold(true);
    value->setFont(value_font);
    value->setWordWrap(true);

    grid->addWidget(head, 0, column);
    grid->addWidget(value, 1, column);
    grid->setColumnStretch(column, 1);
    return value;
}
} // namespace

DiscoveryPage::DiscoveryPage(BpsRpc& rpc, QWidget* parent) : QWidget(parent), m_rpc(rpc)
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(6);

    QLabel* title = new QLabel(tr("Discovery"), this);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);
    outer->addWidget(title);

    QLabel* subtitle = new QLabel(
        tr("Peers announce themselves on the chain rather than to a server, so this list "
           "is the same for everyone and nobody is in a position to edit it."),
        this);
    subtitle->setWordWrap(true);
    subtitle->setEnabled(false);
    outer->addWidget(subtitle);
    outer->addSpacing(8);

    // --- the three things worth knowing at a glance ---------------------
    QGridLayout* tiles = new QGridLayout();
    tiles->setHorizontalSpacing(24);
    m_index_state = MakeTile(tiles, 0, tr("Roster"));
    m_listing_state = MakeTile(tiles, 1, tr("Your listing"));
    m_roster_size = MakeTile(tiles, 2, tr("Peers listed"));
    outer->addLayout(tiles);
    outer->addSpacing(8);

    // --- who this node is ------------------------------------------------
    QHBoxLayout* key_row = new QHBoxLayout();
    QLabel* key_caption = new QLabel(tr("You are"), this);
    key_caption->setEnabled(false);
    m_key = new QLabel(tr("\xe2\x80\x94"), this);
    m_key->setFont(BpsUtil::FixedPitchFont());
    m_key->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_copy_key = new QPushButton(tr("Copy"), this);
    m_copy_key->setEnabled(false);
    m_publish = new QPushButton(tr("Publish your listing\xe2\x80\xa6"), this);
    m_publish->setEnabled(false);

    key_row->addWidget(key_caption);
    key_row->addWidget(m_key);
    key_row->addWidget(m_copy_key);
    key_row->addStretch(1);
    key_row->addWidget(m_publish);
    outer->addLayout(key_row);

    m_error = new QLabel(this);
    m_error->setWordWrap(true);
    m_error->setVisible(false);
    outer->addWidget(m_error);

    // --- the roster itself ------------------------------------------------
    m_model = new RosterModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);

    QLineEdit* filter = new QLineEdit(this);
    filter->setPlaceholderText(tr("Find a peer or an address"));
    filter->setClearButtonEnabled(true);
    connect(filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    outer->addWidget(filter);

    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(RosterModel::Where, QHeaderView::Stretch);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    outer->addWidget(m_table, 1);

    connect(m_copy_key, &QPushButton::clicked, this, &DiscoveryPage::onCopyKey);
    connect(m_publish, &QPushButton::clicked, this, &DiscoveryPage::onPublishClicked);
    connect(&m_rpc, &BpsRpc::result, this, &DiscoveryPage::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &DiscoveryPage::onRpcFailed);

    m_timer = new QTimer(this);
    m_timer->setInterval(REFRESH_MS);
    connect(m_timer, &QTimer::timeout, this, &DiscoveryPage::Refresh);

    m_index_state->setText(tr("starting\xe2\x80\xa6"));
    m_listing_state->setText(tr("\xe2\x80\x94"));
    m_roster_size->setText(tr("\xe2\x80\x94"));
}

void DiscoveryPage::setClientModel(ClientModel* model)
{
    m_client_model = model;
    if (!model) {
        m_timer->stop();
        return;
    }
    m_tip = model->getNumBlocks();
    m_model->SetTip(m_tip);
    connect(model, &ClientModel::numBlocksChanged, this,
            [this](int count, const QDateTime&, double, bool header, SynchronizationState) {
                if (header) return;
                m_tip = count;
                m_model->SetTip(count);
                UpdateListingSummary();
            });
    m_timer->start();
    Refresh();
}

void DiscoveryPage::Refresh()
{
    m_rpc.Call(TAG_INFO, "getrosterinfo");
}

void DiscoveryPage::onCopyKey()
{
    if (m_own_key.isEmpty()) return;
    QApplication::clipboard()->setText(m_own_key);
}

void DiscoveryPage::onPublishClicked()
{
    PublishDialog dialog(m_rpc, m_wallets, m_tip, m_own_expiry > m_tip, this);
    connect(&dialog, &PublishDialog::published, this, [this](const QString& txid, bool by_relay) {
        m_error->setVisible(true);
        m_error->setText(by_relay
            ? tr("Your relay published your listing in transaction %1. It counts once the "
                 "transaction confirms.").arg(BpsUtil::ShortKey(txid))
            : tr("Published in transaction %1. It counts once the transaction confirms.")
                  .arg(BpsUtil::ShortKey(txid)));
    });
    dialog.exec();
    Refresh();
}

void DiscoveryPage::UpdateListingSummary()
{
    if (!m_index_enabled) {
        m_listing_state->setText(tr("unknown"));
        Q_EMIT listingChanged(tr("roster index off"), false);
        return;
    }
    if (m_own_expiry == 0 || m_own_expiry <= m_tip) {
        m_listing_state->setText(tr("not listed"));
        m_publish->setText(tr("Publish your listing\xe2\x80\xa6"));
        m_publish->setToolTip(QString());
        m_publish->setEnabled(true);
        Q_EMIT listingChanged(tr("not listed"), false);
    } else {
        const int blocks_left = m_own_expiry - m_tip;
        const QString left = BpsUtil::HumanBlocks(blocks_left);
        m_listing_state->setText(tr("ends in %1").arg(left));
        // Renewal opens in the listing's last three days, the same rule a relay
        // applies before paying, so a month already paid for is not cut short.
        const bool can_renew = blocks_left <= (int)roster::RENEW_WINDOW;
        m_publish->setText(can_renew ? tr("Renew your listing\xe2\x80\xa6")
                                     : tr("Renew in the last 3 days"));
        m_publish->setToolTip(can_renew ? QString()
            : tr("Your listing ends in %1. Renewing opens three days before it does.").arg(left));
        m_publish->setEnabled(can_renew);
        Q_EMIT listingChanged(tr("listed, ends in %1").arg(left), true);
    }
}

void DiscoveryPage::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_INFO) {
        const UniValue& enabled = find_value(value, "enabled");
        m_index_enabled = enabled.isBool() && enabled.get_bool();

        const UniValue& key = find_value(value, "operational_key");
        if (key.isStr()) {
            m_own_key = QString::fromStdString(key.get_str());
            m_key->setText(BpsUtil::ShortKey(m_own_key));
            m_key->setToolTip(m_own_key);
            m_copy_key->setEnabled(true);
        } else {
            const UniValue& key_error = find_value(value, "operational_key_error");
            if (key_error.isStr()) {
                m_error->setVisible(true);
                m_error->setText(tr("This node has no announcing key: %1")
                                     .arg(QString::fromStdString(key_error.get_str())));
            }
        }

        if (!m_index_enabled) {
            m_index_state->setText(tr("switched off"));
            m_roster_size->setText(tr("\xe2\x80\x94"));
            m_publish->setEnabled(false);
            m_error->setVisible(true);
            m_error->setText(tr("The roster index is not running, so this node cannot see who is "
                                "listed. Restart with -rosterindex to turn it on."));
            UpdateListingSummary();
            return;
        }

        const UniValue& synced = find_value(value, "synced");
        const UniValue& best = find_value(value, "best_block_height");
        if (synced.isBool() && !synced.get_bool()) {
            m_index_state->setText(tr("catching up (%1)").arg(best.isNum() ? best.get_int() : 0));
        } else {
            m_index_state->setText(tr("up to date"));
        }

        const UniValue& live = find_value(value, "live_peers");
        m_roster_size->setText(live.isNum() ? QString::number(live.get_int()) : tr("\xe2\x80\x94"));

        // Whether publishing or renewing is open is decided by the listing
        // itself, once its history arrives (UpdateListingSummary).
        if (m_error->text().startsWith(tr("The roster index is not running"))) m_error->setVisible(false);

        // Two follow-ups: this node's own history, and the roster to display.
        if (!m_own_key.isEmpty()) {
            UniValue params(UniValue::VARR);
            params.push_back(m_own_key.toStdString());
            m_rpc.Call(TAG_HISTORY, "getrosterhistory", params);
        }
        UniValue roster_params(UniValue::VARR);
        roster_params.push_back(ROSTER_PAGE);
        m_rpc.Call(TAG_ROSTER, "getroster", roster_params);
        return;
    }

    if (tag == TAG_HISTORY) {
        // Oldest first, so the last record with a live expiry is the one in force.
        m_own_expiry = 0;
        if (value.isArray()) {
            for (size_t i = 0; i < value.size(); ++i) {
                const UniValue& expiry = find_value(value[i], "expiry_height");
                if (expiry.isNum()) m_own_expiry = expiry.get_int();
            }
        }
        UpdateListingSummary();
        return;
    }

    if (tag == TAG_ROSTER) {
        m_model->SetRoster(value, m_tip);
        m_table->resizeColumnsToContents();
        m_table->horizontalHeader()->setSectionResizeMode(RosterModel::Where, QHeaderView::Stretch);
        return;
    }
}

void DiscoveryPage::onRpcFailed(const QString& tag, const QString& message)
{
    if (tag == TAG_HISTORY) {
        // A key with no records is a normal state, not a failure worth showing.
        m_own_expiry = 0;
        UpdateListingSummary();
        return;
    }
    if (tag != TAG_INFO && tag != TAG_ROSTER) return;

    m_error->setVisible(true);
    m_error->setText(message);
}
