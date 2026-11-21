// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/discoverypage.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>
#include <qt/bps/publishdialog.h>
#include <qt/bps/rostermodel.h>
#include <qt/bps/serverpage.h>

#include <qt/clientmodel.h>

#include <roster/listing.h>

#ifdef ENABLE_WALLET
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#endif

#include <univalue.h>

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QCursor>
#include <QDialog>
#include <QDialogButtonBox>
#include <QInputDialog>
#include <QMessageBox>
#include <QUrl>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QTimer>
#include <QToolTip>
#include <QVBoxLayout>

namespace {
const char* TAG_INFO = "disc:info";
const char* TAG_HISTORY = "disc:history";
const char* TAG_ROSTER = "disc:roster";
const char* TAG_IDENTITY = "disc:identity";
const char* TAG_DELEGATION = "disc:delegation";
const char* TAG_NAMES = "disc:names";
const char* TAG_PENDING = "disc:pending";

//! Blocks a listing transaction may be missing from the mempool, and not yet
//! in the history, before it is taken as dropped and the button opens again.
const int PENDING_GONE_BLOCKS = 3;

//! How many entries the table holds. The roster is bounded by the rolling
//! window rather than by the chain, but it can still be larger than anyone
//! wants to scroll, and the whole of it is one RPC call away when it matters.
const int ROSTER_PAGE = 500;

//! The roster moves at block pace, so polling faster than this buys nothing.
const int REFRESH_MS = 20000;

//! The text filter, and optionally only relays that have said where they are
//! in the last three hours.
class RosterFilter : public QSortFilterProxyModel
{
public:
    explicit RosterFilter(QObject* parent) : QSortFilterProxyModel(parent) {}
    void SetOnlineOnly(bool on)
    {
        m_online_only = on;
        invalidateFilter();
    }

protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override
    {
        if (m_online_only && !sourceModel()->index(row, 0, parent).data(RosterModel::OnlineRole).toBool()) return false;
        return QSortFilterProxyModel::filterAcceptsRow(row, parent);
    }

private:
    bool m_online_only{false};
};

//! Peer, note and address share the spare width equally; the rest fit their contents.
void SizeColumns(QTableView* table)
{
    table->resizeColumnsToContents();
    QHeaderView* header = table->horizontalHeader();
    header->setSectionResizeMode(RosterModel::Peer, QHeaderView::Stretch);
    header->setSectionResizeMode(RosterModel::Note, QHeaderView::Stretch);
    header->setSectionResizeMode(RosterModel::Where, QHeaderView::Stretch);
}

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
           "is the same for everyone and nobody is in a position to edit it. A peer listed "
           "through the overlay shows where it can be met today, which changes every day; "
           "a relay shows its address only while it is online, since it is never on the chain."),
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
    // One grid for the three rows below, so their values and buttons line up
    // and a row whose button is hidden keeps the height of the others.
    QGridLayout* who = new QGridLayout();
    who->setHorizontalSpacing(8);
    who->setColumnStretch(3, 1);
    QLabel* key_caption = new QLabel(tr("You are"), this);
    key_caption->setEnabled(false);
    m_key = new QLabel(tr("\xe2\x80\x94"), this);
    m_key->setFont(BpsUtil::FixedPitchFont());
    m_key->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_copy_key = new QPushButton(tr("Copy"), this);
    m_copy_key->setEnabled(false);
    m_publish = new QPushButton(tr("Publish your listing\xe2\x80\xa6"), this);
    m_publish->setEnabled(false);

    who->addWidget(key_caption, 0, 0);
    who->addWidget(m_key, 0, 1);
    who->addWidget(m_copy_key, 0, 2, Qt::AlignLeft);
    who->addWidget(m_publish, 0, 4);

    // --- the identity behind it (design note §7) ---------------------------
    QLabel* identity_caption = new QLabel(tr("Identity"), this);
    identity_caption->setEnabled(false);
    m_identity = new QLabel(tr("\xe2\x80\x94"), this);
    m_identity->setFont(BpsUtil::FixedPitchFont());
    m_identity->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_make_identity = new QPushButton(tr("Make one\xe2\x80\xa6"), this);
    m_make_identity->setVisible(false);
    m_make_identity->setToolTip(tr("An identity keeps this node's history - how long it has been listed - "
                                   "if its key ever has to change."));
    who->addWidget(identity_caption, 1, 0);
    who->addWidget(m_identity, 1, 1);
    who->addWidget(m_make_identity, 1, 2, Qt::AlignLeft);

    // --- the name that points at this key (design note 001 §11) -----------
    // A listing is a key; a name is how a person finds that key without
    // copying it. The names a key holds all resolve to it, so this is "what
    // you are known by" beside "who you are".
    QLabel* name_caption = new QLabel(tr("Name"), this);
    name_caption->setEnabled(false);
    m_name = new QLabel(tr("\xe2\x80\x94"), this);
    m_name->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_name_button = new QPushButton(tr("Register a name\xe2\x80\xa6"), this);
    m_name_button->setToolTip(tr("A name is how others reach you without copying your key. "
                                 "Names are registered on the Names tab."));
    who->addWidget(name_caption, 2, 0);
    who->addWidget(m_name, 2, 1);
    who->addWidget(m_name_button, 2, 2, Qt::AlignLeft);
    const int row_height = m_name_button->sizeHint().height();
    for (int row = 0; row < 3; ++row) who->setRowMinimumHeight(row, row_height);
    outer->addLayout(who);

    m_error = new QLabel(this);
    m_error->setWordWrap(true);
    m_error->setVisible(false);
    outer->addWidget(m_error);

    // --- the roster itself ------------------------------------------------
    m_model = new RosterModel(this);
    RosterFilter* proxy = new RosterFilter(this);
    m_proxy = proxy;
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);

    QHBoxLayout* filter_row = new QHBoxLayout();
    QLineEdit* filter = new QLineEdit(this);
    filter->setPlaceholderText(tr("Find a peer, a note or an address"));
    filter->setClearButtonEnabled(true);
    connect(filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    QCheckBox* online = new QCheckBox(tr("Only relays online now"), this);
    online->setToolTip(tr("Relays that said where they are in the last three hours. Others are listed "
                          "too: being listed says a peer exists, not that it is running."));
    connect(online, &QCheckBox::toggled, this, [proxy](bool on) { proxy->SetOnlineOnly(on); });
    filter_row->addWidget(filter, 1);
    filter_row->addWidget(online);
    outer->addLayout(filter_row);

    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->setTextElideMode(Qt::ElideMiddle);
    SizeColumns(m_table);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    outer->addWidget(m_table, 1);

    // A key or an address is copied by clicking it: those two are what anyone
    // wants out of this table, and both are too long to retype.
    connect(m_table, &QTableView::clicked, this, [this](const QModelIndex& index) {
        if (!index.isValid()) return;
        QString text, what;
        if (index.column() == RosterModel::Peer) {
            text = index.data(RosterModel::KeyRole).toString();
            what = tr("Key copied");
        } else if (index.column() == RosterModel::Where) {
            text = index.data(RosterModel::AddressRole).toString();
            what = tr("Address copied");
        }
        if (text.isEmpty()) return;
        QApplication::clipboard()->setText(text);
        QToolTip::showText(QCursor::pos(), what + "\n" + text, m_table);
    });

    connect(m_copy_key, &QPushButton::clicked, this, &DiscoveryPage::onCopyKey);
    connect(m_make_identity, &QPushButton::clicked, this, &DiscoveryPage::onMakeIdentity);
    connect(m_name_button, &QPushButton::clicked, this, [this] { Q_EMIT showNames(); });
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

QStringList DiscoveryPage::OpenWalletNames() const
{
    QStringList names;
#ifdef ENABLE_WALLET
    if (m_wallets) {
        for (WalletModel* model : m_wallets->getOpenWallets()) names << model->getWalletName();
    }
#endif
    return names;
}

void DiscoveryPage::onMakeIdentity()
{
    const QStringList wallets = OpenWalletNames();
    if (wallets.isEmpty()) return;
    QString wallet = wallets.front();
    bool ok = true;
    if (wallets.size() > 1) {
        wallet = QInputDialog::getItem(this, tr("Make an identity"), tr("Pay the fee from"), wallets, 0, false, &ok);
        if (!ok) return;
    }
    if (QMessageBox::question(this, tr("Make an identity"),
            tr("An identity is a second key that stands behind this node's key. If this node's key is ever lost "
               "or stolen, a new key can be put under the same identity, and the node keeps how long it has "
               "been listed instead of starting again.\n\n"
               "You will be shown a recovery key once. Write it down: it is the only way to stop someone who "
               "steals the identity from moving it. Then a small transaction publishes the identity, and your "
               "next listing renewal links this node's key to it."),
            QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Ok) != QMessageBox::Ok) {
        return;
    }
    m_delegation_wallet = wallet;
    m_rpc.Call(TAG_IDENTITY, "createidentity");
}

void DiscoveryPage::onPublishClicked()
{
    const bool renewing = m_own_expiry > m_tip;
    // Before the renewal window: only to make the listing say what the Server
    // page now says about relaying (UpdateListingSummary).
    const bool updating = renewing && m_own_expiry - m_tip > (int)roster::RENEW_WINDOW;
    PublishDialog dialog(m_rpc, m_wallets, m_tip, renewing, renewing ? m_own_note : QString(), this, updating);
    connect(&dialog, &PublishDialog::published, this, [this](const QString& txid, bool by_relay) {
        // Until it confirms the history still shows the old listing, and the
        // button would offer to pay again.
        m_pending_txid = txid;
        m_pending_prev_height = m_own_last_height;
        m_pending_gone_tip = 0;
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
    if (!m_pending_txid.isEmpty()) {
        // One payment at a time: a second click before the first confirms
        // would only pay a second fee.
        m_listing_state->setText(m_own_expiry > m_tip ? tr("ends in %1").arg(BpsUtil::HumanBlocks(m_own_expiry - m_tip))
                                                      : tr("not listed"));
        m_publish->setText(tr("Waiting for your listing to confirm"));
        m_publish->setToolTip(tr("Transaction %1 is waiting to confirm. Publishing again before it does "
                                 "would only pay a second fee.").arg(BpsUtil::ShortKey(m_pending_txid)));
        m_publish->setEnabled(false);
        Q_EMIT listingChanged(tr("waiting to confirm"), m_own_expiry > m_tip);
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
        // Others find relays by the listing, so one that no longer says what
        // the Server page does can be replaced at once, not only at renewal.
        const bool relay_now = ServerPage::RelaySwitchedOn();
        if (!can_renew && m_own_relay != relay_now) {
            m_publish->setText(tr("Update your listing\xe2\x80\xa6"));
            m_publish->setToolTip(relay_now
                ? tr("Relaying is switched on on the Server page, but your listing does not say this node "
                     "is a relay, so nobody finds it as one. Updating writes a fresh record that says it is.")
                : tr("Your listing says this node is a relay, but relaying is switched off on the Server "
                     "page. Updating writes a fresh record that says it is not."));
            m_publish->setEnabled(true);
        } else {
            m_publish->setText(can_renew ? tr("Renew your listing\xe2\x80\xa6")
                                         : tr("Renew in the last 3 days"));
            m_publish->setToolTip(can_renew ? QString()
                : tr("Your listing ends in %1. Renewing opens three days before it does.").arg(left));
            m_publish->setEnabled(can_renew);
        }
        Q_EMIT listingChanged(tr("listed, ends in %1").arg(left), true);
    }
}

void DiscoveryPage::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_INFO) {
        const UniValue& enabled = find_value(value, "enabled");
        m_index_enabled = enabled.isBool() && enabled.get_bool();

        const UniValue& identity = find_value(value, "identity_key");
        m_identity_key = identity.isStr() ? QString::fromStdString(identity.get_str()) : QString();
        if (m_identity_key.isEmpty()) {
            m_identity->setText(tr("none"));
            m_identity->setToolTip(QString());
        } else {
            m_identity->setText(BpsUtil::ShortKey(m_identity_key));
            m_identity->setToolTip(m_identity_key);
        }
        m_make_identity->setVisible(m_identity_key.isEmpty());
        m_make_identity->setEnabled(m_identity_key.isEmpty() && !OpenWalletNames().isEmpty());

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
        } else if (find_value(value, "stale").isTrue()) {
            // Still used to reach peers; not trusted, because revocations made
            // since may be missing from it (design note §5, §9).
            const UniValue& age = find_value(value, "roster_age_seconds");
            const int days = age.isNum() ? (int)(age.get_int64() / 86400) : 30;
            m_index_state->setText(tr("%1 days old").arg(days));
            m_index_state->setToolTip(tr("The newest block this node has is %1 days old, so peers revoked since then "
                                         "may still be listed here. The roster is still used to reach peers, but the "
                                         "overlay stops preferring long-listed relays until the chain catches up.")
                                          .arg(days));
        } else {
            m_index_state->setText(tr("up to date"));
            m_index_state->setToolTip(QString());
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
        // A listing just paid for, still to confirm (onPublishClicked).
        if (!m_pending_txid.isEmpty()) {
            UniValue params(UniValue::VARR);
            params.push_back(m_pending_txid.toStdString());
            m_rpc.Call(TAG_PENDING, "getmempoolentry", params);
        }
        UniValue roster_params(UniValue::VARR);
        roster_params.push_back(ROSTER_PAGE);
        m_rpc.Call(TAG_ROSTER, "getroster", roster_params);

        // The names this node's key holds, which all resolve to it.
        m_rpc.Call(TAG_NAMES, "listnames");
        return;
    }

    if (tag == TAG_IDENTITY) {
        const QString recovery = QString::fromStdString(find_value(value, "recovery_key_wif").getValStr());
        const QString delegation = QString::fromStdString(find_value(value, "delegation").getValStr());
        QDialog dialog(this);
        dialog.setWindowTitle(tr("Your recovery key"));
        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        QLabel* text = new QLabel(tr("Write this down and keep it somewhere safe, away from this computer. It is "
                                     "shown only now and is not kept anywhere. Nobody can use it to spend coins; "
                                     "it can only stop a move of your identity you did not make."), &dialog);
        text->setWordWrap(true);
        layout->addWidget(text);
        QLineEdit* field = new QLineEdit(recovery, &dialog);
        field->setReadOnly(true);
        field->setFont(BpsUtil::FixedPitchFont());
        layout->addWidget(field);
        QDialogButtonBox* buttons = new QDialogButtonBox(&dialog);
        QPushButton* copy = buttons->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
        buttons->addButton(tr("I have written it down"), QDialogButtonBox::AcceptRole);
        connect(copy, &QPushButton::clicked, &dialog, [recovery] { QApplication::clipboard()->setText(recovery); });
        connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        layout->addWidget(buttons);
        dialog.resize(560, dialog.sizeHint().height());
        dialog.exec();
        UniValue params(UniValue::VARR);
        params.push_back(delegation.toStdString());
        m_rpc.Call(TAG_DELEGATION, "publishrecord", params,
                   "/wallet/" + QString::fromUtf8(QUrl::toPercentEncoding(m_delegation_wallet)));
        Refresh();
        return;
    }

    if (tag == TAG_DELEGATION) {
        m_error->setVisible(true);
        m_error->setText(tr("Your identity is published in transaction %1. Your next listing renewal links this "
                            "node's key to it.").arg(BpsUtil::ShortKey(QString::fromStdString(find_value(value, "txid").getValStr()))));
        return;
    }

    if (tag == TAG_HISTORY) {
        // Oldest first, so the last announcement is the one in force. The
        // history also holds delegations naming this key, which are not listings.
        m_own_expiry = 0;
        m_own_note.clear();
        m_own_relay = false;
        int last_height = 0;
        if (value.isArray()) {
            for (size_t i = 0; i < value.size(); ++i) {
                if (find_value(value[i], "type").getValStr() != "announce") continue;
                const UniValue& height = find_value(value[i], "height");
                if (height.isNum()) last_height = height.get_int();
                const UniValue& expiry = find_value(value[i], "expiry_height");
                if (expiry.isNum()) m_own_expiry = expiry.get_int();
                // The listing in force, so a renewal offers its note again.
                m_own_note = QString::fromStdString(find_value(value[i], "note").getValStr());
                m_own_relay = find_value(value[i], "relay").isTrue();
            }
        }
        m_own_last_height = last_height;
        // The listing paid for has reached the chain: nothing waits any more.
        if (!m_pending_txid.isEmpty() && last_height > m_pending_prev_height) {
            m_pending_txid.clear();
            m_pending_gone_tip = 0;
        }
        UpdateListingSummary();
        return;
    }

    if (tag == TAG_PENDING) {
        // Still in the mempool, so still waiting.
        m_pending_gone_tip = 0;
        return;
    }

    if (tag == TAG_ROSTER) {
        m_model->SetRoster(value, m_tip);
        SizeColumns(m_table);
        return;
    }

    if (tag == TAG_NAMES) {
        // Live names this key holds, newest-sounding first is not meaningful, so
        // just show them in the order the node returns, with the rest in a tooltip.
        QStringList live;
        if (value.isArray()) {
            for (size_t i = 0; i < value.size(); ++i) {
                if (find_value(value[i], "status").getValStr() != "live") continue;
                const QString n = QString::fromStdString(find_value(value[i], "name").getValStr());
                if (!n.isEmpty()) live << n;
            }
        }
        if (live.isEmpty()) {
            m_name->setText(tr("none"));
            m_name->setToolTip(QString());
            m_name_button->setText(tr("Register a name\xe2\x80\xa6"));
        } else {
            m_name->setText(live.join(QStringLiteral(", ")));
            m_name->setToolTip(tr("These names all resolve to this node's key. Others can reach you by any of them."));
            m_name_button->setText(tr("Manage names\xe2\x80\xa6"));
        }
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
    if (tag == TAG_PENDING) {
        // Not in the mempool: confirmed, which the history shows shortly, or
        // dropped. Held a few blocks so the first is not taken for the second.
        if (m_pending_gone_tip == 0) {
            m_pending_gone_tip = std::max(1, m_tip);
        } else if (m_tip - m_pending_gone_tip >= PENDING_GONE_BLOCKS) {
            m_pending_txid.clear();
            m_pending_gone_tip = 0;
        }
        UpdateListingSummary();
        return;
    }
    if (tag == TAG_NAMES) {
        // Names run off their own index (-nameindex); without it there is just
        // nothing to show here, not an error for the whole page.
        m_name->setText(tr("names off"));
        m_name->setToolTip(tr("Names need the name index. Turn it on in Settings to register and show one."));
        m_name_button->setText(tr("Register a name\xe2\x80\xa6"));
        return;
    }
    if (tag != TAG_INFO && tag != TAG_ROSTER) return;

    m_error->setVisible(true);
    m_error->setText(message);
}
