// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/serverpage.h>

#include <qt/bps/bpsrpc.h>

#include <qt/clientmodel.h>
#ifdef ENABLE_WALLET
#include <interfaces/wallet.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#endif

#include <mail/mailbox.h>
#include <policy/feerate.h>
#include <roster/listing.h>
#include <roster/payout.h>
#include <univalue.h>
#include <util/system.h>

#include <QCheckBox>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QScrollArea>
#include <QSettings>
#include <QSpinBox>
#include <QStringList>
#include <QTimer>
#include <QVBoxLayout>

namespace {
//! QSettings keys, prefixed like the Settings page's own.
const char* KEY_ACCEPTLISTINGS = "bps/acceptlistings";
const char* KEY_MAXLISTEDUSERS = "bps/maxlistedusers";
const char* KEY_LISTINGWALLET = "bps/listingwallet";
const char* KEY_RELAYSHARE = "bps/relayshare";
const char* KEY_MAILBOX = "bps/mailbox";
const char* KEY_MAILBOX_SIZE = "bps/mailboxmaxsize";

const char* TAG_PAYOUT = "server:payout";
const char* TAG_MAIL = "server:mail";

//! The roster moves at block pace; so do the figures here.
const int REFRESH_MS = 20000;

enum class Status { RUNNING, OFF, ATTENTION, PLANNED };

void SetBadge(QLabel* badge, Status status, const QString& text)
{
    const char* style = "";
    switch (status) {
    case Status::RUNNING: style = "color: #1f6f3a; background: #dcf1e2;"; break;
    case Status::OFF: style = "color: #4a5560; background: #e4e8ec;"; break;
    case Status::ATTENTION: style = "color: #8a3b12; background: #f6e0d3;"; break;
    case Status::PLANNED: style = "color: #6b5a1e; background: #f3ecd3;"; break;
    }
    badge->setText(text);
    badge->setStyleSheet(QString(style) + " border-radius: 9px; padding: 2px 9px;");
}

//! A product: a titled card with a badge saying whether it runs.
QFrame* MakeCard(const QString& title, Status status, const QString& description, QWidget* parent,
                 QVBoxLayout** body_out, QLabel** badge_out = nullptr)
{
    QFrame* card = new QFrame(parent);
    card->setObjectName("serverCard");
    card->setStyleSheet("#serverCard { border: 1px solid palette(mid); border-radius: 8px;"
                        "              background: palette(base); }");
    QVBoxLayout* layout = new QVBoxLayout(card);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(8);

    QHBoxLayout* head = new QHBoxLayout();
    QLabel* name = new QLabel(title, card);
    QFont name_font = name->font();
    name_font.setPointSizeF(name_font.pointSizeF() * 1.25);
    name_font.setBold(true);
    name->setFont(name_font);
    head->addWidget(name);
    head->addStretch(1);

    QLabel* badge = new QLabel(card);
    SetBadge(badge, status, status == Status::PLANNED ? QObject::tr("not built yet") : QString());
    head->addWidget(badge);
    if (badge_out) *badge_out = badge;
    layout->addLayout(head);

    QLabel* text = new QLabel(description, card);
    text->setWordWrap(true);
    layout->addWidget(text);

    if (body_out) *body_out = layout;
    else layout->addStretch(1);
    return card;
}
} // namespace

void ServerPage::ApplyStoredSettings()
{
    QSettings settings;
    // Paying for other peers' listings spends coins, so nothing is set until
    // the operator chooses here; the node's own defaults apply until then.
    if (settings.contains(KEY_ACCEPTLISTINGS)) {
        gArgs.SoftSetBoolArg("-acceptlistings", settings.value(KEY_ACCEPTLISTINGS).toBool());
    }
    if (settings.contains(KEY_MAXLISTEDUSERS)) {
        gArgs.SoftSetArg("-maxlistedusers", settings.value(KEY_MAXLISTEDUSERS).toString().toStdString());
    }
    const QString listing_wallet = settings.value(KEY_LISTINGWALLET).toString();
    if (!listing_wallet.isEmpty()) gArgs.SoftSetArg("-listingwallet", listing_wallet.toStdString());
    if (settings.contains(KEY_RELAYSHARE)) {
        gArgs.SoftSetArg("-relayshare", settings.value(KEY_RELAYSHARE).toString().toStdString());
    }
    if (settings.contains(KEY_MAILBOX)) {
        gArgs.SoftSetBoolArg("-mailbox", settings.value(KEY_MAILBOX).toBool());
    }
    if (settings.contains(KEY_MAILBOX_SIZE)) {
        gArgs.SoftSetArg("-mailboxmaxsize", settings.value(KEY_MAILBOX_SIZE).toString().toStdString());
    }
}

ServerPage::ServerPage(BpsRpc& rpc, QWidget* parent) : QWidget(parent), m_rpc(rpc)
{
    QVBoxLayout* page = new QVBoxLayout(this);
    page->setContentsMargins(0, 0, 0, 0);
    QScrollArea* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    page->addWidget(scroll);

    QWidget* content = new QWidget(scroll);
    scroll->setWidget(content);
    QVBoxLayout* outer = new QVBoxLayout(content);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(10);

    QLabel* title = new QLabel(tr("Server"), content);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);
    outer->addWidget(title);

    QLabel* subtitle = new QLabel(
        tr("What this node offers other people. Relaying and holding mail run today; names and "
           "hosting are on the way, and each is found the same way peers are \xe2\x80\x94 through "
           "the roster."),
        content);
    subtitle->setWordWrap(true);
    subtitle->setEnabled(false);
    outer->addWidget(subtitle);
    outer->addSpacing(6);

    outer->addWidget(MakeRelayCard());
    outer->addWidget(MakeMailboxCard());

    QGridLayout* planned = new QGridLayout();
    planned->setHorizontalSpacing(12);
    planned->setVerticalSpacing(12);
    planned->addWidget(MakeCard(tr("Names"), Status::PLANNED,
        tr("A name that resolves to your key, so people pay you by name instead of a "
           "42-character address, with a fresh address for every payment. Root names are "
           "priced and renewed; names under a root are free; a peer without a name stays a "
           "full peer. Designed (design note 001, section 11); who settles a disputed name is "
           "still open."),
        content, nullptr), 0, 0);
    planned->addWidget(MakeCard(tr("Hosting"), Status::PLANNED,
        tr("A site or service served from this node, found by its key or name and reached over "
           "the overlay, so the host never publishes where it runs. The meeting part exists: a "
           "service registers at rendezvous points both sides work out from the roster. Serving "
           "pages and apps through it is not built yet."),
        content, nullptr), 0, 1);
    for (int c = 0; c < 2; ++c) planned->setColumnStretch(c, 1);
    outer->addLayout(planned);
    outer->addStretch(1);

    connect(&m_rpc, &BpsRpc::result, this, &ServerPage::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &ServerPage::onRpcFailed);
    m_timer = new QTimer(this);
    m_timer->setInterval(REFRESH_MS);
    connect(m_timer, &QTimer::timeout, this, &ServerPage::Refresh);

    Load();
}

QWidget* ServerPage::MakeRelayCard()
{
    QVBoxLayout* body = nullptr;
    QFrame* card = MakeCard(tr("Relay"), Status::OFF,
        tr("Carry other peers' overlay traffic, pay for the monthly listings of the peers that use "
           "this node, and share part of each block it stakes with them. A relay puts the listings "
           "it pays for into blocks it stakes itself, which is how they confirm while most nodes "
           "still refuse to pass records on \xe2\x80\x94 so a relay has to be staking."),
        this, &body, &m_relay_badge);

    QFormLayout* status = new QFormLayout();
    m_staking = new QLabel(tr("\xe2\x80\x94"), card);
    m_users = new QLabel(tr("\xe2\x80\x94"), card);
    m_payout = new QLabel(tr("\xe2\x80\x94"), card);
    m_payout->setWordWrap(true);
    status->addRow(tr("Staking"), m_staking);
    status->addRow(tr("Peers listed here"), m_users);
    status->addRow(tr("Next block it stakes"), m_payout);
    body->addLayout(status);

    QFrame* rule = new QFrame(card);
    rule->setFrameShape(QFrame::HLine);
    rule->setFrameShadow(QFrame::Sunken);
    body->addWidget(rule);

    m_acceptlistings = new QCheckBox(tr("Pay to list peers that ask through the overlay"), card);
    m_acceptlistings->setToolTip(tr("A peer with no coins can ask this node to publish its monthly "
                                    "listing. This node pays the fee, stakes it into a block, and adds "
                                    "the peer to those it shares rewards with. Off by default, because "
                                    "it spends this node's coins."));
    body->addWidget(m_acceptlistings);

    QFormLayout* form = new QFormLayout();
    m_maxlistedusers = new QSpinBox(card);
    m_maxlistedusers->setRange(1, 100000);
    m_maxlistedusers->setToolTip(tr("Peers past this number are turned away. Peers already listed "
                                    "here can still renew."));
    form->addRow(tr("Most peers to keep listed"), m_maxlistedusers);

    m_listingwallet = new QLineEdit(card);
    m_listingwallet->setPlaceholderText(tr("the only wallet open"));
    m_listingwallet->setToolTip(tr("Which wallet pays the fees. With several open and none named "
                                   "here, requests are declined rather than paid from a guess. "
                                   "Staking can happen in any wallet on this node."));
    form->addRow(tr("Pay fees from wallet"), m_listingwallet);

    m_relayshare = new QSpinBox(card);
    m_relayshare->setRange(0, 100);
    m_relayshare->setSuffix(tr(" %"));
    m_relayshare->setToolTip(tr("Part of every block this node stakes from its own coins, split "
                                "equally among the peers it lists. 0 shares nothing."));
    form->addRow(tr("Share of each staked block"), m_relayshare);
    body->addLayout(form);

    m_restart_note = new QLabel(card);
    m_restart_note->setWordWrap(true);
    m_restart_note->setVisible(false);
    body->addWidget(m_restart_note);

    connect(m_acceptlistings, &QCheckBox::toggled, this, &ServerPage::onChanged);
    connect(m_maxlistedusers, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &ServerPage::onChanged);
    connect(m_listingwallet, &QLineEdit::editingFinished, this, &ServerPage::onChanged);
    connect(m_relayshare, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &ServerPage::onChanged);
    return card;
}

QWidget* ServerPage::MakeMailboxCard()
{
    QVBoxLayout* body = nullptr;
    QFrame* card = MakeCard(tr("Mailbox"), Status::OFF,
        tr("Hold sealed mail for the people the roster makes this node a mailbox for, until they "
           "collect it. Which relays hold whose mail is worked out from the roster, so nobody assigns "
           "it. Senders and owners reach this node through three relays, so it never learns where "
           "they are; letters are sealed, so it cannot read them or tell who wrote them. Letters are "
           "dropped after two weeks, and only listed people are served."),
        this, &body, &m_mailbox_badge);

    QFormLayout* status = new QFormLayout();
    m_mailbox_holding = new QLabel(tr("\xe2\x80\x94"), card);
    m_mailbox_keys = new QLabel(tr("\xe2\x80\x94"), card);
    status->addRow(tr("Holding"), m_mailbox_holding);
    status->addRow(tr("Mail keys held for senders"), m_mailbox_keys);
    body->addLayout(status);

    QFrame* rule = new QFrame(card);
    rule->setFrameShape(QFrame::HLine);
    rule->setFrameShadow(QFrame::Sunken);
    body->addWidget(rule);

    m_mailbox = new QCheckBox(tr("Hold mail for the people the roster assigns to this node"), card);
    m_mailbox->setToolTip(tr("On by default wherever the overlay runs: a relay that refuses leaves the "
                             "people it was chosen for with one mailbox fewer."));
    body->addWidget(m_mailbox);

    QFormLayout* form = new QFormLayout();
    m_mailbox_size = new QSpinBox(card);
    m_mailbox_size->setRange(1, 1 << 20);
    m_mailbox_size->setSuffix(tr(" MiB"));
    m_mailbox_size->setToolTip(tr("When this is full, new letters are refused until old ones are collected "
                                  "or dropped. No one person can use more than 8 MiB of it."));
    form->addRow(tr("Disk it may use"), m_mailbox_size);
    body->addLayout(form);

    m_mailbox_note = new QLabel(card);
    m_mailbox_note->setWordWrap(true);
    m_mailbox_note->setVisible(false);
    body->addWidget(m_mailbox_note);

    connect(m_mailbox, &QCheckBox::toggled, this, &ServerPage::onChanged);
    connect(m_mailbox_size, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &ServerPage::onChanged);
    return card;
}

void ServerPage::Load()
{
    m_loading = true;
    // What the node is running with, so a value from the command line or the
    // config file shows here rather than being contradicted by the page.
    m_acceptlistings->setChecked(gArgs.GetBoolArg("-acceptlistings", roster::DEFAULT_ACCEPT_LISTINGS));
    m_maxlistedusers->setValue((int)gArgs.GetArg("-maxlistedusers", roster::DEFAULT_MAX_LISTED_USERS));
    m_listingwallet->setText(QString::fromStdString(gArgs.GetArg("-listingwallet", "")));
    m_relayshare->setValue((int)gArgs.GetArg("-relayshare", roster::DEFAULT_RELAY_SHARE));
    m_mailbox->setChecked(gArgs.GetBoolArg("-mailbox", mail::DEFAULT_MAILBOX));
    m_mailbox_size->setValue((int)gArgs.GetArg("-mailboxmaxsize", (int64_t)mail::DEFAULT_MAILBOX_MAX_MB));
    m_loading = false;
}

void ServerPage::onChanged()
{
    if (m_loading) return;
    QSettings settings;
    settings.setValue(KEY_ACCEPTLISTINGS, m_acceptlistings->isChecked());
    settings.setValue(KEY_MAXLISTEDUSERS, m_maxlistedusers->value());
    settings.setValue(KEY_LISTINGWALLET, m_listingwallet->text().trimmed());
    settings.setValue(KEY_RELAYSHARE, m_relayshare->value());
    settings.setValue(KEY_MAILBOX, m_mailbox->isChecked());
    settings.setValue(KEY_MAILBOX_SIZE, m_mailbox_size->value());
    const QString saved = tr("Saved. These are read when the node starts, so restart the client "
                             "for the change to take effect.");
    for (QLabel* note : {m_restart_note, m_mailbox_note}) {
        note->setVisible(true);
        note->setText(saved);
    }
}

void ServerPage::setWalletController(WalletController* controller)
{
    m_wallets = controller;
    Refresh();
}

void ServerPage::setClientModel(ClientModel* model)
{
    m_client_model = model;
    if (!model) {
        m_timer->stop();
        return;
    }
    m_timer->start();
    Refresh();
}

void ServerPage::Refresh()
{
    UpdateStaking();
    if (m_client_model) {
        m_rpc.Call(TAG_PAYOUT, "getrelaypayout");
        m_rpc.Call(TAG_MAIL, "getmailinfo");
    }
}

void ServerPage::UpdateStaking()
{
#ifdef ENABLE_WALLET
    if (!m_wallets) {
        m_staking->setText(tr("no wallet open"));
        return;
    }
    // The same reading the footer and the wallet client make.
    QStringList staking;
    for (WalletModel* model : m_wallets->getOpenWallets()) {
        if (model->wallet().getEnabledStaking() && model->wallet().getLastCoinStakeSearchInterval() &&
            model->getStakeWeight()) {
            staking << model->getDisplayName();
        }
    }
    m_staking->setText(staking.isEmpty()
        ? tr("no \xe2\x80\x94 a relay that is not staking turns listing requests down")
        : tr("yes, in %1").arg(staking.join(", ")));

    // What the badge says is what a peer asking this node would find.
    const bool accepting = gArgs.GetBoolArg("-acceptlistings", roster::DEFAULT_ACCEPT_LISTINGS);
    if (!accepting) {
        SetBadge(m_relay_badge, Status::OFF, tr("not paying for listings"));
    } else if (staking.isEmpty()) {
        SetBadge(m_relay_badge, Status::ATTENTION, tr("paying, but not staking"));
    } else {
        SetBadge(m_relay_badge, Status::RUNNING, tr("running"));
    }
#else
    m_staking->setText(tr("this build has no wallet"));
    SetBadge(m_relay_badge, Status::OFF, tr("needs a wallet"));
#endif
}

void ServerPage::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_MAIL) {
        const UniValue& holding = find_value(value, "holding");
        if (!find_value(holding, "enabled").isTrue()) {
            SetBadge(m_mailbox_badge, Status::OFF,
                     gArgs.GetBoolArg("-overlay", true) ? tr("off") : tr("needs the overlay"));
            m_mailbox_holding->setText(tr("nothing \xe2\x80\x94 not holding mail"));
            m_mailbox_keys->setText(tr("\xe2\x80\x94"));
            return;
        }
        SetBadge(m_mailbox_badge, Status::RUNNING, tr("running"));
        const int64_t letters = find_value(holding, "letters").get_int64();
        const int64_t people = find_value(holding, "people").get_int64();
        const int64_t bytes = find_value(holding, "bytes").get_int64();
        const int64_t max_mib = find_value(holding, "max_bytes").get_int64() >> 20;
        const QString what = letters == 0 ? tr("no letters")
                             : letters == 1 ? tr("1 letter") : tr("%1 letters").arg(letters);
        const QString whom = people == 1 ? tr("1 person") : tr("%1 people").arg(people);
        const QString used = bytes < (1 << 20) ? tr("%1 KiB").arg((bytes + 1023) / 1024)
                                               : tr("%1 MiB").arg(bytes / 1048576.0, 0, 'f', 1);
        m_mailbox_holding->setText(letters == 0 ? tr("nothing at the moment, room for %1 MiB").arg(max_mib)
                                                : tr("%1 for %2, %3 of %4 MiB").arg(what, whom, used).arg(max_mib));
        m_mailbox_keys->setText(QString::number(find_value(holding, "keys").get_int64()));
        return;
    }
    if (tag != TAG_PAYOUT) return;
    const UniValue& users = find_value(value, "users");
    m_users->setText(users.isNum() ? QString::number(users.get_int()) : tr("\xe2\x80\x94"));

    const UniValue& share = find_value(value, "share_percent");
    const UniValue& total = find_value(value, "total");
    const UniValue& each = find_value(value, "each");
    const UniValue& note = find_value(value, "note");
    if (note.isStr()) {
        m_payout->setText(QString::fromStdString(note.get_str()));
    } else if (share.isNum() && total.isNum() && each.isNum()) {
        m_payout->setText(tr("shares %1%: %2 %4 in all, %3 %4 to each peer")
                              .arg(share.get_int())
                              .arg(QString::fromStdString(total.getValStr()))
                              .arg(QString::fromStdString(each.getValStr()))
                              .arg(QString::fromStdString(CURRENCY_UNIT)));
    }
}

void ServerPage::onRpcFailed(const QString& tag, const QString& message)
{
    if (tag == TAG_MAIL) {
        m_mailbox_holding->setText(message);
        return;
    }
    if (tag != TAG_PAYOUT) return;
    m_payout->setText(message);
}
