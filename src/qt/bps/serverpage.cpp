// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/serverpage.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>
#include <qt/bps/publishdialog.h>

#include <qt/clientmodel.h>
#ifdef ENABLE_WALLET
#include <interfaces/wallet.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#endif

#include <mail/mailbox.h>
#include <net.h>
#include <overlay/gateway.h>
#include <overlay/localproxy.h>
#include <overlay/socket.h>
#include <overlay/sysif.h>
#include <overlay/sysroute.h>
#include <policy/feerate.h>
#include <roster/listing.h>
#include <roster/payout.h>
#include <roster/relayaddr.h>
#include <univalue.h>
#include <util/system.h>

#include <QCheckBox>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QSpinBox>
#include <QDateTime>
#include <QStringList>
#include <QTimer>
#include <QVBoxLayout>

#ifdef WIN32
#include <QCoreApplication>
#include <QDir>
#include <QFile>

#include <cstring>
#include <vector>

#include <windows.h>
#include <sddl.h>
#include <shellapi.h>
#endif

namespace {
//! QSettings keys, prefixed like the Settings page's own.
const char* KEY_RELAY = "bps/relay";
const char* KEY_ACCEPTLISTINGS = "bps/acceptlistings";
const char* KEY_MAXLISTEDUSERS = "bps/maxlistedusers";
const char* KEY_LISTINGWALLET = "bps/listingwallet";
const char* KEY_RELAYSHARE = "bps/relayshare";
const char* KEY_MAILBOX = "bps/mailbox";
const char* KEY_MAILBOX_SIZE = "bps/mailboxmaxsize";
const char* KEY_GATEWAY = "bps/gateway";
const char* KEY_GATEWAY_BUDGET = "bps/gatewaybandwidth";
const char* KEY_GATEWAY_PROXY = "bps/gatewayproxy";
const char* KEY_GATEWAY_NOTICE = "bps/gatewaynotice";
const char* KEY_GATEWAY_INTERFACE = "bps/gatewayinterface";

/** The system-wide interface's name: a TUN device on Linux; on Windows the service's adapter, whatever this says. */
const char* InterfaceName()
{
#ifdef WIN32
    return "bps";
#else
    return "bps0";
#endif
}

/** Whether this system can have the system-wide interface at all yet. */
bool InterfaceAvailable()
{
#if defined(__linux__) || defined(WIN32)
    return true;
#else
    return false;
#endif
}

const char* TAG_PAYOUT = "server:payout";
const char* TAG_MAIL = "server:mail";
const char* TAG_GATEWAY = "server:gateway";
const char* TAG_ROSTERINFO = "server:rosterinfo";

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

bool ServerPage::RelaySwitchedOn()
{
    QSettings settings;
    if (settings.contains(KEY_RELAY)) return settings.value(KEY_RELAY).toBool();
    return gArgs.GetBoolArg("-relay", roster::DEFAULT_RELAY);
}

bool ServerPage::GatewaySwitchedOn()
{
    QSettings settings;
    if (settings.contains(KEY_GATEWAY)) return settings.value(KEY_GATEWAY).toBool();
    return gArgs.GetBoolArg("-gateway", overlay::DEFAULT_GATEWAY);
}

void ServerPage::ApplyStoredSettings()
{
    QSettings settings;
    // Relaying makes this computer's address public, so it is off until the
    // owner switches it on here.
    if (settings.contains(KEY_RELAY)) gArgs.SoftSetBoolArg("-relay", settings.value(KEY_RELAY).toBool());
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
    // The gateway is on unless switched off, in the node as here; what is
    // stored is only ever the owner's own choice.
    if (settings.contains(KEY_GATEWAY)) gArgs.SoftSetBoolArg("-gateway", settings.value(KEY_GATEWAY).toBool());
    if (settings.contains(KEY_GATEWAY_BUDGET)) {
        gArgs.SoftSetArg("-gatewaybandwidth", settings.value(KEY_GATEWAY_BUDGET).toString().toStdString());
    }
    // The local proxy is part of this client: on unless switched off here.
    if (!settings.contains(KEY_GATEWAY_PROXY)) settings.setValue(KEY_GATEWAY_PROXY, true);
    gArgs.SoftSetBoolArg("-gatewayproxy", settings.value(KEY_GATEWAY_PROXY).toBool());
    // All of the computer's traffic through the network: off until chosen, and
    // only once this program may route the computer - the node would refuse
    // to start otherwise. The Server page says what is missing.
    std::string how;
    if (settings.value(KEY_GATEWAY_INTERFACE, false).toBool() && InterfaceAvailable() && overlay::HaveNetAdmin(how)) {
        gArgs.SoftSetArg("-gatewayinterface", InterfaceName());
        gArgs.SoftSetBoolArg("-gatewayroutes", true);
    }
}

void ServerPage::AskAboutGatewayOnce()
{
    QSettings settings;
    if (settings.value(KEY_GATEWAY_NOTICE).toBool()) return;
    if (gArgs.IsArgSet("-gateway")) {
        // Chosen already, where the node reads its options.
        settings.setValue(KEY_GATEWAY_NOTICE, true);
        return;
    }
    QMessageBox box;
    box.setIcon(QMessageBox::Information);
    box.setWindowTitle(tr("Sharing your internet connection"));
    box.setText(tr("BPS Relay shares this computer's internet connection with the network, as every "
                   "member with the internet does, unless you switch it off. In return, programs on "
                   "this computer can use the network's internet."));
    box.setInformativeText(
        tr("People reach the internet through this computer by way of relays, so it never learns who "
           "they are, and nobody in the network learns where it is.\n\n"
           "What it means for you: the websites they visit see this computer's internet address, as "
           "they would see yours. Only encrypted connections leave \xe2\x80\x94 the web, and encrypted "
           "mail and messaging \xe2\x80\x94 never mail between servers, and never into your own home "
           "network. It shares at most 1 GiB a day.\n\n"
           "If the law where you live, or your internet provider's terms, forbid sharing your "
           "connection, switch it off. In the EU, passing traffic on for others is protected as a "
           "\"mere conduit\", but complaints about it still reach you through your provider.\n\n"
           "You can change this at any time on the Server page."));
    QPushButton* keep = box.addButton(tr("Keep sharing"), QMessageBox::AcceptRole);
    QPushButton* off = box.addButton(tr("Switch it off"), QMessageBox::RejectRole);
    box.setDefaultButton(keep);
    box.exec();
    settings.setValue(KEY_GATEWAY, box.clickedButton() != off);
    settings.setValue(KEY_GATEWAY_NOTICE, true);
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
        tr("What this node offers other people. Relaying, holding mail and sharing the internet run "
           "today; hosting is on the way, and like everything here it is found the same way peers are "
           "\xe2\x80\x94 through the roster. Names have a page of their own."),
        content);
    subtitle->setWordWrap(true);
    subtitle->setEnabled(false);
    outer->addWidget(subtitle);
    outer->addSpacing(6);

    outer->addWidget(MakeRelayCard());
    outer->addWidget(MakeMailboxCard());
    outer->addWidget(MakeGatewayCard());

    QGridLayout* planned = new QGridLayout();
    planned->setHorizontalSpacing(12);
    planned->setVerticalSpacing(12);
    planned->addWidget(MakeCard(tr("Hosting"), Status::PLANNED,
        tr("A site or service served from this node, found by its key or name and reached over "
           "the overlay, so the host never publishes where it runs. The meeting part exists: a "
           "service registers at rendezvous points both sides work out from the roster. Serving "
           "pages and apps through it is not built yet."),
        content, nullptr), 0, 0);
    planned->setColumnStretch(0, 1);
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
    m_announced = new QLabel(tr("\xe2\x80\x94"), card);
    m_announced->setWordWrap(true);
    m_announced->setTextInteractionFlags(Qt::TextSelectableByMouse);
    status->addRow(tr("Staking"), m_staking);
    status->addRow(tr("Peers listed here"), m_users);
    status->addRow(tr("Next block it stakes"), m_payout);
    status->addRow(tr("Address announced"), m_announced);
    body->addLayout(status);

    QFrame* rule = new QFrame(card);
    rule->setFrameShape(QFrame::HLine);
    rule->setFrameShadow(QFrame::Sunken);
    body->addWidget(rule);

    // A setting of the node, not of its listing: the listing takes it over
    // when it is next published (roster/relayaddr.h).
    m_relay = new QCheckBox(tr("Carry others' paths as a relay"), card);
    body->addWidget(m_relay);
    QLabel* relay_note = new QLabel(
        tr("While your node runs it tells the network this computer's current address, signed with "
           "its key, so that paths can reach it, and again whenever it changes. It is never written to "
           "the chain, and the network forgets it within three hours of your node stopping. Others "
           "must be able to reach this computer at port %1 (TCP) and %2 (UDP).")
            .arg(GetListenPort()).arg(overlay::OverlayPortFor(GetListenPort())),
        card);
    relay_note->setWordWrap(true);
    relay_note->setContentsMargins(24, 0, 0, 0);
    QFont relay_font = relay_note->font();
    relay_font.setPointSizeF(relay_font.pointSizeF() * 0.9);
    relay_note->setFont(relay_font);
    body->addWidget(relay_note);

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

    connect(m_relay, &QCheckBox::toggled, this, &ServerPage::onChanged);
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

QWidget* ServerPage::MakeGatewayCard()
{
    QVBoxLayout* body = nullptr;
    QFrame* card = MakeCard(tr("Gateway"), Status::OFF,
        tr("Share this computer's internet connection with the network, as every member with the "
           "internet does unless they switch it off, and use the network's internet in return. People "
           "reach the internet through it by way of relays, so it never learns who they are, and nobody "
           "in the network learns where it is. The websites they visit see this computer's address, as "
           "they would see yours. Only encrypted connections leave \xe2\x80\x94 the web, and encrypted "
           "mail and messaging \xe2\x80\x94 never mail between servers, and never into your own network."),
        this, &body, &m_gateway_badge);

    QFormLayout* status = new QFormLayout();
    m_gateway_state = new QLabel(tr("\xe2\x80\x94"), card);
    m_gateway_state->setWordWrap(true);
    m_gateway_key = new QLabel(tr("\xe2\x80\x94"), card);
    m_gateway_key->setWordWrap(true);
    m_gateway_today = new QLabel(tr("\xe2\x80\x94"), card);
    m_gateway_now = new QLabel(tr("\xe2\x80\x94"), card);
    status->addRow(tr("Sharing"), m_gateway_state);
    status->addRow(tr("Listed as"), m_gateway_key);
    status->addRow(tr("Today"), m_gateway_today);
    status->addRow(tr("Open now"), m_gateway_now);
    body->addLayout(status);

    m_gateway_list = new QPushButton(tr("List as a gateway\xe2\x80\xa6"), card);
    m_gateway_list->setVisible(false);
    QHBoxLayout* list_row = new QHBoxLayout();
    list_row->addWidget(m_gateway_list);
    list_row->addStretch(1);
    body->addLayout(list_row);

    QFrame* rule = new QFrame(card);
    rule->setFrameShape(QFrame::HLine);
    rule->setFrameShadow(QFrame::Sunken);
    body->addWidget(rule);

    m_gateway = new QCheckBox(tr("Share this computer's internet connection as a gateway"), card);
    m_gateway->setToolTip(tr("Switch it off if the law where you live, or your internet provider's terms, "
                             "forbid sharing your connection. With it off, this node still relays, holds "
                             "mail and stays on the chain, and uses its own connection directly."));
    body->addWidget(m_gateway);

    QFormLayout* form = new QFormLayout();
    m_gateway_budget = new QSpinBox(card);
    m_gateway_budget->setRange(0, 1 << 20);
    m_gateway_budget->setSuffix(tr(" MiB"));
    m_gateway_budget->setSpecialValueText(tr("no limit"));
    m_gateway_budget->setToolTip(tr("Both ways together. Once it is used up the gateway takes no new "
                                    "connections until the day turns (UTC)."));
    form->addRow(tr("Most it shares in a day"), m_gateway_budget);
    body->addLayout(form);

    m_proxy = new QCheckBox(tr("Let programs on this computer use the network's internet, through a local proxy"), card);
    m_proxy->setToolTip(tr("A SOCKS5 proxy on this computer only. Each connection leaves through another "
                           "member's gateway, and names are looked up there, never here. It works while "
                           "this computer shares its own connection."));
    body->addWidget(m_proxy);
    m_proxy_status = new QLabel(card);
    m_proxy_status->setWordWrap(true);
    m_proxy_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_proxy_status->setContentsMargins(24, 0, 0, 0);
    body->addWidget(m_proxy_status);

    m_interface = new QCheckBox(tr("Carry all of this computer's traffic through the network, with no proxy setting "
                                   "in any program"), card);
    m_interface->setToolTip(tr("Every program's connections leave through the network's gateways, each through "
                               "another, and names are looked up there. This computer's own network \xe2\x80\x94 a "
                               "printer, the router \xe2\x80\x94 and this node's own connections stay direct. It "
                               "works while this computer shares its own connection."));
    body->addWidget(m_interface);
    m_interface_status = new QLabel(card);
    m_interface_status->setWordWrap(true);
    m_interface_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_interface_status->setContentsMargins(24, 0, 0, 0);
    body->addWidget(m_interface_status);
    m_interface_setup = new QPushButton(tr("Install the network service\xe2\x80\xa6"), card);
    m_interface_setup->setVisible(false);
    QHBoxLayout* setup_row = new QHBoxLayout();
    setup_row->setContentsMargins(24, 0, 0, 0);
    setup_row->addWidget(m_interface_setup);
    setup_row->addStretch(1);
    body->addLayout(setup_row);

    m_gateway_note = new QLabel(card);
    m_gateway_note->setWordWrap(true);
    m_gateway_note->setVisible(false);
    body->addWidget(m_gateway_note);

    connect(m_gateway, &QCheckBox::toggled, this, &ServerPage::onChanged);
    connect(m_gateway_budget, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged),
            this, &ServerPage::onChanged);
    connect(m_proxy, &QCheckBox::toggled, this, &ServerPage::onChanged);
    connect(m_interface, &QCheckBox::toggled, this, &ServerPage::onChanged);
    connect(m_gateway_list, &QPushButton::clicked, this, &ServerPage::onListGateway);
    connect(m_interface_setup, &QPushButton::clicked, this, &ServerPage::onInstallNetService);
    return card;
}

void ServerPage::onInstallNetService()
{
#ifdef WIN32
    // The service serves only the user it is installed for: this one.
    QString sid;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<BYTE> buf(size);
        LPWSTR text = nullptr;
        if (size && GetTokenInformation(token, TokenUser, buf.data(), size, &size) &&
            ConvertSidToStringSidW(((TOKEN_USER*)buf.data())->User.Sid, &text)) {
            sid = QString::fromWCharArray(text);
            LocalFree(text);
        }
        CloseHandle(token);
    }
    const QString exe = QDir::toNativeSeparators(QCoreApplication::applicationDirPath() + "/bps-relay-net.exe");
    if (sid.isEmpty() || !QFile::exists(exe)) {
        QMessageBox::warning(this, tr("Network service"),
                             tr("The network service was not installed: bps-relay-net.exe and wintun.dll must be "
                                "beside BPS Relay."));
        return;
    }
    const std::wstring file = exe.toStdWString();
    const std::wstring params = (QStringLiteral("install ") + sid).toStdWString();
    SHELLEXECUTEINFOW sei;
    std::memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = file.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        QMessageBox::warning(this, tr("Network service"),
                             tr("The network service was not installed: Windows did not give it an administrator's "
                                "rights."));
        return;
    }
    WaitForSingleObject(sei.hProcess, 120000);
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    if (code == 0) {
        QMessageBox::information(this, tr("Network service"),
                                 tr("The network service is installed and running. Restart BPS Relay for this "
                                    "computer's traffic to go through the network."));
    } else {
        QMessageBox::warning(this, tr("Network service"),
                             tr("The network service was not installed (code %1). Its log is in "
                                "%ProgramData%\\BPS Relay\\network.log.").arg(code));
    }
    Refresh();
#endif
}

void ServerPage::onListGateway()
{
    if (!m_client_model) return;
    // A relay's own listing carries its address, so its gateway is listed under
    // a second key; any other node lists itself with the gateway option on.
    PublishDialog dialog(m_rpc, m_wallets, m_client_model->getNumBlocks(), false, this, m_own_address);
    dialog.exec();
    Refresh();
}

void ServerPage::ShowGateway(const UniValue& value)
{
    const auto num = [&value](const char* key) -> int64_t {
        const UniValue& v = find_value(value, key);
        return v.isNum() ? v.get_int64() : 0;
    };
    const auto mib = [](int64_t bytes) {
        return bytes < (1 << 20) ? tr("%1 KiB").arg((bytes + 1023) / 1024)
                                 : tr("%1 MiB").arg(bytes / 1048576.0, 0, 'f', 1);
    };

    // Using the network's internet.
    const UniValue& visitor = find_value(value, "visitor");
    if (visitor.isObject()) {
        const UniValue& proxy = find_value(visitor, "proxy");
        const UniValue& why = find_value(visitor, "why");
        int open = 0;
        for (const UniValue& g : find_value(visitor, "gateways").getValues()) {
            if (find_value(g, "state").getValStr() == "open") ++open;
        }
        if (!find_value(visitor, "allowed").isTrue()) {
            m_proxy_status->setText(tr("Waiting: %1.").arg(QString::fromStdString(why.isStr() ? why.get_str() : "")));
        } else if (open == 0) {
            m_proxy_status->setText(tr("Looking for gateways to use\xe2\x80\xa6"));
        } else {
            m_proxy_status->setText(
                tr("SOCKS5 proxy at %1 \xe2\x80\x94 set it in a browser or another program, with names looked "
                   "up through the proxy. %2 gateway(s) met, %3 connection(s) open.")
                    .arg(QString::fromStdString(proxy.isStr() ? proxy.get_str() : ""))
                    .arg(open)
                    .arg(find_value(visitor, "connections").isNum() ? find_value(visitor, "connections").get_int64() : 0));
        }
    } else {
        m_proxy_status->setText(gArgs.GetBoolArg("-gatewayproxy", overlay::DEFAULT_GATEWAY_PROXY)
                                    ? tr("Off: it needs the overlay and the roster index.")
                                    : tr("Off."));
    }

    // All of the computer's traffic, and what it still needs.
    const UniValue& iface = visitor.isObject() ? find_value(visitor, "interface") : NullUniValue;
    std::string how;
    const bool may = InterfaceAvailable() && overlay::HaveNetAdmin(how);
    m_interface->setEnabled(InterfaceAvailable());
    m_interface_setup->setVisible(false);
    if (iface.isObject()) {
        const auto inum = [&iface](const char* key) -> int64_t {
            const UniValue& v = find_value(iface, key);
            return v.isNum() ? v.get_int64() : 0;
        };
        m_interface_status->setText(tr("On: %1 connection(s) through the network now; %2 sent, %3 received.")
                                        .arg(inum("connections"))
                                        .arg(mib(inum("bytes_out")))
                                        .arg(mib(inum("bytes_in"))));
    } else if (!InterfaceAvailable()) {
        m_interface_status->setText(tr("Not available on this system yet."));
    } else if (!may) {
#ifdef WIN32
        m_interface_status->setText(tr("First install BPS Relay's network service, once; Windows asks for an "
                                       "administrator."));
        m_interface_setup->setVisible(true);
#else
        m_interface_status->setText(tr("First let BPS Relay manage the network, once, as an administrator: %1")
                                        .arg(QString::fromStdString(how.substr(how.find("sudo") == std::string::npos ? 0 : how.find("sudo")))));
#endif
    } else {
        m_interface_status->setText(m_interface->isChecked() ? tr("Starts when the client restarts.") : QString());
    }
    m_interface_status->setVisible(!m_interface_status->text().isEmpty());

    // Sharing.
    if (!find_value(value, "enabled").isTrue()) {
        SetBadge(m_gateway_badge, Status::OFF,
                 gArgs.GetBoolArg("-gateway", overlay::DEFAULT_GATEWAY) ? tr("needs the overlay") : tr("switched off"));
        m_gateway_state->setText(gArgs.GetBoolArg("-gateway", overlay::DEFAULT_GATEWAY)
                                     ? tr("no \xe2\x80\x94 it needs the overlay and the roster index")
                                     : tr("no \xe2\x80\x94 switched off"));
        for (QLabel* l : {m_gateway_key, m_gateway_today, m_gateway_now}) l->setText(tr("\xe2\x80\x94"));
        m_gateway_list->setVisible(false);
        return;
    }
    const std::string state = find_value(value, "state").getValStr();
    const bool listed = find_value(value, "listed").isTrue();
    const std::string own = find_value(value, "own_listing").getValStr();
    m_own_address = own == "with an address";
    if (!listed) {
        SetBadge(m_gateway_badge, Status::ATTENTION, tr("not listed as a gateway"));
        m_gateway_state->setText(tr("not yet \xe2\x80\x94 the roster does not list this node as a gateway, so "
                                    "nobody can find it"));
        m_gateway_key->setText(
            m_own_address ? tr("nothing yet \xe2\x80\x94 a relay lists its gateway under a second key, with no "
                               "address, apart from its own listing")
            : own == "without an address"
                ? tr("nothing yet \xe2\x80\x94 this node's listing lacks the gateway option; publish it again "
                     "with the option on")
                : tr("nothing yet \xe2\x80\x94 publish a listing with no address and the gateway option on"));
        m_gateway_list->setText(m_own_address ? tr("List this relay's gateway\xe2\x80\xa6") : tr("List as a gateway\xe2\x80\xa6"));
        m_gateway_list->setVisible(true);
    } else {
        m_gateway_list->setVisible(false);
        if (state == "open") {
            SetBadge(m_gateway_badge, Status::RUNNING, tr("sharing"));
            m_gateway_state->setText(tr("yes, taking connections"));
        } else {
            SetBadge(m_gateway_badge, Status::ATTENTION, tr("today's share used"));
            m_gateway_state->setText(tr("today's share is used up; it takes connections again when the day "
                                        "turns (UTC)"));
        }
        const QString key = BpsUtil::ShortKey(QString::fromStdString(find_value(value, "key").getValStr()));
        m_gateway_key->setText(find_value(value, "second_key").isTrue()
                                   ? tr("its gateway key %1, apart from the relay's address").arg(key)
                                   : tr("this node's own key %1").arg(key));
    }
    const int64_t budget = num("daily_budget_bytes");
    m_gateway_today->setText(budget > 0 ? tr("%1 of %2 MiB").arg(mib(num("today_bytes"))).arg(budget >> 20)
                                        : tr("%1, with no daily limit").arg(mib(num("today_bytes"))));
    m_gateway_now->setText(tr("%1 connection(s) for %2 visitor(s), at %3 meeting point(s)")
                               .arg(num("tcp_connections") + num("udp_flows"))
                               .arg(num("visitors"))
                               .arg(num("registrations")));
}

void ServerPage::Load()
{
    m_loading = true;
    // What the node is running with, so a value from the command line or the
    // config file shows here rather than being contradicted by the page.
    m_relay->setChecked(gArgs.GetBoolArg("-relay", roster::DEFAULT_RELAY));
    m_acceptlistings->setChecked(gArgs.GetBoolArg("-acceptlistings", roster::DEFAULT_ACCEPT_LISTINGS));
    m_maxlistedusers->setValue((int)gArgs.GetArg("-maxlistedusers", roster::DEFAULT_MAX_LISTED_USERS));
    m_listingwallet->setText(QString::fromStdString(gArgs.GetArg("-listingwallet", "")));
    m_relayshare->setValue((int)gArgs.GetArg("-relayshare", roster::DEFAULT_RELAY_SHARE));
    m_mailbox->setChecked(gArgs.GetBoolArg("-mailbox", mail::DEFAULT_MAILBOX));
    m_mailbox_size->setValue((int)gArgs.GetArg("-mailboxmaxsize", (int64_t)mail::DEFAULT_MAILBOX_MAX_MB));
    m_gateway->setChecked(gArgs.GetBoolArg("-gateway", overlay::DEFAULT_GATEWAY));
    m_gateway_budget->setValue((int)gArgs.GetArg("-gatewaybandwidth", (int64_t)overlay::DEFAULT_GATEWAY_BANDWIDTH_MIB));
    m_proxy->setChecked(gArgs.GetBoolArg("-gatewayproxy", overlay::DEFAULT_GATEWAY_PROXY));
    m_interface->setChecked(gArgs.GetBoolArg("-gatewayroutes", false) ||
                            QSettings().value(KEY_GATEWAY_INTERFACE, false).toBool());
    m_loading = false;
}

void ServerPage::onChanged()
{
    if (m_loading) return;
    QSettings settings;
    settings.setValue(KEY_RELAY, m_relay->isChecked());
    settings.setValue(KEY_ACCEPTLISTINGS, m_acceptlistings->isChecked());
    settings.setValue(KEY_MAXLISTEDUSERS, m_maxlistedusers->value());
    settings.setValue(KEY_LISTINGWALLET, m_listingwallet->text().trimmed());
    settings.setValue(KEY_RELAYSHARE, m_relayshare->value());
    settings.setValue(KEY_MAILBOX, m_mailbox->isChecked());
    settings.setValue(KEY_MAILBOX_SIZE, m_mailbox_size->value());
    settings.setValue(KEY_GATEWAY, m_gateway->isChecked());
    settings.setValue(KEY_GATEWAY_BUDGET, m_gateway_budget->value());
    settings.setValue(KEY_GATEWAY_PROXY, m_proxy->isChecked());
    settings.setValue(KEY_GATEWAY_INTERFACE, m_interface->isChecked());
    const QString saved = tr("Saved. These are read when the node starts, so restart the client "
                             "for the change to take effect.");
    for (QLabel* note : {m_restart_note, m_mailbox_note, m_gateway_note}) {
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
        m_rpc.Call(TAG_GATEWAY, "getgatewayinfo");
        m_rpc.Call(TAG_ROSTERINFO, "getrosterinfo");
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
    if (tag == TAG_GATEWAY) {
        ShowGateway(value);
        return;
    }
    if (tag == TAG_ROSTERINFO) {
        // A relay listed to announce its address says where it is while it
        // runs, instead of on the chain (roster/relayaddr.h).
        const UniValue& announcing = find_value(value, "announcing");
        if (!find_value(value, "relay").isTrue()) {
            m_announced->setText(tr("none \xe2\x80\x94 relaying is switched off"));
            m_announced->setToolTip(QString());
            return;
        }
        if (!announcing.isObject()) {
            m_announced->setText(tr("none \xe2\x80\x94 this node is not listed as a relay that announces its address"));
            m_announced->setToolTip(QString());
            return;
        }
        QStringList where;
        const UniValue& eps = find_value(announcing, "endpoints");
        for (size_t i = 0; eps.isArray() && i < eps.size(); ++i) where << BpsUtil::DescribeEndpoint(eps[i]);
        const UniValue& time = find_value(announcing, "time");
        const qint64 age = time.isNum() ? std::max<qint64>(0, QDateTime::currentSecsSinceEpoch() - time.get_int64()) : 0;
        m_announced->setText(tr("%1, signed %2 ago").arg(where.join(", "), BpsUtil::HumanSeconds(age)));
        m_announced->setToolTip(tr("Where this relay tells the network it is, signed with its key. It says so "
                                   "again every hour and when the address changes; none of it is on the chain."));
        return;
    }
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
    if (tag == TAG_GATEWAY) {
        m_gateway_state->setText(message);
        return;
    }
    if (tag == TAG_MAIL) {
        m_mailbox_holding->setText(message);
        return;
    }
    if (tag != TAG_PAYOUT) return;
    m_payout->setText(message);
}
