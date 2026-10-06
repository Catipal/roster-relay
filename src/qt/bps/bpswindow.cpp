// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/bpswindow.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>
#include <qt/bps/discoverypage.h>
#include <qt/bps/overlaypage.h>
#include <qt/bps/serverpage.h>
#include <qt/bps/settingspage.h>
#ifdef ENABLE_WALLET
#include <qt/bps/walletpage.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <rpc/server.h>
#endif

#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/networkstyle.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/rpcconsole.h>

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <univalue.h>
#include <node/ui_interface.h>
#include <policy/feerate.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/translation.h>

#include <QApplication>
#include <QCloseEvent>
#include <QDateTime>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QMetaObject>
#include <QSettings>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QTimer>
#include <QWidget>

#include <algorithm>
#include <assert.h>
#include <functional>

Q_DECLARE_METATYPE(bool*)

namespace {
//! How often the staking state is looked at again. It changes when a stake
//! search runs, and the wallet client polls on the same order.
const int STAKING_REFRESH_MS = 5000;
//! The block reward and the share given to peers change at most per block.
const int REWARD_REFRESH_MS = 30000;
const char* TAG_FOOTER_REWARD = "footer:reward";

//! Core wants to say something. Marshalled onto the GUI thread by name, which
//! is the only way to reach a slot from a thread that has no Qt connection.
bool ThreadSafeMessageBox(BpsWindow* window, const bilingual_str& message,
                          const std::string& caption, unsigned int style)
{
    const bool modal = (style & CClientUIInterface::MODAL);
    style &= ~CClientUIInterface::SECURE;
    bool ret = false;

    QString detailed;
    if (message.original != message.translated) {
        detailed = BpsWindow::tr("Original message:") + "\n" + QString::fromStdString(message.original);
    }

    const bool invoked = QMetaObject::invokeMethod(
        window, "message",
        modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(caption)),
        Q_ARG(QString, QString::fromStdString(message.translated)),
        Q_ARG(unsigned int, style),
        Q_ARG(bool*, &ret),
        Q_ARG(QString, detailed));
    assert(invoked);
    return ret;
}

QString NoWrap(const QString& html) { return "<nobr>" + html + "</nobr>"; }
} // namespace

BpsWindow::BpsWindow(interfaces::Node& node, const PlatformStyle* platformStyle,
                     const NetworkStyle* networkStyle, QWidget* parent)
    : QMainWindow(parent), m_node(node), m_platform_style(platformStyle)
{
    QSettings settings;
    if (!restoreGeometry(settings.value("BpsWindowGeometry").toByteArray())) {
        resize(1000, 700);
    }

    setWindowTitle(GUIUtil::ClientName() + " " + networkStyle->getTitleAddText());
    setWindowIcon(networkStyle->getTrayAndWindowIcon());
    setMinimumSize(900, 600);

    m_rpc.reset(new BpsRpc(node, this));

    m_discovery = new DiscoveryPage(*m_rpc, this);
    m_overlay = new OverlayPage(*m_rpc, this);
    // Not a reimplementation: this is the wallet client's own console, peer
    // table and traffic graph, linked rather than copied.
    m_console = new RPCConsole(node, platformStyle, nullptr);

    // The node first, because this client is about who is on the network: who
    // is listed, the overlay this node runs, and the peers and console. Three
    // views of one thing, so one section with tabs rather than three entries.
    m_node_tabs = new QTabWidget(this);
    m_node_tabs->setDocumentMode(true);
    m_node_tabs->addTab(m_discovery, tr("Discovery"));
    m_node_tabs->addTab(m_overlay, tr("Overlay"));
    m_node_tabs->addTab(m_console, tr("Peers and console"));

    m_pages = new QStackedWidget(this);
    m_pages->addWidget(m_node_tabs);

    m_nav = new QListWidget(this);
    m_nav->addItem(tr("Node"));

#ifdef ENABLE_WALLET
    // After the node: the wallet is here because publishing costs a fee and a
    // relay stakes, not because this client is about coins.
    if (WalletModel::isWalletEnabled()) {
        m_wallet = new WalletPage(node, platformStyle, networkStyle, this);
        m_pages->addWidget(m_wallet);
        m_nav->addItem(tr("Wallet"));
    }
#endif

    m_server = new ServerPage(*m_rpc, this);
    m_pages->addWidget(m_server);
    m_nav->addItem(tr("Server"));

    m_settings = new SettingsPage(platformStyle, this);
    connect(m_settings, &SettingsPage::message, this,
            [this](const QString& title, const QString& text, unsigned int style) {
                message(title, text, style);
            });
    m_pages->addWidget(m_settings);
    m_nav->addItem(tr("Settings"));
    m_nav->setFixedWidth(180);
    m_nav->setFrameShape(QFrame::NoFrame);
    m_nav->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_nav->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // Palette roles rather than fixed colours, so the sidebar follows whatever
    // theme the desktop is using instead of insisting on one.
    m_nav->setStyleSheet(
        "QListWidget { background: palette(alternate-base); border: none; outline: none;"
        "              padding-top: 10px; }"
        "QListWidget::item { padding: 11px 16px; border: none; }"
        "QListWidget::item:selected { background: palette(highlight);"
        "                             color: palette(highlighted-text); }"
        "QListWidget::item:hover:!selected { background: palette(midlight); }");
    m_nav->setCurrentRow(0);
    connect(m_nav, &QListWidget::currentRowChanged, m_pages, &QStackedWidget::setCurrentIndex);

    QWidget* central = new QWidget(this);
    QHBoxLayout* layout = new QHBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(m_nav);
    layout->addWidget(m_pages, 1);
    setCentralWidget(central);

    CreateFooter();
    subscribeToCoreSignals();
}

BpsWindow::~BpsWindow()
{
    QSettings settings;
    settings.setValue("BpsWindowGeometry", saveGeometry());
    // m_console is a child of the page stack, so Qt owns it from here.
}

void BpsWindow::CreateFooter()
{
    // The wallet client's status bar, with what this client adds: whether you
    // are listed and whether the overlay is running. Network on the right, as
    // there; the progress bar on the left, only while catching up.
    m_progress_label = new QLabel(this);
    m_progress_label->setVisible(false);
    // Parented by the status bar when added; these two take no parent argument.
    m_progress = new GUIUtil::ProgressBar();
    m_progress->setAlignment(Qt::AlignCenter);
    // Wide enough for "6 years and 22 weeks behind" on one line.
    m_progress->setMinimumWidth(300);
    m_progress->setVisible(false);
    statusBar()->addWidget(m_progress_label);
    statusBar()->addWidget(m_progress);

    QFrame* frame = new QFrame(this);
    QHBoxLayout* row = new QHBoxLayout(frame);
    row->setContentsMargins(3, 0, 3, 0);
    row->setSpacing(5);
    const auto separator = [frame]() {
        QFrame* line = new QFrame(frame);
        line->setFrameShape(QFrame::VLine);
        line->setFrameShadow(QFrame::Sunken);
        return line;
    };

    m_listing_label = new QLabel(tr("listing unknown"), frame);
    m_overlay_label = new QLabel(tr("overlay unknown"), frame);
    m_lock_icon = new QLabel(frame);
    m_staking_icon = new QLabel(frame);
    m_staking_label = new QLabel(frame);
    m_connections_icon = new GUIUtil::ClickableLabel();
    m_connections_label = new QLabel(frame);
    m_blocks_icon = new QLabel(frame);
    m_blocks_label = new QLabel(tr("connecting\xe2\x80\xa6"), frame);

    row->addWidget(m_listing_label);
    row->addWidget(separator());
    row->addWidget(m_overlay_label);
    m_wallet_separator = separator();
    row->addWidget(m_wallet_separator);
    row->addWidget(m_lock_icon);
    row->addWidget(m_staking_icon);
    row->addWidget(m_staking_label);
    row->addWidget(separator());
    row->addWidget(m_connections_icon);
    row->addWidget(m_connections_label);
    row->addWidget(separator());
    row->addWidget(m_blocks_icon);
    row->addWidget(m_blocks_label);
    statusBar()->addPermanentWidget(frame);

    m_lock_icon->setVisible(false);
    m_staking_icon->setVisible(false);
    m_staking_label->setVisible(false);
    m_wallet_separator->setVisible(false);

    connect(m_discovery, &DiscoveryPage::listingChanged, this, [this](const QString& summary, bool) {
        m_listing_label->setText(summary);
    });
    connect(m_overlay, &OverlayPage::overlayChanged, this, [this](const QString& summary, bool) {
        m_overlay_label->setText(summary);
    });
    connect(m_connections_icon, &GUIUtil::ClickableLabel::clicked, this, [this] {
        m_node.setNetworkActive(!m_node.getNetworkActive());
    });

#ifdef ENABLE_WALLET
    if (m_wallet) {
        m_staking_timer = new QTimer(this);
        m_staking_timer->setInterval(STAKING_REFRESH_MS);
        connect(m_staking_timer, &QTimer::timeout, this, &BpsWindow::updateWalletStatus);
        m_staking_timer->start();

        // What a block pays and how much of it this node gives its peers, for
        // the yearly rate staking earns.
        connect(m_rpc.get(), &BpsRpc::result, this, &BpsWindow::onRpcResult);
        m_reward_timer = new QTimer(this);
        m_reward_timer->setInterval(REWARD_REFRESH_MS);
        connect(m_reward_timer, &QTimer::timeout, this, [this] {
            if (m_client_model) m_rpc->Call(TAG_FOOTER_REWARD, "getrelaypayout");
        });
        m_reward_timer->start();
    }
#endif
}

void BpsWindow::onRpcResult(const QString& tag, const UniValue& value)
{
    if (tag != TAG_FOOTER_REWARD) return;
    const UniValue& reward = find_value(value, "block_reward");
    const UniValue& share = find_value(value, "share_percent");
    int64_t amount = 0;
    if (reward.isNum() && ParseFixedPoint(reward.getValStr(), 8, &amount)) m_block_reward = amount;
    if (share.isNum()) m_share_percent = share.get_int();
    updateWalletStatus();
}

QString BpsWindow::YearlyRate(uint64_t network_weight, QString* detail) const
{
    if (m_block_reward <= 0 || network_weight == 0) return QString();
    // Every staker wins blocks in proportion to its stake, so the rate is the
    // same for all of them: what a year of blocks pays, over the coins staking.
    // Fees are left out; on a chain this empty they are a rounding error.
    const double blocks_per_year = 365.0 * 24 * 3600 / Params().GetConsensus().nPowTargetSpacing;
    const double kept = 1.0 - m_share_percent / 100.0;
    const double rate = 100.0 * blocks_per_year * (double)m_block_reward * kept / (double)network_weight;
    if (detail) {
        *detail = tr("Staking earns about %1% a year at the current network weight: %2 blocks a year, "
                     "%3 %4 each, over %5 %4 staking.")
                      .arg(rate, 0, 'f', 2)
                      .arg((qint64)blocks_per_year)
                      .arg(QString::fromStdString(FormatMoney(m_block_reward)))
                      .arg(QString::fromStdString(CURRENCY_UNIT))
                      .arg(network_weight / COIN);
        if (m_share_percent > 0) {
            *detail += "<br>" + tr("That is after the %1% of each block this node shares with its peers.")
                                    .arg(m_share_percent);
        }
    }
    return tr("%1% a year").arg(rate, 0, 'f', 1);
}

void BpsWindow::subscribeToCoreSignals()
{
    m_handler_message_box = m_node.handleMessageBox(
        std::bind(ThreadSafeMessageBox, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    m_handler_question = m_node.handleQuestion(
        std::bind(ThreadSafeMessageBox, this, std::placeholders::_1, std::placeholders::_3, std::placeholders::_4));
}

void BpsWindow::unsubscribeFromCoreSignals()
{
    if (m_handler_message_box) m_handler_message_box->disconnect();
    if (m_handler_question) m_handler_question->disconnect();
}

void BpsWindow::setClientModel(ClientModel* model, interfaces::BlockAndHeaderTipInfo* tip_info)
{
    m_client_model = model;

    if (model) {
        updateNetworkState();
        connect(model, &ClientModel::numConnectionsChanged, this, &BpsWindow::setNumConnections);
        connect(model, &ClientModel::networkActiveChanged, this, &BpsWindow::updateNetworkState);
        connect(model, &ClientModel::numBlocksChanged, this, &BpsWindow::setNumBlocks);

        // Paint the height now rather than waiting for the next block. A node
        // with a loaded chain and no peers never receives one, so the status
        // bar otherwise reads "connecting..." for as long as it runs.
        if (tip_info) {
            UpdateChain(tip_info->block_height, QDateTime::fromTime_t(tip_info->block_time),
                        tip_info->verification_progress);
        }
    }

    // The console owns a good deal of state tied to the model, so it is told
    // first and told the same things the wallet client tells it.
    if (m_console) {
        if (model && tip_info) {
            m_console->setClientModel(model, tip_info->block_height,
                                      tip_info->block_time, tip_info->verification_progress);
        } else {
            m_console->setClientModel(model);
        }
    }

    m_discovery->setClientModel(model);
    m_overlay->setClientModel(model);
    m_server->setClientModel(model);
    if (m_settings) m_settings->setClientModel(model);
#ifdef ENABLE_WALLET
    if (m_wallet) m_wallet->setClientModel(model, tip_info);
#endif

    if (!model) {
        if (m_staking_timer) m_staking_timer->stop();
        m_blocks_label->setText(tr("shutting down\xe2\x80\xa6"));
        m_progress_label->setVisible(false);
        m_progress->setVisible(false);
        m_connections_label->clear();
    }
}

#ifdef ENABLE_WALLET
void BpsWindow::setWalletController(WalletController* controller)
{
    m_wallet_controller = controller;
    if (m_wallet) m_wallet->setWalletController(controller);
    m_discovery->setWalletController(controller);
    m_server->setWalletController(controller);
    if (controller) {
        connect(controller, &WalletController::walletAdded, this, &BpsWindow::updateWalletStatus);
        connect(controller, &WalletController::walletRemoved, this, &BpsWindow::updateWalletStatus);
    }
    updateWalletStatus();
}
#endif

void BpsWindow::setNumConnections(int count)
{
    Q_UNUSED(count);
    updateNetworkState();
}

void BpsWindow::updateNetworkState()
{
    if (!m_client_model) return;
    const int count = m_client_model->getNumConnections();

    QString icon;
    switch (count) {
    case 0: icon = ":/icons/connect_0"; break;
    case 1: case 2: case 3: icon = ":/icons/connect_1"; break;
    case 4: case 5: case 6: icon = ":/icons/connect_2"; break;
    case 7: case 8: case 9: icon = ":/icons/connect_3"; break;
    default: icon = ":/icons/connect_4"; break;
    }

    QString tooltip;
    if (m_node.getNetworkActive()) {
        const size_t in = m_node.getNodeCount(CConnman::CONNECTIONS_IN);
        const size_t out = m_node.getNodeCount(CConnman::CONNECTIONS_OUT);
        tooltip = tr("%1 peers: %2 inbound, %3 outbound.").arg(count).arg(in).arg(out) +
                  "<br>" + tr("Click to pause network activity.");
        m_connections_label->setText(count == 1 ? tr("1 peer") : tr("%1 peers").arg(count));
    } else {
        icon = ":/icons/network_disabled";
        tooltip = tr("Network activity is paused.") + "<br>" + tr("Click to resume it.");
        m_connections_label->setText(tr("network paused"));
    }

    m_connections_icon->setPixmap(
        m_platform_style->SingleColorIcon(icon).pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
    m_connections_icon->setToolTip(NoWrap(tooltip));
    m_connections_label->setToolTip(NoWrap(tooltip));
}

void BpsWindow::setNumBlocks(int count, const QDateTime& block_date, double progress,
                             bool header, SynchronizationState sync_state)
{
    Q_UNUSED(sync_state);
    if (header) return;
    UpdateChain(count, block_date, progress);
}

void BpsWindow::UpdateChain(int height, const QDateTime& block_date, double progress)
{
    const qint64 secs = block_date.secsTo(QDateTime::currentDateTime());
    QString tooltip = tr("Processed %1 blocks of history.").arg(height);
    m_blocks_label->setText(tr("block %1").arg(height));

    if (secs < MAX_BLOCK_TIME_GAP) {
        m_blocks_icon->setPixmap(
            m_platform_style->SingleColorIcon(":/icons/synced").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        tooltip = tr("Up to date.") + "<br>" + tooltip;
        m_progress_label->setVisible(false);
        m_progress->setVisible(false);
    } else {
        const QString behind = GUIUtil::formatNiceTimeOffset(secs);
        QString what;
        switch (m_client_model ? m_client_model->getBlockSource() : BlockSource::NONE) {
        case BlockSource::NETWORK: what = tr("Synchronizing with network\xe2\x80\xa6"); break;
        case BlockSource::DISK: what = tr("Processing blocks on disk\xe2\x80\xa6"); break;
        case BlockSource::REINDEX: what = tr("Reindexing blocks on disk\xe2\x80\xa6"); break;
        case BlockSource::NONE: what = tr("Connecting to peers\xe2\x80\xa6"); break;
        }
        m_progress_label->setText(what);
        m_progress_label->setVisible(true);
        m_progress->setFormat(tr("%1 behind").arg(behind));
        m_progress->setMaximum(1000000000);
        m_progress->setValue(progress * 1000000000.0 + 0.5);
        m_progress->setVisible(true);

        if (height != m_prev_blocks) {
            m_blocks_icon->setPixmap(m_platform_style->SingleColorIcon(
                QString(":/animation/spinner-%1").arg(m_spinner_frame, 3, 10, QChar('0')))
                .pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
            m_spinner_frame = (m_spinner_frame + 1) % SPINNER_FRAMES;
        }
        tooltip = tr("Catching up\xe2\x80\xa6") + "<br>" + tooltip + "<br>" +
                  tr("The last block received was made %1 ago.").arg(behind);
    }
    m_prev_blocks = height;

    m_blocks_icon->setToolTip(NoWrap(tooltip));
    m_blocks_label->setToolTip(NoWrap(tooltip));
    m_progress_label->setToolTip(NoWrap(tooltip));
    m_progress->setToolTip(NoWrap(tooltip));
}

#ifdef ENABLE_WALLET
WalletModel* BpsWindow::FooterWallet() const
{
    if (!m_wallet_controller) return nullptr;
    // The wallet that is staking if one is, since that is the state worth a
    // glance; otherwise the first one open. Each has its full state in the
    // wallet client's own status bar on the Wallet page.
    const std::vector<WalletModel*> wallets = m_wallet_controller->getOpenWallets();
    for (WalletModel* model : wallets) {
        if (model->wallet().getEnabledStaking() && model->wallet().getLastCoinStakeSearchInterval() &&
            model->getStakeWeight()) {
            return model;
        }
    }
    return wallets.empty() ? nullptr : wallets.front();
}
#endif

void BpsWindow::updateWalletStatus()
{
#ifdef ENABLE_WALLET
    if (m_node.shutdownRequested()) return;
    WalletModel* model = FooterWallet();
    m_wallet_separator->setVisible(model != nullptr);
    m_lock_icon->setVisible(false);
    const bool show_staking = model != nullptr && gArgs.GetBoolArg("-staking", true);
    m_staking_icon->setVisible(show_staking);
    m_staking_label->setVisible(show_staking);
    if (!model) return;

    const QString name = model->getDisplayName().toHtmlEscaped();
    QString icon, tooltip;
    switch (model->getEncryptionStatus()) {
    case WalletModel::Unencrypted:
        break;
    case WalletModel::Unlocked:
        if (model->getWalletUnlockStakingOnly()) {
            icon = ":/icons/lock_staking";
            tooltip = tr("Wallet <b>%1</b> is encrypted and unlocked for staking only").arg(name);
        } else {
            icon = ":/icons/lock_open";
            tooltip = tr("Wallet <b>%1</b> is encrypted and unlocked").arg(name);
        }
        break;
    case WalletModel::Locked:
        icon = ":/icons/lock_closed";
        tooltip = tr("Wallet <b>%1</b> is encrypted and locked").arg(name);
        break;
    }
    if (!icon.isEmpty()) {
        m_lock_icon->setPixmap(
            m_platform_style->SingleColorIcon(icon).pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        m_lock_icon->setToolTip(NoWrap(tooltip));
        m_lock_icon->setVisible(true);
    }
    if (!show_staking) return;

    // The same reading of the same wallet calls the wallet client makes, so
    // the two clients cannot disagree about whether a wallet is staking.
    const uint64_t weight = model->getStakeWeight();
    const bool staking = model->wallet().getLastCoinStakeSearchInterval() &&
                         model->wallet().getEnabledStaking() && weight;
    const uint64_t network_weight = GetPoSKernelPS();
    QString rate_detail;
    const QString rate = YearlyRate(network_weight, &rate_detail);
    if (staking) {
        // Blocks until a reward, on average: the network's weight over ours.
        const int blocks = (int)std::max<uint64_t>(1, network_weight / weight);
        m_staking_icon->setPixmap(
            m_platform_style->SingleColorIcon(":/icons/staking_on").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        m_staking_label->setText(rate.isEmpty() ? tr("staking") : tr("staking, %1").arg(rate));
        tooltip = tr("<b>%1</b> is staking.<br>Its weight is %2<br>Network weight is %3<br>"
                     "Expected time to earn a reward is %4")
                      .arg(name).arg(weight / COIN).arg(network_weight / COIN).arg(BpsUtil::HumanBlocks(blocks));
    } else {
        m_staking_icon->setPixmap(
            m_platform_style->SingleColorIcon(":/icons/staking_off").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        m_staking_label->setText(rate.isEmpty() ? tr("not staking") : tr("not staking (pays %1)").arg(rate));
        if (m_node.getNodeCount(CConnman::CONNECTIONS_ALL) < 4) {
            tooltip = tr("Not staking: too few peers");
        } else if (m_node.isInitialBlockDownload()) {
            tooltip = tr("Not staking: still catching up with the chain");
        } else if (!weight) {
            tooltip = tr("Not staking: <b>%1</b> has no mature coins").arg(name);
        } else if (model->wallet().isLocked()) {
            tooltip = tr("Not staking: <b>%1</b> is locked").arg(name);
        } else {
            tooltip = tr("Not staking");
        }
    }
    if (!rate_detail.isEmpty()) tooltip += "<br><br>" + rate_detail;
    m_staking_icon->setToolTip(NoWrap(tooltip));
    m_staking_label->setToolTip(NoWrap(tooltip));
#endif
}

void BpsWindow::closeEvent(QCloseEvent* event)
{
    // The application does not quit when its last window closes (the shutdown
    // notice is a window of its own), so without this, closing only hid the
    // window and left the node running with nothing on screen to stop it -
    // there is no tray icon to come back through.
    const OptionsModel* options = m_client_model ? m_client_model->getOptionsModel() : nullptr;
    if (options && options->getMinimizeOnClose()) {
        showMinimized();
        event->ignore();
        return;
    }
    QApplication::quit();
    QMainWindow::closeEvent(event);
}

void BpsWindow::detectShutdown()
{
    if (m_node.shutdownRequested()) {
        if (m_console) m_console->hide();
        qApp->quit();
    }
}

void BpsWindow::message(const QString& title, const QString& text, unsigned int style,
                        bool* ret, const QString& detailed_message)
{
    QString caption = title.isEmpty() ? GUIUtil::ClientName() : title;

    QMessageBox::Icon icon = QMessageBox::Information;
    switch (style & ((CClientUIInterface::ICON_MASK) & ~CClientUIInterface::ICON_INFORMATION)) {
    case CClientUIInterface::ICON_WARNING: icon = QMessageBox::Warning; break;
    case CClientUIInterface::ICON_ERROR: icon = QMessageBox::Critical; break;
    default: break;
    }

    QMessageBox::StandardButton buttons =
        (QMessageBox::StandardButton)(style & CClientUIInterface::BTN_MASK);
    if (!buttons) buttons = QMessageBox::Ok;

    QMessageBox box(icon, caption, text, buttons, this);
    box.setTextFormat(Qt::PlainText);
    box.setDetailedText(detailed_message);
    const int r = box.exec();
    if (ret != nullptr) *ret = r == QMessageBox::Ok || r == QMessageBox::Yes;
}
