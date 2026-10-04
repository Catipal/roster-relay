// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/bps/walletpage.h>

#include <qt/bitcoingui.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/walletcontroller.h>

#include <interfaces/node.h>

#include <QFont>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenuBar>
#include <QSystemTrayIcon>
#include <QVBoxLayout>

namespace {
//! The remote window's chrome is a fixed dark console whatever the desktop
//! theme, the way a remote desktop viewer frames another machine's screen.
const char* CHROME_STYLE =
    "#vpsFrame { border: 1px solid #2b3139; border-radius: 9px; background: #15191e; }"
    "#vpsTitle { background: #1f252c; border-top-left-radius: 8px; border-top-right-radius: 8px;"
    "            border-bottom: 1px solid #2b3139; }"
    "#vpsTitle QLabel { color: #c9d1d9; background: transparent; }"
    "#vpsTitle QLabel#vpsHost { color: #7d8590; }"
    "#vpsTitle QLabel#vpsLive { color: #3fb950; }"
    "#vpsScreen { background: palette(window); border-bottom-left-radius: 8px;"
    "             border-bottom-right-radius: 8px; }";

QLabel* Dot(const char* colour, QWidget* parent)
{
    QLabel* dot = new QLabel(parent);
    dot->setFixedSize(11, 11);
    dot->setStyleSheet(QString("background: %1; border-radius: 5px;").arg(colour));
    return dot;
}
} // namespace

WalletPage::WalletPage(interfaces::Node& node, const PlatformStyle* platform_style,
                       const NetworkStyle* network_style, QWidget* parent)
    : QWidget(parent)
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(18, 16, 18, 14);
    outer->setSpacing(0);

    QFrame* frame = new QFrame(this);
    frame->setObjectName("vpsFrame");
    frame->setStyleSheet(CHROME_STYLE);
    QVBoxLayout* frame_layout = new QVBoxLayout(frame);
    frame_layout->setContentsMargins(1, 1, 1, 1);
    frame_layout->setSpacing(0);

    // --- title bar: whose screen this is ----------------------------------
    QWidget* title_bar = new QWidget(frame);
    title_bar->setObjectName("vpsTitle");
    title_bar->setAttribute(Qt::WA_StyledBackground, true);
    title_bar->setFixedHeight(32);
    QHBoxLayout* title_layout = new QHBoxLayout(title_bar);
    title_layout->setContentsMargins(12, 0, 12, 0);
    title_layout->setSpacing(7);
    title_layout->addWidget(Dot("#ff5f57", title_bar));
    title_layout->addWidget(Dot("#febc2e", title_bar));
    title_layout->addWidget(Dot("#28c840", title_bar));
    title_layout->addSpacing(10);

    m_title = new QLabel(title_bar);
    QFont title_font = m_title->font();
    title_font.setBold(true);
    m_title->setFont(title_font);
    title_layout->addWidget(m_title);
    title_layout->addStretch(1);

    QLabel* host = new QLabel(tr("bitcoin-pos-qt @ this node"), title_bar);
    host->setObjectName("vpsHost");
    host->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    title_layout->addWidget(host);
    QLabel* live = new QLabel(tr("\xe2\x97\x8f live"), title_bar);
    live->setObjectName("vpsLive");
    live->setToolTip(tr("The wallet client, running in this process against this node. "
                        "It is the same program as bitcoin-pos-qt, not a copy of it."));
    title_layout->addWidget(live);
    frame_layout->addWidget(title_bar);

    // --- the screen: the wallet client's own window -------------------------
    QWidget* screen = new QWidget(frame);
    screen->setObjectName("vpsScreen");
    screen->setAttribute(Qt::WA_StyledBackground, true);
    QVBoxLayout* screen_layout = new QVBoxLayout(screen);
    screen_layout->setContentsMargins(0, 0, 0, 0);

    m_gui = new BitcoinGUI(node, platform_style, network_style, screen);
    // A main window made into an ordinary child: it lays out its menu bar,
    // toolbar and status bar inside itself, and stops being a window.
    m_gui->setWindowFlags(Qt::Widget);
    m_gui->menuBar()->setNativeMenuBar(false);
    // This window answers the node's message boxes; two subscribers would show
    // every message twice.
    m_gui->unsubscribeFromCoreSignals();
    screen_layout->addWidget(m_gui);
    frame_layout->addWidget(screen, 1);

    outer->addWidget(frame, 1);

    // The wallet client names its window after the wallet showing and the
    // network; the title bar follows it, the way a viewer shows the remote title.
    m_title->setText(m_gui->windowTitle());
    connect(m_gui, &QWidget::windowTitleChanged, m_title, &QLabel::setText);
}

void WalletPage::HideTrayIcon()
{
    // Its tray icon would toggle the embedded window rather than this one, so
    // it is hidden, and kept hidden when the option is changed.
    for (QSystemTrayIcon* tray : m_gui->findChildren<QSystemTrayIcon*>()) tray->hide();
    if (m_client_model && m_client_model->getOptionsModel()) {
        disconnect(m_client_model->getOptionsModel(), &OptionsModel::hideTrayIconChanged, m_gui, nullptr);
    }
}

void WalletPage::setClientModel(ClientModel* client_model, interfaces::BlockAndHeaderTipInfo* tip_info)
{
    m_client_model = client_model;
    m_gui->setClientModel(client_model, tip_info);
    if (client_model) HideTrayIcon();
}

void WalletPage::setWalletController(WalletController* controller)
{
    m_gui->setWalletController(controller);
}
