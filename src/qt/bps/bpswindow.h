// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_BPSWINDOW_H
#define BITCOIN_QT_BPS_BPSWINDOW_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <QMainWindow>
#include <QPointer>

#include <memory>

class BpsRpc;
class ClientModel;
class DiscoveryPage;
class NetworkStyle;
class OverlayPage;
class PlatformStyle;
class RPCConsole;
class SettingsPage;
class WalletController;
class WalletModel;
class WalletPage;

enum class SynchronizationState;

namespace GUIUtil {
class ClickableLabel;
class ClickableProgressBar;
} // namespace GUIUtil

namespace interfaces {
class Handler;
class Node;
struct BlockAndHeaderTipInfo;
} // namespace interfaces

QT_BEGIN_NAMESPACE
class QDateTime;
class QFrame;
class QLabel;
class QListWidget;
class QStackedWidget;
class QTimer;
QT_END_NAMESPACE

/**
 * The window of BPS Relay.
 *
 * Deliberately not BitcoinGUI and deliberately not a copy of it. The wallet
 * client's window is about coins; this one is about who is on the network. What
 * the two genuinely share - the node models, the console, the peer table, the
 * platform styling - is linked from the same library rather than duplicated, so
 * a change made to any of it in the core layer arrives here by rebuilding and
 * nothing else.
 *
 * The Node tab is qt/rpcconsole.cpp exactly as the wallet client uses it. That
 * is the clearest example of the rule: the moment this client needed peer
 * tables and a console, the answer was to reuse the ones that exist, not to
 * write a second pair that would then have to be kept in step.
 */
class BpsWindow : public QMainWindow
{
    Q_OBJECT

public:
    BpsWindow(interfaces::Node& node, const PlatformStyle* platformStyle,
              const NetworkStyle* networkStyle, QWidget* parent = nullptr);
    ~BpsWindow();

    void setClientModel(ClientModel* model = nullptr,
                        interfaces::BlockAndHeaderTipInfo* tip_info = nullptr);

#ifdef ENABLE_WALLET
    /** Hand over the controller that opens and closes wallets. */
    void setWalletController(WalletController* controller);
#endif

    /** Called before shutdown, while an event loop is still running. */
    void unsubscribeFromCoreSignals();

public Q_SLOTS:
    void detectShutdown();

    /** Core wants to tell the operator something. Invoked by name from a worker thread. */
    void message(const QString& title, const QString& text, unsigned int style,
                 bool* ret = nullptr, const QString& detailed_message = QString());

private Q_SLOTS:
    void setNumConnections(int count);
    void setNumBlocks(int count, const QDateTime& block_date, double progress,
                      bool header, SynchronizationState sync_state);
    void updateNetworkState();
    /** Lock and staking state in the footer, read from the open wallets. */
    void updateWalletStatus();

private:
    void subscribeToCoreSignals();
    void CreateFooter();
#ifdef ENABLE_WALLET
    /** The wallet the footer reports on: one that is staking, else the first open. */
    WalletModel* FooterWallet() const;
#endif

    /** The chain half of the footer, from a height, its block's time and a sync fraction. */
    void UpdateChain(int height, const QDateTime& block_date, double progress);

    interfaces::Node& m_node;
    const PlatformStyle* m_platform_style;

    ClientModel* m_client_model{nullptr};
    std::unique_ptr<BpsRpc> m_rpc;

    QListWidget* m_nav{nullptr};
    QStackedWidget* m_pages{nullptr};
    DiscoveryPage* m_discovery{nullptr};
    OverlayPage* m_overlay{nullptr};
    RPCConsole* m_console{nullptr};
    SettingsPage* m_settings{nullptr};
#ifdef ENABLE_WALLET
    WalletPage* m_wallet{nullptr};
    QPointer<WalletController> m_wallet_controller;
#endif

    // Footer, left to right.
    QLabel* m_progress_label{nullptr};
    GUIUtil::ClickableProgressBar* m_progress{nullptr};
    QLabel* m_listing_label{nullptr};
    QLabel* m_overlay_label{nullptr};
    QFrame* m_wallet_separator{nullptr};
    QLabel* m_lock_icon{nullptr};
    QLabel* m_staking_icon{nullptr};
    QLabel* m_staking_label{nullptr};
    GUIUtil::ClickableLabel* m_connections_icon{nullptr};
    QLabel* m_connections_label{nullptr};
    QLabel* m_blocks_icon{nullptr};
    QLabel* m_blocks_label{nullptr};
    QTimer* m_staking_timer{nullptr};
    int m_spinner_frame{0};
    int m_prev_blocks{-1}; //!< so the first height painted gets an icon too

    std::unique_ptr<interfaces::Handler> m_handler_message_box;
    std::unique_ptr<interfaces::Handler> m_handler_question;
};

#endif // BITCOIN_QT_BPS_BPSWINDOW_H
