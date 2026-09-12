// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_BPSWINDOW_H
#define BITCOIN_QT_BPS_BPSWINDOW_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <QMainWindow>

#include <memory>

class BpsRpc;
class ClientModel;
class DiscoveryPage;
class NetworkStyle;
class OverlayPage;
class PlatformStyle;
class RPCConsole;
class WalletController;
class WalletPage;

enum class SynchronizationState;

namespace interfaces {
class Handler;
class Node;
struct BlockAndHeaderTipInfo;
} // namespace interfaces

QT_BEGIN_NAMESPACE
class QDateTime;
class QLabel;
class QListWidget;
class QStackedWidget;
QT_END_NAMESPACE

/**
 * The window of the discovery client.
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

private:
    void subscribeToCoreSignals();

    interfaces::Node& m_node;
    const PlatformStyle* m_platform_style;

    ClientModel* m_client_model{nullptr};
    std::unique_ptr<BpsRpc> m_rpc;

    QListWidget* m_nav{nullptr};
    QStackedWidget* m_pages{nullptr};
    DiscoveryPage* m_discovery{nullptr};
    OverlayPage* m_overlay{nullptr};
    RPCConsole* m_console{nullptr};
#ifdef ENABLE_WALLET
    WalletPage* m_wallet{nullptr};
#endif

    QLabel* m_status_chain{nullptr};
    QLabel* m_status_peers{nullptr};

    std::unique_ptr<interfaces::Handler> m_handler_message_box;
    std::unique_ptr<interfaces::Handler> m_handler_question;
};

#endif // BITCOIN_QT_BPS_BPSWINDOW_H
