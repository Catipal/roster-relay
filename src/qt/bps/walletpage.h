// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_WALLETPAGE_H
#define BITCOIN_QT_BPS_WALLETPAGE_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <QWidget>

class BitcoinGUI;
class ClientModel;
class NetworkStyle;
class PlatformStyle;
class WalletController;

namespace interfaces {
class Node;
struct BlockAndHeaderTipInfo;
} // namespace interfaces

QT_BEGIN_NAMESPACE
class QLabel;
QT_END_NAMESPACE

/**
 * The wallet client itself, running inside this one.
 *
 * Not a second wallet and not a selection of its pages: this is BitcoinGUI,
 * the wallet client's own main window, with its menus, toolbar and status bar,
 * embedded as a widget and framed like a remote desktop onto another machine.
 * Every fix and feature that lands in the wallet client arrives here by
 * rebuilding, because there is nothing here to keep in step with it.
 *
 * Three things a top-level window does are switched off, because the window it
 * now lives in does them: it stops answering the node's message boxes (or
 * every message would appear twice), its tray icon is hidden (clicking it would
 * hide the wallet inside the page), and closing it is not offered.
 */
class WalletPage : public QWidget
{
    Q_OBJECT

public:
    WalletPage(interfaces::Node& node, const PlatformStyle* platform_style,
               const NetworkStyle* network_style, QWidget* parent = nullptr);

    void setClientModel(ClientModel* client_model,
                        interfaces::BlockAndHeaderTipInfo* tip_info = nullptr);
    void setWalletController(WalletController* controller);

private:
    void HideTrayIcon();

    BitcoinGUI* m_gui{nullptr};
    ClientModel* m_client_model{nullptr};
    QLabel* m_title{nullptr};
};

#endif // BITCOIN_QT_BPS_WALLETPAGE_H
