// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_NODEPAGE_H
#define BITCOIN_QT_BPS_NODEPAGE_H

#include <QWidget>

class BpsRpc;
class ClientModel;
class PlatformStyle;
class RPCConsole;
class UniValue;

namespace interfaces {
class Node;
struct BlockAndHeaderTipInfo;
} // namespace interfaces

QT_BEGIN_NAMESPACE
class QLabel;
class QTimer;
QT_END_NAMESPACE

/**
 * The node, and what the network pays for carrying traffic.
 *
 * Mostly it is qt/rpcconsole.cpp - the wallet client's own information tab,
 * console, traffic graph and peer table, linked rather than copied. What this
 * wrapper adds above it is the one number the relay design turns on: how much
 * the whole network issues in a day, against how many peers are listed to share
 * it.
 *
 * That figure is a ceiling rather than an income. Nothing pays it out: the
 * payment layer of design note 001 section 8 is argued, not built. Showing it
 * anyway is worth doing because it is the quantity the whole argument rests on
 * - an adversary wanting a share of the network's users has to fund a share of
 * this - and because a number nobody can see is a number nobody checks.
 */
class NodePage : public QWidget
{
    Q_OBJECT

public:
    NodePage(BpsRpc& rpc, interfaces::Node& node, const PlatformStyle* platform_style,
             QWidget* parent = nullptr);

    /** The embedded console, for the window to feed and to hide on shutdown. */
    RPCConsole* Console() const { return m_console; }

    void setClientModel(ClientModel* model, interfaces::BlockAndHeaderTipInfo* tip_info);

public Q_SLOTS:
    void Refresh();

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);

private:
    void UpdateShare();

    BpsRpc& m_rpc;
    ClientModel* m_client_model{nullptr};
    RPCConsole* m_console{nullptr};

    QLabel* m_reward{nullptr};
    QLabel* m_per_day{nullptr};
    QLabel* m_listed{nullptr};
    QLabel* m_share{nullptr};
    QTimer* m_timer{nullptr};

    int m_display_unit{0};
    qint64 m_subsidy{-1}; //!< satoshi per block, -1 until known
    int m_peers{-1};      //!< peers in the live roster, -1 until known
};

#endif // BITCOIN_QT_BPS_NODEPAGE_H
