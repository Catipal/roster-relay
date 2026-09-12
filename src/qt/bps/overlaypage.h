// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_OVERLAYPAGE_H
#define BITCOIN_QT_BPS_OVERLAYPAGE_H

#include <QWidget>

class BpsRpc;
class ClientModel;
class UniValue;

QT_BEGIN_NAMESPACE
class QLabel;
class QListWidget;
class QTimer;
QT_END_NAMESPACE

/**
 * What the anonymity overlay is doing, and where this node can be met.
 *
 * The meeting points shown here are the part worth understanding, so the page
 * says it plainly: they are not looked up anywhere. Both sides compute them
 * from the same roster by the same arithmetic, which is why nobody is in a
 * position to answer the question differently for different people.
 *
 * The page is also honest about the overlay being off by default and about the
 * handshake being unreviewed. A privacy feature that overstates itself is worse
 * than one that is absent.
 */
class OverlayPage : public QWidget
{
    Q_OBJECT

public:
    OverlayPage(BpsRpc& rpc, QWidget* parent = nullptr);

    void setClientModel(ClientModel* model);

public Q_SLOTS:
    void Refresh();

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);

private:
    /** Recompute what a user would be paid, from the relay and user counts. */
    void UpdatePay();

    BpsRpc& m_rpc;
    ClientModel* m_client_model{nullptr};

    QLabel* m_issued{nullptr};
    QLabel* m_relays{nullptr};
    QLabel* m_users{nullptr};
    QLabel* m_per_relay{nullptr};
    QLabel* m_share{nullptr};
    QLabel* m_own_payout{nullptr};

    int m_display_unit{0};
    qint64 m_subsidy{-1};  //!< satoshi per block, -1 until known
    int m_listed{-1};      //!< peers in the live roster
    int m_relay_count{-1}; //!< of those, the ones this node would route through

    QLabel* m_state{nullptr};
    QLabel* m_listening{nullptr};
    QLabel* m_paths{nullptr};
    QLabel* m_introductions{nullptr};
    QLabel* m_candidates{nullptr};
    QLabel* m_epoch{nullptr};
    QLabel* m_off_note{nullptr};
    QListWidget* m_guards{nullptr};
    QListWidget* m_rendezvous{nullptr};
    QTimer* m_timer{nullptr};
};

#endif // BITCOIN_QT_BPS_OVERLAYPAGE_H
