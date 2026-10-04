// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_DISCOVERYPAGE_H
#define BITCOIN_QT_BPS_DISCOVERYPAGE_H

#include <QWidget>

class BpsRpc;
class ClientModel;
class RosterModel;
class UniValue;
class WalletController;

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QSortFilterProxyModel;
class QTableView;
class QTimer;
QT_END_NAMESPACE

/**
 * The page this client exists for: who is on the chain-anchored roster, and
 * whether you are one of them.
 *
 * Three questions, in the order somebody actually asks them. Is the index
 * running - because without it there is nothing to show. Am I listed, and until
 * when. And who else is out there.
 *
 * Everything here is a view over getrosterinfo, getrosterhistory and getroster.
 * There is no second copy of the roster in the GUI and no second opinion about
 * what a listing means.
 */
class DiscoveryPage : public QWidget
{
    Q_OBJECT

public:
    DiscoveryPage(BpsRpc& rpc, QWidget* parent = nullptr);

    void setClientModel(ClientModel* model);
    /** The open wallets, so publishing can offer them as payers. Null without a wallet. */
    void setWalletController(WalletController* controller) { m_wallets = controller; }

Q_SIGNALS:
    /** Whether this node is listed, and until when, as one short phrase. */
    void listingChanged(const QString& summary, bool listed);

public Q_SLOTS:
    /** Ask the node for everything on this page. Cheap to call; answers are async. */
    void Refresh();

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);
    void onPublishClicked();
    void onCopyKey();

private:
    void UpdateListingSummary();

    BpsRpc& m_rpc;
    ClientModel* m_client_model{nullptr};
    WalletController* m_wallets{nullptr};

    QLabel* m_index_state{nullptr};
    QLabel* m_listing_state{nullptr};
    QLabel* m_roster_size{nullptr};
    QLabel* m_key{nullptr};
    QLabel* m_error{nullptr};
    QPushButton* m_copy_key{nullptr};
    QPushButton* m_publish{nullptr};
    QTableView* m_table{nullptr};
    RosterModel* m_model{nullptr};
    QSortFilterProxyModel* m_proxy{nullptr};
    QTimer* m_timer{nullptr};

    QString m_own_key;
    int m_tip{0};
    int m_own_expiry{0}; //!< 0 when this node is not listed
    bool m_index_enabled{false};
};

#endif // BITCOIN_QT_BPS_DISCOVERYPAGE_H
