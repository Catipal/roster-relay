// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_SERVERPAGE_H
#define BITCOIN_QT_BPS_SERVERPAGE_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <QWidget>

class BpsRpc;
class ClientModel;
class UniValue;
class WalletController;

QT_BEGIN_NAMESPACE
class QCheckBox;
class QGridLayout;
class QLabel;
class QLineEdit;
class QSpinBox;
class QTimer;
QT_END_NAMESPACE

/**
 * What this node offers other people.
 *
 * Two services run today: relaying - paying for the listings of peers that use
 * this node and sharing its staking rewards with them - and holding sealed mail
 * for the people the roster makes this node a mailbox for. Their controls live
 * here rather than in Settings because they are what an operator runs, not how
 * the client behaves. The services still to come - names and hosting - are
 * shown for what they are, not built yet, so the page says where the project
 * is going without claiming anything it cannot do.
 *
 * Like Settings, the relay controls are startup arguments in the node, stored
 * in QSettings and soft-set at startup, so the command line and config file
 * still win and a change takes effect at the next start.
 */
class ServerPage : public QWidget
{
    Q_OBJECT

public:
    explicit ServerPage(BpsRpc& rpc, QWidget* parent = nullptr);

    void setClientModel(ClientModel* model);
    /** The open wallets, to say whether this node is staking. Lives until shutdown. */
    void setWalletController(WalletController* controller);

    /** Read the stored relay settings into the argument list, before the node starts. */
    static void ApplyStoredSettings();

public Q_SLOTS:
    void Refresh();

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);
    void onChanged();

private:
    QWidget* MakeRelayCard();
    QWidget* MakeMailboxCard();
    void Load();
    void UpdateStaking();

    BpsRpc& m_rpc;
    ClientModel* m_client_model{nullptr};
    WalletController* m_wallets{nullptr};
    bool m_loading{false};

    QLabel* m_relay_badge{nullptr};
    QLabel* m_staking{nullptr};
    QLabel* m_users{nullptr};
    QLabel* m_payout{nullptr};
    QCheckBox* m_acceptlistings{nullptr};
    QSpinBox* m_maxlistedusers{nullptr};
    QLineEdit* m_listingwallet{nullptr};
    QSpinBox* m_relayshare{nullptr};
    QLabel* m_restart_note{nullptr};

    QLabel* m_mailbox_badge{nullptr};
    QLabel* m_mailbox_holding{nullptr};
    QLabel* m_mailbox_keys{nullptr};
    QCheckBox* m_mailbox{nullptr};
    QSpinBox* m_mailbox_size{nullptr};
    QLabel* m_mailbox_note{nullptr};
    QTimer* m_timer{nullptr};
};

#endif // BITCOIN_QT_BPS_SERVERPAGE_H
