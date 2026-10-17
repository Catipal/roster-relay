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
class QPushButton;
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

    /**
     * What the owner chose here for relaying and the gateway, saved or as the
     * node runs: settings of the node, which a listing takes over when it is
     * published, not choices made with each listing.
     */
    static bool RelaySwitchedOn();
    static bool GatewaySwitchedOn();

    /**
     * The first time the client starts, say plainly what sharing the internet
     * connection means, and let the owner switch it off before the node
     * starts (design note section 8.7). Not asked again, and not asked when
     * -gateway was given on the command line or in the config file.
     */
    static void AskAboutGatewayOnce();

public Q_SLOTS:
    void Refresh();

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);
    void onChanged();
    void onListGateway();
    void onInstallNetService();

private:
    QWidget* MakeRelayCard();
    QCheckBox* m_relay{nullptr};    //!< carry others' paths as a relay (-relay)
    QWidget* MakeMailboxCard();
    QWidget* MakeGatewayCard();
    void ShowGateway(const UniValue& value);
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
    QLabel* m_announced{nullptr}; //!< where this relay announces it is, if it does
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

    QLabel* m_gateway_badge{nullptr};
    QLabel* m_gateway_state{nullptr};
    QLabel* m_gateway_key{nullptr};
    QLabel* m_gateway_today{nullptr};
    QLabel* m_gateway_now{nullptr};
    QPushButton* m_gateway_list{nullptr};
    QCheckBox* m_gateway{nullptr};
    QSpinBox* m_gateway_budget{nullptr};
    QCheckBox* m_proxy{nullptr};
    QLabel* m_proxy_status{nullptr};
    QCheckBox* m_interface{nullptr};    //!< all of this computer's traffic through the network
    QLabel* m_interface_status{nullptr};
    QPushButton* m_interface_setup{nullptr}; //!< Windows: install the network service
    QLabel* m_gateway_note{nullptr};
    bool m_own_address{false};
    QTimer* m_timer{nullptr};
};

#endif // BITCOIN_QT_BPS_SERVERPAGE_H
