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
class QTableWidget;
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
     * Whether the owner switched relaying on here, saved or as the node runs:
     * a setting of the node, which a listing takes over when it is published,
     * not a choice made with each listing.
     */
    static bool RelaySwitchedOn();

    /**
     * The first time the client starts, say plainly what sharing the internet
     * connection means, and let the owner switch it off before the node
     * starts (design note section 8.7). Not asked again, and not asked when
     * -gateway was given on the command line or in the config file.
     */
    static void AskAboutGatewayOnce();
public Q_SLOTS:
    void Refresh();

Q_SIGNALS:
    /** Show a site in the Sites page. */
    void openSite(const QString& address);
    /** Open the wallet's Send tab, to pay `address` - the allowance wallet's. */
    void topUpRequested(const QString& address);

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);
    void onChanged();
    void onInstallNetService();
    void onPublishSite();
    void onRepublishSite();
    void onStopSite();
    void onPublishService();
    void onStopService();
    void onPairPhone();
    void onCreateAllowance();
    void onTopUp();
    void onDeviceLimits();
    void onDeviceUnlock();
    void onDeviceRevoke();
    void onDeviceSelected();

private:
    QWidget* MakeRelayCard();
    QCheckBox* m_relay{nullptr};    //!< carry others' paths as a relay (-relay)
    QWidget* MakeMailboxCard();
    QWidget* MakeGatewayCard();
    QWidget* MakeHostingCard();
    void ShowGateway(const UniValue& value);
    void ShowHosting(const UniValue& value);
    void ShowServices(const UniValue& value);
    QWidget* MakeCompanionCard();
    void Load();
    void UpdateStaking();
    void ShowCompanion(const UniValue& info);
    void ShowDevices(const UniValue& devices);
    /** The selected phone's device key, or empty. */
    QString SelectedDevice() const;
    /** The allowance wallet's name as the node runs it, or as the field says. */
    QString AllowanceName() const;

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
    QLabel* m_gateway_today{nullptr};
    QLabel* m_gateway_now{nullptr};
    QCheckBox* m_gateway{nullptr};
    QSpinBox* m_gateway_budget{nullptr};
    QLabel* m_proxy_status{nullptr};
    QLabel* m_interface_status{nullptr};
    QPushButton* m_interface_setup{nullptr}; //!< Windows: install the network service
    QLabel* m_gateway_note{nullptr};

    QLabel* m_hosting_badge{nullptr};
    QLabel* m_hosting_folder{nullptr};
    QLabel* m_hosting_reached{nullptr};
    QLabel* m_hosting_sent{nullptr};
    QPushButton* m_hosting_publish{nullptr};
    QPushButton* m_hosting_again{nullptr};
    QPushButton* m_hosting_stop{nullptr};
    QPushButton* m_hosting_open{nullptr};
    QLabel* m_hosting_note{nullptr};
    QLabel* m_services{nullptr};
    QStringList m_service_names;
    QString m_hosting_dir;   //!< the folder published, to publish again
    QString m_own_key;       //!< this node's roster key, the site's address
    QLabel* m_companion_badge{nullptr};
    QLabel* m_companion_wallet_state{nullptr};
    QLabel* m_companion_reach{nullptr};
    QCheckBox* m_companion{nullptr};
    QLineEdit* m_companion_wallet{nullptr};
    QPushButton* m_companion_create{nullptr};
    QPushButton* m_companion_topup{nullptr};
    QPushButton* m_companion_pair{nullptr};
    QTableWidget* m_companion_devices{nullptr};
    QPushButton* m_companion_limits{nullptr};
    QPushButton* m_companion_unlock{nullptr};
    QPushButton* m_companion_revoke{nullptr};
    QLabel* m_companion_note{nullptr};
    bool m_companion_running{false};

    QTimer* m_timer{nullptr};
};

#endif // BITCOIN_QT_BPS_SERVERPAGE_H
