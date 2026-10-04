// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_PUBLISHDIALOG_H
#define BITCOIN_QT_BPS_PUBLISHDIALOG_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#ifdef ENABLE_WALLET
#include <qt/walletmodel.h>
#endif

#include <QDialog>
#include <QString>

#include <memory>

class BpsRpc;
class UniValue;
class WalletController;

QT_BEGIN_NAMESPACE
class QComboBox;
class QDialogButtonBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QRadioButton;
class QSpinBox;
class QWidget;
QT_END_NAMESPACE

/**
 * Publishing or renewing this node's listing.
 *
 * Two decisions: where peers may reach you, and who pays the fee.
 *
 * The first is the one design note 001 §0·5 cares about. A listing with no
 * address at all is legal, useful, and the private option - it puts an identity
 * in the roster without telling anyone where that identity runs. It is offered
 * as a peer of the others rather than buried, because a privacy choice nobody
 * can find is not a choice.
 *
 * The second has two answers. A wallet with coins pays, through
 * createannouncement and publishrecord. A node with none asks its relay to pay,
 * through requestlisting - which is the settled model (§8): the user signs, the
 * relay pays. The dialog duplicates none of the node's checks; the record is
 * verified before any coin is spent, by whoever spends it.
 */
class PublishDialog : public QDialog
{
    Q_OBJECT

public:
    PublishDialog(BpsRpc& rpc, WalletController* wallets, int tip, bool renewing,
                  QWidget* parent = nullptr);
    ~PublishDialog();

Q_SIGNALS:
    /** A record reached a mempool. Carries the transaction id and who paid. */
    void published(const QString& txid, bool by_relay);

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);
    void onAddressChoiceChanged();
    void onPayerChanged();
    void onPublish();

private:
    void FillPayers();
    void SetBusy(bool busy);
    void ShowError(const QString& message);
    bool RelayChosen() const;
    /** The endpoint and expiry options both RPCs take. False with an error shown. */
    bool BuildOptions(UniValue& options);
    void Done();

    BpsRpc& m_rpc;
    WalletController* m_wallets;
    const int m_tip;

    bool m_overlay_on{false};
    int m_relays{-1}; //!< relays this node could ask, -1 until known

    QRadioButton* m_at_address{nullptr};
    QRadioButton* m_nowhere{nullptr};
    QWidget* m_address_row{nullptr};
    QComboBox* m_network{nullptr};
    QLineEdit* m_address{nullptr};
    QSpinBox* m_port{nullptr};
    QComboBox* m_payer{nullptr};
    QLabel* m_payer_note{nullptr};
    QLabel* m_status{nullptr};
    QDialogButtonBox* m_buttons{nullptr};
    QPushButton* m_publish{nullptr};

#ifdef ENABLE_WALLET
    //! Held from the passphrase prompt until the fee is paid, so the wallet is
    //! unlocked for exactly as long as publishing takes.
    std::unique_ptr<WalletModel::UnlockContext> m_unlock;
#endif
};

#endif // BITCOIN_QT_BPS_PUBLISHDIALOG_H
