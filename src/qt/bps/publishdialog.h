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
#include <stdint.h>

class BpsRpc;
class UniValue;
class WalletController;

QT_BEGIN_NAMESPACE
class QCheckBox;
class QComboBox;
class QDialogButtonBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QWidget;
QT_END_NAMESPACE

/**
 * Publishing or renewing this node's listing.
 *
 * A listing made here never carries an address: it says who you are and not
 * where you run (design note 001 §0·5), and peers meet you through the
 * overlay. What it may carry instead is a note, a line of text shown beside
 * the key in everyone's roster. An address can still be published with
 * createannouncement, for an onion service or a test network; this dialog
 * does not offer it, since the chain keeps it for good.
 *
 * Who pays the fee has two answers. A wallet with coins pays, through
 * createannouncement and publishrecord. A node with none asks its relay to pay,
 * through requestlisting - which is the settled model (§8): the user signs, the
 * relay pays. The dialog duplicates none of the node's checks; the record is
 * verified before any coin is spent, by whoever spends it.
 */
class PublishDialog : public QDialog
{
    Q_OBJECT

public:
    /** `note` is the current listing's note, offered again when renewing. */
    PublishDialog(BpsRpc& rpc, WalletController* wallets, int tip, bool renewing,
                  const QString& note, QWidget* parent = nullptr);
    ~PublishDialog();

Q_SIGNALS:
    /** A record reached a mempool. Carries the transaction id and who paid. */
    void published(const QString& txid, bool by_relay);

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);
    void onNoteChanged();
    void onPayerChanged();
    void onPublish();

private:
    void FillPayers();
    void SetBusy(bool busy);
    void ShowError(const QString& message);
    bool RelayChosen() const;
    /** The note and expiry options both RPCs take. False with an error shown. */
    bool BuildOptions(UniValue& options);
    void Done();
    /** Blocks a listing must be able to wait for this node to stake it; 0 if it never would. */
    uint32_t OwnConfirmWindow(bool& staking) const;

    BpsRpc& m_rpc;
    WalletController* m_wallets;
    const int m_tip;

    bool m_overlay_on{false};
    int m_relays{-1}; //!< relays this node could ask, -1 until known

    QLineEdit* m_note{nullptr};
    QLabel* m_note_count{nullptr}; //!< bytes used of the note's room
    bool m_note_fits{true};
    QComboBox* m_payer{nullptr};
    QComboBox* m_length{nullptr};    //!< a month or a year, when this node pays
    QLabel* m_length_fixed{nullptr}; //!< a month, when a relay pays
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
