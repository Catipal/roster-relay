// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_PUBLISHDIALOG_H
#define BITCOIN_QT_BPS_PUBLISHDIALOG_H

#include <QDialog>
#include <QString>

class BpsRpc;
class UniValue;

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
 * Two decisions and nothing else: where peers may reach you, and for how long.
 *
 * The first of those is the one design note 001 §0·5 cares about. A listing
 * with no address at all is legal, useful, and the private option - it puts an
 * identity in the roster without telling anyone where that identity runs. It is
 * offered here as a peer of the others rather than buried, because a privacy
 * choice nobody can find is not a choice.
 *
 * The work is done by createannouncement and publishrecord, in that order. This
 * dialog fills in their arguments and reports what they say. It duplicates none
 * of their checks - in particular the record is verified by the node before any
 * coin is spent, so a mistake here costs nothing.
 */
class PublishDialog : public QDialog
{
    Q_OBJECT

public:
    PublishDialog(BpsRpc& rpc, int tip, bool renewing, QWidget* parent = nullptr);

Q_SIGNALS:
    /** A record reached the mempool. Carries the transaction id. */
    void published(const QString& txid);

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);
    void onAddressChoiceChanged();
    void onPublish();

private:
    void SetBusy(bool busy);
    void ShowError(const QString& message);

    BpsRpc& m_rpc;
    const int m_tip;

    QRadioButton* m_at_address{nullptr};
    QRadioButton* m_nowhere{nullptr};
    QWidget* m_address_row{nullptr};
    QComboBox* m_network{nullptr};
    QLineEdit* m_address{nullptr};
    QSpinBox* m_port{nullptr};
    QComboBox* m_duration{nullptr};
    QComboBox* m_wallet{nullptr};
    QLabel* m_status{nullptr};
    QDialogButtonBox* m_buttons{nullptr};
    QPushButton* m_publish{nullptr};
};

#endif // BITCOIN_QT_BPS_PUBLISHDIALOG_H
