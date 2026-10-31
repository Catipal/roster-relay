// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_COMPANIONDIALOGS_H
#define BITCOIN_QT_BPS_COMPANIONDIALOGS_H

#include <amount.h>

#include <QDialog>

class BitcoinAmountField;
class BpsRpc;
class UniValue;

QT_BEGIN_NAMESPACE
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QStackedWidget;
class QTimer;
QT_END_NAMESPACE

/**
 * Pairing a phone, start to finish: the ticket as a QR code and as text, then
 * - once a phone has answered it - the six digits the phone should be showing
 * and the limits it will be held to, and nothing paired until both are agreed.
 *
 * The digits are the point. Anyone who sees the ticket could answer it first;
 * their phone would show different digits from the ones here, and the right
 * answer to that is Reject.
 */
class CompanionPairDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CompanionPairDialog(BpsRpc& rpc, QWidget* parent = nullptr);

private Q_SLOTS:
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);
    void NewTicket();
    void Poll();
    void Accept();
    void Reject();
    void UpdateAcceptable();

private:
    void ShowExpired();

    BpsRpc& m_rpc;
    QString m_token;
    qint64 m_expires{0};
    bool m_answered{false};

    QStackedWidget* m_steps{nullptr};
    QLabel* m_qr{nullptr};
    QPlainTextEdit* m_ticket{nullptr};
    QLabel* m_wait{nullptr};
    QPushButton* m_again{nullptr};

    QLabel* m_who{nullptr};
    QLabel* m_code{nullptr};
    BitcoinAmountField* m_per_tx{nullptr};
    BitcoinAmountField* m_per_day{nullptr};
    QLabel* m_error{nullptr};
    QPushButton* m_accept{nullptr};
    QPushButton* m_reject{nullptr};

    QLabel* m_done{nullptr};
    QTimer* m_timer{nullptr};
};

/** What a paired phone may spend: one payment, and any 24 hours. */
class CompanionLimitsDialog : public QDialog
{
    Q_OBJECT

public:
    CompanionLimitsDialog(const QString& phone, CAmount per_tx, CAmount per_day, QWidget* parent = nullptr);

    CAmount PerTx() const;
    CAmount PerDay() const;

private Q_SLOTS:
    void Check();

private:
    BitcoinAmountField* m_per_tx{nullptr};
    BitcoinAmountField* m_per_day{nullptr};
    QLabel* m_error{nullptr};
    QPushButton* m_ok{nullptr};
};

#endif // BITCOIN_QT_BPS_COMPANIONDIALOGS_H
