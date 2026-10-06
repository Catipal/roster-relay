// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_MAILPAGE_H
#define BITCOIN_QT_BPS_MAILPAGE_H

#include <univalue.h>

#include <QDialog>
#include <QString>
#include <QWidget>

#include <memory>

class BpsRpc;
class ClientModel;

namespace interfaces {
class Node;
} // namespace interfaces

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTabBar;
class QTableWidget;
class QTimer;
QT_END_NAMESPACE

/**
 * Mail between roster keys (design note 001, section 11.5).
 *
 * Everything here is an RPC - listmail, readmail, sendmail, checkmail - so this
 * page and a script see the same mail. It has its own RPC thread rather than
 * sharing the window's: sending and collecting build paths through three
 * relays, which takes seconds, and the footer should not wait behind that.
 */
class MailPage : public QWidget
{
    Q_OBJECT

public:
    MailPage(interfaces::Node& node, QWidget* parent = nullptr);
    ~MailPage();

    void setClientModel(ClientModel* model);

Q_SIGNALS:
    /** How many letters are unread, for the navigation to show. */
    void unreadChanged(int unread);

protected:
    /** Opening the page shows what is there now, not what was there at the last tick. */
    void showEvent(QShowEvent* event) override;

public Q_SLOTS:
    void Refresh();

private Q_SLOTS:
    void onResult(const QString& tag, const UniValue& value);
    void onFailed(const QString& tag, const QString& message);
    void onSelection();
    void onWrite();
    void onReply();
    void onCollect();
    void onDelete();
    void onCopyAddress();

private:
    void ShowLetters();
    void ShowLetter(const UniValue& letter);
    void ClearReader();
    void Compose(const QString& to, const QString& subject, const QString& body);
    bool InSent() const;

    std::unique_ptr<BpsRpc> m_rpc;
    ClientModel* m_client_model{nullptr};
    bool m_enabled{false};
    QString m_address;
    UniValue m_letters;
    QString m_selected;
    //! What the last collection found, shown until the next one.
    QString m_note;

    QLabel* m_address_label{nullptr};
    QPushButton* m_copy{nullptr};
    QLabel* m_status{nullptr};
    QLabel* m_off{nullptr};
    QTabBar* m_folders{nullptr};
    QTableWidget* m_list{nullptr};
    QLabel* m_reader_head{nullptr};
    QPlainTextEdit* m_reader{nullptr};
    QPushButton* m_write{nullptr};
    QPushButton* m_reply{nullptr};
    QPushButton* m_collect{nullptr};
    QPushButton* m_delete{nullptr};
    QTimer* m_timer{nullptr};
};

/** Writing a letter. Sends through the page's RPC thread and says how it went. */
class ComposeDialog : public QDialog
{
    Q_OBJECT

public:
    ComposeDialog(BpsRpc& rpc, const QString& to, const QString& subject, const QString& body,
                  QWidget* parent = nullptr);

Q_SIGNALS:
    void sent();

private Q_SLOTS:
    void onSend();
    void onResult(const QString& tag, const UniValue& value);
    void onFailed(const QString& tag, const QString& message);

private:
    BpsRpc& m_rpc;
    QString m_tag;
    QLineEdit* m_to{nullptr};
    QLineEdit* m_subject{nullptr};
    QPlainTextEdit* m_body{nullptr};
    QLabel* m_status{nullptr};
    QPushButton* m_send{nullptr};
};

#endif // BITCOIN_QT_BPS_MAILPAGE_H
