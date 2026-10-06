// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_NAMESPAGE_H
#define BITCOIN_QT_BPS_NAMESPAGE_H

#include <univalue.h>

#include <QString>
#include <QStringList>
#include <QWidget>

#include <memory>

class BpsRpc;
class ClientModel;

namespace interfaces {
class Node;
} // namespace interfaces

QT_BEGIN_NAMESPACE
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTimer;
QT_END_NAMESPACE

/**
 * Names (design note 001, section 11): the names this node holds, looking a
 * name up, and this user's own address book of petnames.
 *
 * Everything is an RPC, as on the other pages - registername, renewname,
 * transfername, setsubname, resolvename, setpetname - so the page and a
 * script see the same names. Its own RPC thread, because paying waits on the
 * wallet.
 */
class NamesPage : public QWidget
{
    Q_OBJECT

public:
    NamesPage(interfaces::Node& node, QWidget* parent = nullptr);
    ~NamesPage();

    void setClientModel(ClientModel* model);

public Q_SLOTS:
    void Refresh();

protected:
    void showEvent(QShowEvent* event) override;

private Q_SLOTS:
    void onResult(const QString& tag, const UniValue& value);
    void onFailed(const QString& tag, const QString& message);
    void onRegister();
    void onRenew();
    void onTransfer();
    void onSubname();
    void onLookup();
    void onAddPetname();
    void onRemovePetname();

private:
    void ShowNames();
    void ShowPetnames();
    void UpdateButtons();
    QString SelectedName() const;
    /** The wallet a payment comes from: the only one, or the one chosen. */
    QString WalletUri() const;
    void Pay(const QString& tag, const QString& method, const UniValue& params);

    std::unique_ptr<BpsRpc> m_rpc;
    ClientModel* m_client_model{nullptr};
    bool m_enabled{false};
    bool m_active{false};
    QStringList m_wallets;
    UniValue m_names;
    UniValue m_pending;
    UniValue m_petnames;
    QString m_resolved_key;

    QLabel* m_status{nullptr};
    QLabel* m_off{nullptr};
    QComboBox* m_wallet{nullptr};
    QLabel* m_wallet_caption{nullptr};
    QTableWidget* m_owned{nullptr};
    QPushButton* m_register{nullptr};
    QPushButton* m_renew{nullptr};
    QPushButton* m_transfer{nullptr};
    QPushButton* m_subname{nullptr};
    QLineEdit* m_lookup{nullptr};
    QPushButton* m_lookup_button{nullptr};
    QLabel* m_lookup_result{nullptr};
    QPushButton* m_copy_resolved{nullptr};
    QTableWidget* m_book{nullptr};
    QPushButton* m_add_pet{nullptr};
    QPushButton* m_remove_pet{nullptr};
    QTimer* m_timer{nullptr};
};

#endif // BITCOIN_QT_BPS_NAMESPAGE_H
