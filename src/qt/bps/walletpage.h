// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_WALLETPAGE_H
#define BITCOIN_QT_BPS_WALLETPAGE_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <QList>
#include <QMap>
#include <QWidget>

class ClientModel;
class PlatformStyle;
class WalletController;
class WalletModel;
class WalletView;

QT_BEGIN_NAMESPACE
class QComboBox;
class QLabel;
class QPushButton;
class QStackedWidget;
class QToolButton;
QT_END_NAMESPACE

/**
 * Coins, keys and staking, for the discovery client.
 *
 * Not a second wallet. The pages inside are qt/walletview.cpp exactly as the
 * wallet client uses them - overview, send, receive, transactions, staking and
 * both address books - so every fix made to any of them lands here by
 * rebuilding. What this file adds is the frame: which wallet is showing, how to
 * move between its pages, and the lock state, none of which the wallet client
 * could lend because its versions of those live in BitcoinGUI's menus and
 * toolbar.
 *
 * WalletFrame was the obvious thing to reuse and cannot be: it takes a
 * BitcoinGUI* and calls back into it. WalletView, one level down, takes only a
 * PlatformStyle - which is why the split lands here rather than higher up.
 */
class WalletPage : public QWidget
{
    Q_OBJECT

public:
    explicit WalletPage(const PlatformStyle* platform_style, QWidget* parent = nullptr);

    void setClientModel(ClientModel* client_model);
    void setWalletController(WalletController* controller);

Q_SIGNALS:
    /** Something the operator should see, forwarded to the window. */
    void message(const QString& title, const QString& message, unsigned int style);

private Q_SLOTS:
    void addWallet(WalletModel* wallet_model);
    void removeWallet(WalletModel* wallet_model);
    void onWalletSelected(int index);
    void onSectionClicked();
    void onEncryptionStatusChanged();

private:
    WalletView* Current() const;
    void UpdateChrome();

    /** Show one section of the current wallet. Takes a Section, not a page index. */
    void GoTo(int section);
    /** Re-apply whichever section button is checked, after the wallet changes. */
    void ApplyCheckedSection();

    const PlatformStyle* m_platform_style;
    ClientModel* m_client_model{nullptr};
    WalletController* m_controller{nullptr};

    QComboBox* m_wallet_select{nullptr};
    QLabel* m_no_wallet{nullptr};
    QStackedWidget* m_stack{nullptr};
    QMap<WalletModel*, WalletView*> m_views;

    //! Section buttons, in the order they appear. The value carried by each is
    //! the WalletView slot it drives.
    QList<QToolButton*> m_sections;
    QToolButton* m_keys{nullptr};
    QPushButton* m_lock{nullptr};
};

#endif // BITCOIN_QT_BPS_WALLETPAGE_H
