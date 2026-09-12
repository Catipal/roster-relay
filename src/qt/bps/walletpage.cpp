// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/bps/walletpage.h>

#include <qt/clientmodel.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <qt/walletview.h>

#include <QAction>
#include <QComboBox>
#include <QFont>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QStackedWidget>
#include <QToolButton>
#include <QVBoxLayout>
#include <QVariant>

namespace {
//! Which WalletView page a section button drives.
enum Section {
    SEC_OVERVIEW = 0,
    SEC_SEND,
    SEC_RECEIVE,
    SEC_TRANSACTIONS,
    SEC_STAKING,
};
} // namespace

WalletPage::WalletPage(const PlatformStyle* platform_style, QWidget* parent)
    : QWidget(parent), m_platform_style(platform_style)
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(8);

    QLabel* title = new QLabel(tr("Wallet"), this);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);

    m_wallet_select = new QComboBox(this);
    m_wallet_select->setVisible(false);
    connect(m_wallet_select, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, &WalletPage::onWalletSelected);

    m_lock = new QPushButton(this);
    m_lock->setVisible(false);

    QHBoxLayout* head = new QHBoxLayout();
    head->addWidget(title);
    head->addSpacing(16);
    head->addWidget(m_wallet_select);
    head->addStretch(1);
    head->addWidget(m_lock);
    outer->addLayout(head);

    // --- the sections, in the order somebody works through them ----------
    QHBoxLayout* tabs = new QHBoxLayout();
    tabs->setSpacing(2);

    const struct { Section section; const char* label; } kSections[] = {
        {SEC_OVERVIEW, QT_TR_NOOP("Overview")},
        {SEC_SEND, QT_TR_NOOP("Send")},
        {SEC_RECEIVE, QT_TR_NOOP("Receive")},
        {SEC_TRANSACTIONS, QT_TR_NOOP("Transactions")},
        {SEC_STAKING, QT_TR_NOOP("Staking")},
    };
    for (size_t i = 0; i < sizeof(kSections) / sizeof(kSections[0]); ++i) {
        QToolButton* button = new QToolButton(this);
        button->setText(tr(kSections[i].label));
        button->setCheckable(true);
        button->setAutoExclusive(true);
        button->setProperty("section", (int)kSections[i].section);
        button->setToolButtonStyle(Qt::ToolButtonTextOnly);
        connect(button, &QToolButton::clicked, this, &WalletPage::onSectionClicked);
        m_sections.append(button);
        tabs->addWidget(button);
    }
    m_sections.first()->setChecked(true);

    QFrame* divider = new QFrame(this);
    divider->setFrameShape(QFrame::VLine);
    divider->setFrameShadow(QFrame::Sunken);
    tabs->addSpacing(8);
    tabs->addWidget(divider);
    tabs->addSpacing(8);

    // Keys sit beside the pages rather than inside them, because the address
    // books and the passphrase dialogs are dialogs in this codebase and
    // pretending otherwise would mean reimplementing them.
    m_keys = new QToolButton(this);
    m_keys->setText(tr("Keys"));
    m_keys->setPopupMode(QToolButton::InstantPopup);
    m_keys->setToolButtonStyle(Qt::ToolButtonTextOnly);
    QMenu* keys_menu = new QMenu(m_keys);

    // addAction(text, context, functor) is Qt 5.6; this tree still declares
    // 5.5.1 as its minimum, so the action and the connection stay separate.
    QAction* act = keys_menu->addAction(tr("My receiving addresses\xe2\x80\xa6"));
    connect(act, &QAction::triggered, this, [this] {
        if (Current()) Current()->usedReceivingAddresses();
    });
    act = keys_menu->addAction(tr("Addresses I have sent to\xe2\x80\xa6"));
    connect(act, &QAction::triggered, this, [this] {
        if (Current()) Current()->usedSendingAddresses();
    });

    keys_menu->addSeparator();

    act = keys_menu->addAction(tr("Back up this wallet\xe2\x80\xa6"));
    connect(act, &QAction::triggered, this, [this] {
        if (Current()) Current()->backupWallet();
    });
    act = keys_menu->addAction(tr("Encrypt this wallet\xe2\x80\xa6"));
    connect(act, &QAction::triggered, this, [this] {
        if (Current()) Current()->encryptWallet(true);
    });
    act = keys_menu->addAction(tr("Change the passphrase\xe2\x80\xa6"));
    connect(act, &QAction::triggered, this, [this] {
        if (Current()) Current()->changePassphrase();
    });

    keys_menu->addSeparator();

    act = keys_menu->addAction(tr("Sign a message\xe2\x80\xa6"));
    connect(act, &QAction::triggered, this, [this] {
        if (Current()) Current()->gotoSignMessageTab();
    });
    act = keys_menu->addAction(tr("Verify a message\xe2\x80\xa6"));
    connect(act, &QAction::triggered, this, [this] {
        if (Current()) Current()->gotoVerifyMessageTab();
    });

    m_keys->setMenu(keys_menu);
    tabs->addWidget(m_keys);

    tabs->addStretch(1);
    outer->addLayout(tabs);

    // --- the wallet itself -------------------------------------------------
    m_stack = new QStackedWidget(this);

    m_no_wallet = new QLabel(
        tr("No wallet is open.\n\n"
           "This client can publish and renew listings without one, but paying the "
           "fee for a listing needs a wallet. Open or create one in the core wallet "
           "client and it will appear here."),
        m_stack);
    m_no_wallet->setAlignment(Qt::AlignCenter);
    m_no_wallet->setWordWrap(true);
    m_stack->addWidget(m_no_wallet);

    outer->addWidget(m_stack, 1);

    UpdateChrome();
}

void WalletPage::setClientModel(ClientModel* client_model)
{
    m_client_model = client_model;
    for (QMap<WalletModel*, WalletView*>::iterator it = m_views.begin(); it != m_views.end(); ++it) {
        it.value()->setClientModel(client_model);
    }
}

void WalletPage::setWalletController(WalletController* controller)
{
    m_controller = controller;
    if (!controller) return;

    connect(controller, &WalletController::walletAdded, this, &WalletPage::addWallet);
    connect(controller, &WalletController::walletRemoved, this, &WalletPage::removeWallet);

    // Wallets opened before this page existed - the usual case, since the
    // controller is built as soon as the node finishes starting.
    const std::vector<WalletModel*> open = controller->getOpenWallets();
    for (size_t i = 0; i < open.size(); ++i) addWallet(open[i]);
}

WalletView* WalletPage::Current() const
{
    return qobject_cast<WalletView*>(m_stack->currentWidget());
}

void WalletPage::addWallet(WalletModel* wallet_model)
{
    if (!wallet_model || !m_client_model) return;
    if (m_views.count(wallet_model) > 0) return;

    WalletView* view = new WalletView(m_platform_style, this);
    view->setClientModel(m_client_model);
    view->setWalletModel(wallet_model);
    view->setPrivacy(false);
    view->gotoOverviewPage();

    // The wallet pages report through the window's message box like everything
    // else, rather than owning a second notification path.
    connect(view, &WalletView::message, this, &WalletPage::message);
    connect(view, &WalletView::encryptionStatusChanged, this, &WalletPage::onEncryptionStatusChanged);

    m_views[wallet_model] = view;
    m_stack->addWidget(view);
    m_wallet_select->addItem(wallet_model->getDisplayName(),
                             QVariant::fromValue((void*)wallet_model));

    if (m_views.size() == 1) {
        m_stack->setCurrentWidget(view);
        m_wallet_select->setCurrentIndex(0);
        ApplyCheckedSection();
    }
    UpdateChrome();
}

void WalletPage::removeWallet(WalletModel* wallet_model)
{
    QMap<WalletModel*, WalletView*>::iterator it = m_views.find(wallet_model);
    if (it == m_views.end()) return;

    WalletView* view = it.value();
    m_views.erase(it);

    for (int i = 0; i < m_wallet_select->count(); ++i) {
        if (m_wallet_select->itemData(i).value<void*>() == (void*)wallet_model) {
            m_wallet_select->removeItem(i);
            break;
        }
    }

    m_stack->removeWidget(view);
    delete view;

    if (m_views.isEmpty()) m_stack->setCurrentWidget(m_no_wallet);
    UpdateChrome();
}

void WalletPage::onWalletSelected(int index)
{
    if (index < 0) return;
    WalletModel* model = (WalletModel*)m_wallet_select->itemData(index).value<void*>();
    QMap<WalletModel*, WalletView*>::const_iterator it = m_views.constFind(model);
    if (it == m_views.constEnd()) return;

    m_stack->setCurrentWidget(it.value());
    ApplyCheckedSection();
    UpdateChrome();
}

void WalletPage::onSectionClicked()
{
    QObject* sender_object = sender();
    if (!sender_object) return;
    GoTo(sender_object->property("section").toInt());
}

void WalletPage::GoTo(int section)
{
    WalletView* view = Current();
    if (!view) return;

    // Through the named slots rather than by index. WalletView's own page order
    // is not the order of the buttons above, and depending on it here would tie
    // this file to an internal detail of a file it does not own.
    switch (section) {
    case SEC_OVERVIEW: view->gotoOverviewPage(); break;
    case SEC_SEND: view->gotoSendCoinsPage(); break;
    case SEC_RECEIVE: view->gotoReceiveCoinsPage(); break;
    case SEC_TRANSACTIONS: view->gotoHistoryPage(); break;
    case SEC_STAKING: view->gotoStakePage(); break;
    default: break;
    }
}

void WalletPage::ApplyCheckedSection()
{
    // Switching wallets should not move the operator to a different section.
    int section = SEC_OVERVIEW;
    for (int i = 0; i < m_sections.size(); ++i) {
        if (m_sections[i]->isChecked()) {
            section = m_sections[i]->property("section").toInt();
            break;
        }
    }
    GoTo(section);
}

void WalletPage::onEncryptionStatusChanged()
{
    UpdateChrome();
}

void WalletPage::UpdateChrome()
{
    const bool have_wallet = !m_views.isEmpty();

    m_wallet_select->setVisible(m_views.size() > 1);
    m_keys->setEnabled(have_wallet);
    for (int i = 0; i < m_sections.size(); ++i) m_sections[i]->setEnabled(have_wallet);

    if (!have_wallet) {
        m_lock->setVisible(false);
        return;
    }

    WalletModel* model = nullptr;
    const int index = m_wallet_select->currentIndex();
    if (index >= 0) model = (WalletModel*)m_wallet_select->itemData(index).value<void*>();
    if (!model) {
        m_lock->setVisible(false);
        return;
    }

    // Disconnect first: this runs again on every wallet change, and a button
    // that accumulated one connection per call would lock a wallet repeatedly.
    m_lock->disconnect();

    switch (model->getEncryptionStatus()) {
    case WalletModel::Unencrypted:
        m_lock->setVisible(false);
        break;
    case WalletModel::Locked:
        m_lock->setVisible(true);
        m_lock->setText(tr("Locked \xe2\x80\x94 unlock\xe2\x80\xa6"));
        connect(m_lock, &QPushButton::clicked, this, [this] {
            if (Current()) Current()->unlockWallet(false);
        });
        break;
    case WalletModel::Unlocked:
        m_lock->setVisible(true);
        m_lock->setText(tr("Unlocked \xe2\x80\x94 lock"));
        connect(m_lock, &QPushButton::clicked, this, [this] {
            if (Current()) Current()->lockWallet();
        });
        break;
    }
}
