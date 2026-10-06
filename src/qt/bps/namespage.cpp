// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/namespage.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/bpsutil.h>
#include <qt/clientmodel.h>

#include <core_io.h>
#include <names/name.h>
#include <util/moneystr.h>

#include <memory>

#include <QApplication>
#include <cstring>
#include <QClipboard>
#include <QComboBox>
#include <QCursor>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFont>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QToolTip>
#include <QUrl>
#include <QVBoxLayout>

namespace {

const char* TAG_INFO = "names:info";
const char* TAG_LIST = "names:list";
const char* TAG_PENDING = "names:pending";
const char* TAG_PETS = "names:pets";
const char* TAG_WALLETS = "names:wallets";
const char* TAG_RESOLVE = "names:resolve";
const char* TAG_LOOKUP_PRICE = "names:lookupprice";

//! Table item data: whether a name of ours is up for sale.
const int ROLE_FOR_SALE = Qt::UserRole + 1;
const char* TAG_PAY = "names:pay:";
const char* TAG_PET = "names:pet:";

const int REFRESH_MS = 20000;

QString Str(const UniValue& v, const char* key)
{
    const UniValue& f = find_value(v, key);
    return f.isStr() ? QString::fromStdString(f.get_str()) : QString();
}

int64_t Num(const UniValue& v, const char* key)
{
    const UniValue& f = find_value(v, key);
    return f.isNum() ? f.get_int64() : 0;
}

QString Coins(CAmount amount)
{
    return QString::fromStdString(FormatMoney(amount)) + " BPS";
}

QLabel* Heading(const QString& text, QWidget* parent)
{
    QLabel* label = new QLabel(text, parent);
    QFont font = label->font();
    font.setBold(true);
    font.setPointSizeF(font.pointSizeF() * 1.15);
    label->setFont(font);
    return label;
}

QTableWidget* Table(const QStringList& headers, QWidget* parent)
{
    QTableWidget* t = new QTableWidget(0, headers.size(), parent);
    t->setHorizontalHeaderLabels(headers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->verticalHeader()->setVisible(false);
    t->setAlternatingRowColors(true);
    t->setShowGrid(false);
    t->setTextElideMode(Qt::ElideMiddle);
    return t;
}

} // namespace

NamesPage::NamesPage(interfaces::Node& node, QWidget* parent) : QWidget(parent), m_rpc(new BpsRpc(node))
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(8);

    QLabel* title = new QLabel(tr("Names"), this);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);
    outer->addWidget(title);

    QLabel* subtitle = new QLabel(
        tr("A name points people to your roster key, so they can write to you by name instead of by key. "
           "A free name costs its renewal, burned - shorter ones cost more - and is renewed by hand. A name "
           "someone holds can be bought if they put it up for sale: the price is the renewal plus what they "
           "ask. Names under yours are free, and so are petnames: your own labels for people, kept on this "
           "computer."),
        this);
    subtitle->setWordWrap(true);
    subtitle->setEnabled(false);
    outer->addWidget(subtitle);

    m_off = new QLabel(this);
    m_off->setWordWrap(true);
    m_off->setStyleSheet("color: #8a3b12; background: #f6e0d3; border-radius: 6px; padding: 8px 10px;");
    m_off->setVisible(false);
    outer->addWidget(m_off);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outer->addWidget(m_status);

    // --- your names -------------------------------------------------------
    QHBoxLayout* own_head = new QHBoxLayout();
    own_head->addWidget(Heading(tr("Your names"), this));
    own_head->addStretch(1);
    m_wallet_caption = new QLabel(tr("Pay from"), this);
    m_wallet = new QComboBox(this);
    m_wallet_caption->setVisible(false);
    m_wallet->setVisible(false);
    own_head->addWidget(m_wallet_caption);
    own_head->addWidget(m_wallet);
    outer->addLayout(own_head);

    m_owned = Table({tr("Name"), tr("Status"), tr("Ends"), tr("Subnames")}, this);
    m_owned->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_owned->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_owned->setMinimumHeight(120);
    outer->addWidget(m_owned, 2);

    QHBoxLayout* own_tools = new QHBoxLayout();
    m_register = new QPushButton(tr("Get a name\xe2\x80\xa6"), this);
    m_renew = new QPushButton(tr("Renew\xe2\x80\xa6"), this);
    m_subname = new QPushButton(tr("Add a subname\xe2\x80\xa6"), this);
    m_sell = new QPushButton(tr("Sell\xe2\x80\xa6"), this);
    m_transfer = new QPushButton(tr("Transfer\xe2\x80\xa6"), this);
    own_tools->addWidget(m_register);
    own_tools->addWidget(m_renew);
    own_tools->addWidget(m_subname);
    own_tools->addStretch(1);
    own_tools->addWidget(m_sell);
    own_tools->addWidget(m_transfer);
    outer->addLayout(own_tools);

    // --- look up -----------------------------------------------------------
    outer->addSpacing(6);
    outer->addWidget(Heading(tr("Look up"), this));
    QHBoxLayout* lookup = new QHBoxLayout();
    m_lookup = new QLineEdit(this);
    m_lookup->setPlaceholderText(tr("a name, label.name or petname"));
    m_lookup_button = new QPushButton(tr("Look up"), this);
    lookup->addWidget(m_lookup, 1);
    lookup->addWidget(m_lookup_button);
    outer->addLayout(lookup);
    QHBoxLayout* result_row = new QHBoxLayout();
    m_lookup_result = new QLabel(this);
    m_lookup_result->setWordWrap(true);
    m_lookup_result->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_copy_resolved = new QPushButton(tr("Copy key"), this);
    m_copy_resolved->setVisible(false);
    result_row->addWidget(m_lookup_result, 1);
    result_row->addWidget(m_copy_resolved);
    outer->addLayout(result_row);

    // --- address book ------------------------------------------------------
    outer->addSpacing(6);
    outer->addWidget(Heading(tr("Address book"), this));
    m_book = Table({tr("Petname"), tr("Key")}, this);
    m_book->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_book->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_book->setMinimumHeight(100);
    outer->addWidget(m_book, 2);
    QHBoxLayout* book_tools = new QHBoxLayout();
    m_add_pet = new QPushButton(tr("Add someone\xe2\x80\xa6"), this);
    m_remove_pet = new QPushButton(tr("Remove"), this);
    book_tools->addWidget(m_add_pet);
    book_tools->addStretch(1);
    book_tools->addWidget(m_remove_pet);
    outer->addLayout(book_tools);

    connect(m_rpc.get(), &BpsRpc::result, this, &NamesPage::onResult);
    connect(m_rpc.get(), &BpsRpc::failed, this, &NamesPage::onFailed);
    connect(m_register, &QPushButton::clicked, this, &NamesPage::onRegister);
    connect(m_renew, &QPushButton::clicked, this, &NamesPage::onRenew);
    connect(m_transfer, &QPushButton::clicked, this, &NamesPage::onTransfer);
    connect(m_subname, &QPushButton::clicked, this, &NamesPage::onSubname);
    connect(m_sell, &QPushButton::clicked, this, &NamesPage::onSell);
    connect(m_lookup_button, &QPushButton::clicked, this, &NamesPage::onLookup);
    connect(m_lookup, &QLineEdit::returnPressed, this, &NamesPage::onLookup);
    connect(m_add_pet, &QPushButton::clicked, this, &NamesPage::onAddPetname);
    connect(m_remove_pet, &QPushButton::clicked, this, &NamesPage::onRemovePetname);
    connect(m_owned, &QTableWidget::itemSelectionChanged, this, &NamesPage::UpdateButtons);
    connect(m_book, &QTableWidget::itemSelectionChanged, this, &NamesPage::UpdateButtons);
    connect(m_copy_resolved, &QPushButton::clicked, this, [this] {
        if (!m_resolved_key.isEmpty()) QApplication::clipboard()->setText(m_resolved_key);
    });
    // A key in the address book is copied by clicking it, as on Discovery.
    connect(m_book, &QTableWidget::cellClicked, this, [this](int row, int column) {
        if (column != 1) return;
        const QTableWidgetItem* item = m_book->item(row, 1);
        if (!item) return;
        QApplication::clipboard()->setText(item->text());
        QToolTip::showText(QCursor::pos(), tr("Key copied") + "\n" + item->text(), m_book);
    });

    m_timer = new QTimer(this);
    m_timer->setInterval(REFRESH_MS);
    connect(m_timer, &QTimer::timeout, this, &NamesPage::Refresh);

    m_names = UniValue(UniValue::VARR);
    m_pending = UniValue(UniValue::VARR);
    m_petnames = UniValue(UniValue::VARR);
    UpdateButtons();
}

NamesPage::~NamesPage() {}

void NamesPage::setClientModel(ClientModel* model)
{
    m_client_model = model;
    if (!model) {
        m_timer->stop();
        return;
    }
    m_timer->start();
    Refresh();
}

void NamesPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    Refresh();
}

void NamesPage::Refresh()
{
    if (!m_client_model) return;
    m_rpc->Call(TAG_INFO, "getnameinfo");
    m_rpc->Call(TAG_PETS, "listpetnames");
    m_rpc->Call(TAG_WALLETS, "listwallets");
}

QString NamesPage::WalletUri() const
{
    QString wallet;
    if (m_wallets.size() == 1) wallet = m_wallets.front();
    else if (m_wallet->currentIndex() >= 0) wallet = m_wallet->currentText();
    if (m_wallets.size() <= 1 && wallet.isEmpty()) return QString();
    return "/wallet/" + QString::fromUtf8(QUrl::toPercentEncoding(wallet));
}

void NamesPage::Pay(const QString& tag, const QString& method, const UniValue& params)
{
    m_status->setText(tr("Working\xe2\x80\xa6"));
    m_rpc->Call(QString(TAG_PAY) + tag, method, params, WalletUri());
}

QString NamesPage::SelectedName() const
{
    const QList<QTableWidgetItem*> items = m_owned->selectedItems();
    if (items.isEmpty()) return QString();
    const QTableWidgetItem* name = m_owned->item(items.first()->row(), 0);
    return name ? name->data(Qt::UserRole).toString() : QString();
}

bool NamesPage::SelectedForSale() const
{
    const QList<QTableWidgetItem*> items = m_owned->selectedItems();
    if (items.isEmpty()) return false;
    const QTableWidgetItem* name = m_owned->item(items.first()->row(), 0);
    return name && name->data(ROLE_FOR_SALE).toBool();
}

void NamesPage::UpdateButtons()
{
    const bool usable = m_enabled && m_active;
    const QString selected = SelectedName();
    m_register->setEnabled(usable);
    m_renew->setEnabled(usable && !selected.isEmpty());
    m_subname->setEnabled(usable && !selected.isEmpty());
    // While a name is up for sale it cannot be given away; the button says why.
    const bool for_sale = SelectedForSale();
    m_sell->setText(for_sale ? tr("Take off sale") : tr("Sell\xe2\x80\xa6"));
    m_sell->setEnabled(usable && !selected.isEmpty());
    m_transfer->setEnabled(usable && !selected.isEmpty() && !for_sale);
    m_transfer->setToolTip(for_sale ? tr("Take it off sale first.") : QString());
    m_lookup_button->setEnabled(m_client_model != nullptr);
    m_remove_pet->setEnabled(!m_book->selectedItems().isEmpty());
}

void NamesPage::onResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_INFO) {
        m_enabled = find_value(value, "enabled").isTrue();
        m_active = find_value(value, "active").isTrue();
        if (!m_enabled) {
            m_off->setText(tr("Names need the name index. Turn on \"Index names\" under Settings and restart."));
        } else if (!m_active) {
            m_off->setText(tr("Names have not started on this network yet. When they start on mainnet, and how "
                              "the first names are given out, is still to be decided. You can look names up and "
                              "keep an address book meanwhile."));
        }
        m_off->setVisible(!m_enabled || !m_active);
        if (m_enabled) {
            m_rpc->Call(TAG_LIST, "listnames");
            m_rpc->Call(TAG_PENDING, "listnameregistrations");
        }
        UpdateButtons();
        return;
    }
    if (tag == TAG_LIST) {
        if (value.isArray()) m_names = value;
        ShowNames();
        return;
    }
    if (tag == TAG_PENDING) {
        if (value.isArray()) m_pending = value;
        ShowNames();
        return;
    }
    if (tag == TAG_PETS) {
        if (value.isArray()) m_petnames = value;
        ShowPetnames();
        return;
    }
    if (tag == TAG_WALLETS) {
        QStringList wallets;
        if (value.isArray()) {
            for (size_t i = 0; i < value.size(); ++i) wallets << QString::fromStdString(value[i].get_str());
        }
        if (wallets != m_wallets) {
            const QString current = m_wallet->currentText();
            m_wallets = wallets;
            m_wallet->clear();
            m_wallet->addItems(wallets);
            if (wallets.contains(current)) m_wallet->setCurrentText(current);
        }
        // Only a choice when there is one to make.
        m_wallet->setVisible(m_wallets.size() > 1);
        m_wallet_caption->setVisible(m_wallets.size() > 1);
        return;
    }
    if (tag == TAG_RESOLVE) {
        m_resolved_key = Str(value, "key");
        QString text = tr("%1 is %2").arg(Str(value, "name"), m_resolved_key);
        const QString source = Str(value, "source");
        if (source == "petname") {
            text += "\n" + tr("from your address book");
        } else if (source == "name") {
            const int64_t depth = Num(value, "depth");
            text += "\n" + tr("registered name, held until block %1").arg(Num(value, "expiry_height"));
            text += find_value(value, "settled").isTrue()
                ? " - " + tr("settled")
                : " - " + tr("changed %1 ago, not settled yet").arg(BpsUtil::HumanBlocks((int)depth));
        }
        m_lookup_result->setText(text);
        m_copy_resolved->setVisible(true);
        // Say so when it can be bought.
        if (source == "name" && !find_value(value, "subname").isTrue()) {
            UniValue params(UniValue::VARR);
            params.push_back(Str(value, "name").toStdString());
            m_rpc->Call(TAG_LOOKUP_PRICE, "getnameprice", params);
        }
        return;
    }
    if (tag == TAG_LOOKUP_PRICE) {
        if (Str(value, "status") == "for sale") {
            m_lookup_result->setText(m_lookup_result->text() + "\n" +
                tr("For sale: its holder asks %1, and %2 of renewal is burned with it. Use Get a name to buy it.")
                    .arg(QString::fromStdString(find_value(value, "asking").getValStr()) + " BPS",
                         QString::fromStdString(find_value(value, "renewal").getValStr()) + " BPS"));
        }
        return;
    }
    if (tag.startsWith(TAG_PAY)) {
        const QString what = tag.mid(strlen(TAG_PAY));
        if (what == "register") {
            m_status->setText(tr("Committed %1. The name is claimed by itself in %2 blocks (about %3), when %4 is "
                                 "burned - keep BPS Relay running and the wallet unlocked until then.")
                                  .arg(Str(value, "name"))
                                  .arg(names::COMMIT_MIN_AGE)
                                  .arg(BpsUtil::HumanBlocks((int)names::COMMIT_MIN_AGE))
                                  .arg(QString::fromStdString(find_value(value, "price").getValStr()) + " BPS"));
        } else if (what == "buy") {
            m_status->setText(tr("Buying %1: %2 paid to its holder and %3 burned. It is yours once the "
                                 "transaction confirms.")
                                  .arg(Str(value, "name"))
                                  .arg(QString::fromStdString(find_value(value, "paid").getValStr()) + " BPS")
                                  .arg(QString::fromStdString(find_value(value, "burned").getValStr()) + " BPS"));
        } else if (what == "sell") {
            m_status->setText(tr("%1 is going up for sale at %2. Anyone can buy it from the next block on, without "
                                 "this node being online; the price is paid to this wallet.")
                                  .arg(Str(value, "name"))
                                  .arg(QString::fromStdString(find_value(value, "price").getValStr()) + " BPS"));
        } else if (what == "unsell") {
            m_status->setText(tr("%1 is coming off sale. Nobody can buy it from now on.").arg(Str(value, "name")));
        } else if (what == "renew") {
            m_status->setText(tr("Renewed %1 until block %2; %3 BPS burned.")
                                  .arg(Str(value, "name")).arg(Num(value, "expiry_height"))
                                  .arg(QString::fromStdString(find_value(value, "burned").getValStr())));
        } else if (what == "transfer") {
            m_status->setText(tr("%1 is being transferred to %2. It is theirs once the transaction confirms.")
                                  .arg(Str(value, "name"), BpsUtil::ShortKey(Str(value, "new_owner"))));
        } else if (what == "subname") {
            m_status->setText(tr("%1 is set; it resolves once the transaction confirms.").arg(Str(value, "subname")));
        }
        Refresh();
        return;
    }
    if (tag.startsWith(TAG_PET)) {
        Refresh();
        return;
    }
}

void NamesPage::onFailed(const QString& tag, const QString& message)
{
    if (tag == TAG_RESOLVE) {
        m_lookup_result->setText(message);
        m_copy_resolved->setVisible(false);
        m_resolved_key.clear();
        return;
    }
    if (tag.startsWith(TAG_PAY) || tag.startsWith(TAG_PET)) {
        m_status->setText(QString());
        QMessageBox::warning(this, tr("Names"), message);
        return;
    }
    if (tag == TAG_LOOKUP_PRICE) return;
    if (tag == TAG_INFO) m_status->setText(message);
}

void NamesPage::ShowNames()
{
    const QString keep = SelectedName();
    m_owned->setRowCount(0);
    auto add = [this](const QString& name, const QString& status, const QString& ends, const QString& extra,
                      bool selectable) {
        const int row = m_owned->rowCount();
        m_owned->insertRow(row);
        QTableWidgetItem* name_item = new QTableWidgetItem(name);
        if (selectable) name_item->setData(Qt::UserRole, name);
        m_owned->setItem(row, 0, name_item);
        m_owned->setItem(row, 1, new QTableWidgetItem(status));
        m_owned->setItem(row, 2, new QTableWidgetItem(ends));
        QTableWidgetItem* extra_item = new QTableWidgetItem(extra);
        extra_item->setToolTip(extra);
        m_owned->setItem(row, 3, extra_item);
        return row;
    };
    for (size_t i = 0; i < m_names.size(); ++i) {
        const UniValue& n = m_names[i];
        const QString status = Str(n, "status");
        const int64_t left = Num(n, "blocks_left");
        QString ends = left > 0 ? tr("in %1").arg(BpsUtil::HumanBlocks((int)left))
                                : tr("ended %1 ago").arg(BpsUtil::HumanBlocks((int)-left));
        QStringList subs;
        const UniValue& list = find_value(n, "subnames");
        for (size_t j = 0; list.isArray() && j < list.size(); ++j) subs << Str(list[j], "name");
        QString shown = status == "grace" ? tr("expired - renew within the month") : tr("held");
        const UniValue& sale = find_value(n, "for_sale");
        if (sale.isObject()) {
            const QString price = QString::fromStdString(find_value(sale, "price").getValStr()) + " BPS";
            const QString state = Str(sale, "state");
            shown = state == "pending" ? tr("selling - a purchase is confirming")
                  : state == "open" ? tr("for sale at %1").arg(price)
                                    : tr("for sale at %1 - not yet buyable").arg(price);
        }
        const int row = add(Str(n, "name"), shown, ends, subs.join(", "), true);
        m_owned->item(row, 0)->setData(ROLE_FOR_SALE, sale.isObject());
        if (Str(n, "name") == keep) m_owned->selectRow(row);
    }
    // Registrations still under way, and how recent ones ended.
    for (size_t i = 0; i < m_pending.size(); ++i) {
        const UniValue& p = m_pending[i];
        const QString status = Str(p, "status");
        if (status == "done") continue;
        const QString label = status == "lost" ? tr("not registered") : tr("registering");
        add(Str(p, "name"), label, QString(), Str(p, "note"), false);
    }
    m_owned->resizeColumnToContents(1);
    m_owned->resizeColumnToContents(2);
    UpdateButtons();
}

void NamesPage::ShowPetnames()
{
    m_book->setRowCount(0);
    for (size_t i = 0; i < m_petnames.size(); ++i) {
        const int row = m_book->rowCount();
        m_book->insertRow(row);
        m_book->setItem(row, 0, new QTableWidgetItem(Str(m_petnames[i], "label")));
        QTableWidgetItem* key = new QTableWidgetItem(Str(m_petnames[i], "key"));
        key->setFont(BpsUtil::FixedPitchFont());
        key->setToolTip(Str(m_petnames[i], "key") + "\n" + tr("Click to copy"));
        m_book->setItem(row, 1, key);
    }
    UpdateButtons();
}

void NamesPage::onRegister()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Get a name"));
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    QFormLayout* form = new QFormLayout();
    QLineEdit* name = new QLineEdit(&dialog);
    name->setPlaceholderText(tr("3 to 32 letters, digits or hyphens"));
    name->setMaxLength((int)names::MAX_LABEL_LENGTH);
    QComboBox* years = new QComboBox(&dialog);
    years->addItem(tr("1 year"), 1);
    years->addItem(tr("2 years"), 2);
    form->addRow(tr("Name"), name);
    form->addRow(tr("For"), years);
    layout->addLayout(form);
    QLabel* price = new QLabel(&dialog);
    price->setWordWrap(true);
    layout->addWidget(price);
    const QString how_register = tr("Registering takes two steps: a commitment that hides the name, and about 20 "
                                    "minutes later the claim, which BPS Relay sends by itself and which burns the "
                                    "price. Nobody can take the name in between.");
    const QString how_buy = tr("Buying is one transaction: it pays the holder, burns the renewal and makes the name "
                               "yours, all at once or not at all.");
    QLabel* how = new QLabel(how_register, &dialog);
    how->setWordWrap(true);
    how->setEnabled(false);
    layout->addWidget(how);
    QDialogButtonBox* buttons = new QDialogButtonBox(&dialog);
    QPushButton* ok = buttons->addButton(tr("Register"), QDialogButtonBox::AcceptRole);
    // What the node said can be done with the name typed: register or buy.
    std::shared_ptr<QString> action = std::make_shared<QString>("register");
    buttons->addButton(QDialogButtonBox::Cancel);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    dialog.resize(480, dialog.sizeHint().height());

    // The price is known here; whether the name is free is asked of the node.
    auto update = [this, name, years, price, ok] {
        const std::string text = name->text().trimmed().toStdString();
        std::string normal;
        if (text.empty()) {
            price->setText(QString());
            ok->setEnabled(false);
            return;
        }
        if (!names::Normalize(text, normal) || !names::IsValidRoot(normal)) {
            price->setText(tr("A name is 3 to 32 plain letters a-z, digits or inner hyphens."));
            ok->setEnabled(false);
            return;
        }
        const int y = years->currentData().toInt();
        price->setText(tr("%1 costs %2 a year: %3 burned for %4. Checking whether it is free\xe2\x80\xa6")
                           .arg(QString::fromStdString(normal))
                           .arg(Coins(names::PricePerYear(normal.size())))
                           .arg(Coins(names::Price(normal.size(), (uint32_t)y * names::BLOCKS_PER_YEAR)))
                           .arg(y == 1 ? tr("one year") : tr("two years")));
        ok->setEnabled(false);
        UniValue params(UniValue::VARR);
        params.push_back(normal);
        params.push_back(y);
        m_rpc->Call(QString("names:price:") + QString::fromStdString(normal), "getnameprice", params);
    };
    connect(m_rpc.get(), &BpsRpc::result, &dialog,
            [name, price, ok, how, how_register, how_buy, action](const QString& tag, const UniValue& value) {
        if (!tag.startsWith("names:price:")) return;
        std::string normal;
        names::Normalize(name->text().trimmed().toStdString(), normal);
        if (tag.mid(12).toStdString() != normal) return;
        const bool available = find_value(value, "available").isTrue();
        const std::string reason = find_value(value, "reason").getValStr();
        if (find_value(value, "status").getValStr() == "for sale") {
            *action = "buy";
            QString text = QObject::tr("%1 is held by someone, who has put it up for sale. They ask %2, and the "
                                       "renewal that comes with it burns %3: %4 in all.")
                               .arg(QString::fromStdString(normal))
                               .arg(QString::fromStdString(find_value(value, "asking").getValStr()) + " BPS")
                               .arg(QString::fromStdString(find_value(value, "renewal").getValStr()) + " BPS")
                               .arg(QString::fromStdString(find_value(value, "total").getValStr()) + " BPS");
            if (!available) text += " " + QString::fromStdString(reason);
            price->setText(text);
            how->setText(how_buy);
            ok->setText(QObject::tr("Buy"));
        } else {
            *action = "register";
            QString text = price->text();
            text.replace(QObject::tr("Checking whether it is free\xe2\x80\xa6"),
                         available ? QObject::tr("It is free.") : QString::fromStdString(reason));
            price->setText(text);
            how->setText(how_register);
            ok->setText(QObject::tr("Register"));
        }
        ok->setEnabled(available);
    });
    connect(name, &QLineEdit::textChanged, &dialog, update);
    connect(years, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), &dialog, update);
    update();

    if (dialog.exec() != QDialog::Accepted) return;
    UniValue params(UniValue::VARR);
    params.push_back(name->text().trimmed().toLower().toStdString());
    params.push_back(years->currentData().toInt());
    if (*action == "buy") {
        Pay("buy", "buyname", params);
    } else {
        Pay("register", "registername", params);
    }
}

void NamesPage::onSell()
{
    const QString name = SelectedName();
    if (name.isEmpty()) return;
    if (SelectedForSale()) {
        if (QMessageBox::question(this, tr("Take %1 off sale").arg(name),
                tr("Take %1 off sale? Nobody can buy it from then on, and once that confirms you can transfer it "
                   "or put it up again.").arg(name),
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) {
            return;
        }
        UniValue params(UniValue::VARR);
        params.push_back(name.toStdString());
        Pay("unsell", "cancelnamesale", params);
        return;
    }
    bool ok = false;
    const QString text = QInputDialog::getText(this, tr("Sell %1").arg(name),
        tr("Your price for %1, in BPS. Anyone can then buy it at once, even while BPS Relay is closed: they pay "
           "you this and burn the renewal on top, in one transaction. While it is for sale you cannot transfer "
           "it.").arg(name),
        QLineEdit::Normal, QString(), &ok).trimmed();
    if (!ok || text.isEmpty()) return;
    CAmount price = 0;
    if (!ParseMoney(text.toStdString(), price) || price <= 0) {
        QMessageBox::warning(this, tr("Sell %1").arg(name), tr("\"%1\" is not an amount of BPS.").arg(text));
        return;
    }
    if (QMessageBox::question(this, tr("Sell %1").arg(name),
            tr("Put %1 up for sale at %2? Two small transactions are sent: one sets aside the coin a buyer spends, "
               "the other publishes the sale.").arg(name, Coins(price)),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) {
        return;
    }
    UniValue params(UniValue::VARR);
    params.push_back(name.toStdString());
    params.push_back(ValueFromAmount(price));
    Pay("sell", "sellname", params);
}

void NamesPage::onRenew()
{
    const QString name = SelectedName();
    if (name.isEmpty()) return;
    const size_t len = (size_t)name.size();
    QStringList options;
    options << tr("1 year - %1").arg(Coins(names::Price(len, names::BLOCKS_PER_YEAR)))
            << tr("2 years - %1").arg(Coins(names::Price(len, 2 * names::BLOCKS_PER_YEAR)));
    bool ok = false;
    const QString choice = QInputDialog::getItem(this, tr("Renew %1").arg(name),
        tr("Extend %1 from when it ends now. The price is burned. A name can be paid at most two years ahead.")
            .arg(name), options, 0, false, &ok);
    if (!ok) return;
    UniValue params(UniValue::VARR);
    params.push_back(name.toStdString());
    params.push_back(options.indexOf(choice) + 1);
    Pay("renew", "renewname", params);
}

void NamesPage::onTransfer()
{
    const QString name = SelectedName();
    if (name.isEmpty()) return;
    bool ok = false;
    const QString to = QInputDialog::getText(this, tr("Transfer %1").arg(name),
        tr("Give %1 to (a roster key, a petname or a name):").arg(name), QLineEdit::Normal, QString(), &ok).trimmed();
    if (!ok || to.isEmpty()) return;
    if (QMessageBox::question(this, tr("Transfer %1").arg(name),
            tr("Give %1 to %2? Only its new holder can give it back.").arg(name, to),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) {
        return;
    }
    UniValue params(UniValue::VARR);
    params.push_back(name.toStdString());
    params.push_back(to.toStdString());
    Pay("transfer", "transfername", params);
}

void NamesPage::onSubname()
{
    const QString name = SelectedName();
    if (name.isEmpty()) return;
    bool ok = false;
    const QString label = QInputDialog::getText(this, tr("Subname under %1").arg(name),
        tr("The part before .%1, for example alice for alice.%1:").arg(name), QLineEdit::Normal, QString(), &ok)
        .trimmed().toLower();
    if (!ok || label.isEmpty()) return;
    const QString to = QInputDialog::getText(this, tr("Subname under %1").arg(name),
        tr("Who %1.%2 points to (a roster key, petname or name), or \"remove\":").arg(label, name),
        QLineEdit::Normal, QString(), &ok).trimmed();
    if (!ok || to.isEmpty()) return;
    UniValue params(UniValue::VARR);
    params.push_back((label + "." + name).toStdString());
    params.push_back(to.toStdString());
    Pay("subname", "setsubname", params);
}

void NamesPage::onLookup()
{
    const QString text = m_lookup->text().trimmed();
    if (text.isEmpty()) return;
    UniValue params(UniValue::VARR);
    params.push_back(text.toStdString());
    m_lookup_result->setText(tr("Looking up\xe2\x80\xa6"));
    m_rpc->Call(TAG_RESOLVE, "resolvename", params);
}

void NamesPage::onAddPetname()
{
    bool ok = false;
    const QString label = QInputDialog::getText(this, tr("Add someone"),
        tr("What you call them (only you see this):"), QLineEdit::Normal, QString(), &ok).trimmed();
    if (!ok || label.isEmpty()) return;
    const QString who = QInputDialog::getText(this, tr("Add someone"),
        tr("Their roster key, or a name to remember who holds it now:"), QLineEdit::Normal,
        m_resolved_key, &ok).trimmed();
    if (!ok || who.isEmpty()) return;
    UniValue params(UniValue::VARR);
    params.push_back(label.toStdString());
    params.push_back(who.toStdString());
    m_rpc->Call(QString(TAG_PET) + "set", "setpetname", params);
}

void NamesPage::onRemovePetname()
{
    const QList<QTableWidgetItem*> items = m_book->selectedItems();
    if (items.isEmpty()) return;
    const QTableWidgetItem* label = m_book->item(items.first()->row(), 0);
    if (!label) return;
    UniValue params(UniValue::VARR);
    params.push_back(label->text().toStdString());
    m_rpc->Call(QString(TAG_PET) + "delete", "deletepetname", params);
}
