// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/mailpage.h>

#include <qt/bps/bpsrpc.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>

#include <mail/letter.h>
#include <mail/mailbox.h>

#include <cstring>

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFont>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTabBar>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace {

const char* TAG_INFO = "mail:info";
const char* TAG_LIST = "mail:list";
const char* TAG_READ = "mail:read";
const char* TAG_COLLECT = "mail:collect";
const char* TAG_DELETE = "mail:delete";

//! Mail moves when someone sends or collects; this only keeps the list honest.
const int REFRESH_MS = 30000;

enum Column { WHO = 0, SUBJECT = 1, WHEN = 2 };

QString ShortKey(const std::string& hex)
{
    if (hex.size() < 16) return QString::fromStdString(hex);
    return QString::fromStdString(hex.substr(0, 10) + "\xe2\x80\xa6" + hex.substr(hex.size() - 6));
}

QString When(int64_t t)
{
    if (t <= 0) return QString();
    return QDateTime::fromSecsSinceEpoch(t).toString("yyyy-MM-dd hh:mm");
}

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

} // namespace

MailPage::MailPage(interfaces::Node& node, QWidget* parent) : QWidget(parent), m_rpc(new BpsRpc(node))
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(10);

    QLabel* title = new QLabel(tr("Mail"), this);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);
    outer->addWidget(title);

    // Your address is your roster key: give it to people who should write to you.
    QHBoxLayout* address = new QHBoxLayout();
    QLabel* address_caption = new QLabel(tr("Your address"), this);
    address->addWidget(address_caption);
    m_address_label = new QLabel(tr("\xe2\x80\x94"), this);
    m_address_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_address_label->setFont(GUIUtil::fixedPitchFont());
    address->addWidget(m_address_label, 1);
    m_copy = new QPushButton(tr("Copy"), this);
    m_copy->setToolTip(tr("Your roster key. Anyone listed can write to you at it."));
    address->addWidget(m_copy);
    outer->addLayout(address);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    m_status->setEnabled(false);
    outer->addWidget(m_status);

    m_off = new QLabel(tr("Mail travels over the overlay. Turn the overlay on under Settings and restart "
                          "to send and receive mail."), this);
    m_off->setWordWrap(true);
    m_off->setStyleSheet("color: #8a3b12; background: #f6e0d3; border-radius: 6px; padding: 8px 10px;");
    m_off->setVisible(false);
    outer->addWidget(m_off);

    QHBoxLayout* tools = new QHBoxLayout();
    m_write = new QPushButton(tr("Write"), this);
    m_reply = new QPushButton(tr("Reply"), this);
    m_collect = new QPushButton(tr("Collect now"), this);
    m_collect->setToolTip(tr("Fetch new letters from your mailboxes now. This also happens every few minutes."));
    m_delete = new QPushButton(tr("Delete"), this);
    tools->addWidget(m_write);
    tools->addWidget(m_reply);
    tools->addWidget(m_collect);
    tools->addStretch(1);
    tools->addWidget(m_delete);
    outer->addLayout(tools);

    m_folders = new QTabBar(this);
    m_folders->addTab(tr("Inbox"));
    m_folders->addTab(tr("Sent"));
    m_folders->setDocumentMode(true);
    m_folders->setExpanding(false);
    outer->addWidget(m_folders);

    QSplitter* split = new QSplitter(Qt::Horizontal, this);
    m_list = new QTableWidget(0, 3, split);
    m_list->setHorizontalHeaderLabels({tr("From"), tr("Subject"), tr("Date")});
    m_list->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_list->setSelectionMode(QAbstractItemView::SingleSelection);
    m_list->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_list->verticalHeader()->setVisible(false);
    m_list->setShowGrid(false);
    m_list->setAlternatingRowColors(true);
    m_list->horizontalHeader()->setSectionResizeMode(WHO, QHeaderView::ResizeToContents);
    m_list->horizontalHeader()->setSectionResizeMode(SUBJECT, QHeaderView::Stretch);
    m_list->horizontalHeader()->setSectionResizeMode(WHEN, QHeaderView::ResizeToContents);

    QWidget* reader = new QWidget(split);
    QVBoxLayout* reader_layout = new QVBoxLayout(reader);
    reader_layout->setContentsMargins(8, 0, 0, 0);
    m_reader_head = new QLabel(reader);
    m_reader_head->setWordWrap(true);
    m_reader_head->setTextInteractionFlags(Qt::TextSelectableByMouse);
    // Rich text for the bold subject. Everything a sender wrote is escaped
    // before it gets here: a subject is a stranger's text.
    m_reader_head->setTextFormat(Qt::RichText);
    reader_layout->addWidget(m_reader_head);
    m_reader = new QPlainTextEdit(reader);
    m_reader->setReadOnly(true);
    reader_layout->addWidget(m_reader, 1);

    split->addWidget(m_list);
    split->addWidget(reader);
    split->setStretchFactor(0, 4);
    split->setStretchFactor(1, 5);
    outer->addWidget(split, 1);

    QLabel* sealed = new QLabel(
        tr("Letters are sealed to the recipient's weekly mail key with secp256k1 and ML-KEM-768 together, "
           "your key and signature travel inside the seal, and every trip to a mailbox goes through three "
           "relays. Old mail keys are deleted, so a letter collected today cannot be opened later from "
           "this computer's keys."),
        this);
    sealed->setWordWrap(true);
    sealed->setEnabled(false);
    outer->addWidget(sealed);

    connect(m_rpc.get(), &BpsRpc::result, this, &MailPage::onResult);
    connect(m_rpc.get(), &BpsRpc::failed, this, &MailPage::onFailed);
    connect(m_list, &QTableWidget::itemSelectionChanged, this, &MailPage::onSelection);
    connect(m_folders, &QTabBar::currentChanged, this, [this](int) {
        m_list->setHorizontalHeaderLabels({InSent() ? tr("To") : tr("From"), tr("Subject"), tr("Date")});
        ShowLetters();
    });
    connect(m_write, &QPushButton::clicked, this, &MailPage::onWrite);
    connect(m_reply, &QPushButton::clicked, this, &MailPage::onReply);
    connect(m_collect, &QPushButton::clicked, this, &MailPage::onCollect);
    connect(m_delete, &QPushButton::clicked, this, &MailPage::onDelete);
    connect(m_copy, &QPushButton::clicked, this, &MailPage::onCopyAddress);

    m_timer = new QTimer(this);
    m_timer->setInterval(REFRESH_MS);
    connect(m_timer, &QTimer::timeout, this, &MailPage::Refresh);

    m_letters = UniValue(UniValue::VARR);
    ClearReader();
}

MailPage::~MailPage() {}

void MailPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    Refresh();
}

void MailPage::setClientModel(ClientModel* model)
{
    m_client_model = model;
    if (!model) {
        m_timer->stop();
        return;
    }
    m_timer->start();
    Refresh();
}

bool MailPage::InSent() const { return m_folders->currentIndex() == 1; }

void MailPage::Refresh()
{
    if (!m_client_model) return;
    m_rpc->Call(TAG_INFO, "getmailinfo");
    UniValue params(UniValue::VARR);
    params.push_back("all");
    m_rpc->Call(TAG_LIST, "listmail", params);
}

void MailPage::onResult(const QString& tag, const UniValue& value)
{
    if (tag == TAG_INFO) {
        m_enabled = find_value(value, "enabled").isTrue();
        m_off->setVisible(!m_enabled);
        for (QPushButton* b : {m_write, m_collect, m_copy}) b->setEnabled(m_enabled);
        if (!m_enabled) {
            m_address_label->setText(tr("\xe2\x80\x94"));
            m_status->setText(QString());
            return;
        }
        m_address = Str(value, "address");
        m_address_label->setText(m_address);
        const UniValue& boxes = find_value(value, "mailboxes");
        const int count = boxes.isArray() ? (int)boxes.size() : 0;
        const UniValue& key = find_value(value, "key");
        const int64_t last = Num(value, "last_check");
        QString status;
        if (count == 0) {
            status = tr("No relay is listed yet, so you have no mailboxes and nobody can write to you.");
        } else if (count < (int)mail::MAILBOX_COUNT) {
            status = tr("%1 relays hold your mail; there will be %2 once the roster lists more.")
                         .arg(count).arg(mail::MAILBOX_COUNT);
        } else {
            status = tr("%1 relays chosen from your key hold your mail until you collect it.").arg(count);
        }
        status += " " + tr("Mail key #%1, renewed weekly.").arg(Num(key, "id"));
        status += " " + (last > 0 ? tr("Last collected %1.").arg(When(last)) : tr("Not collected yet."));
        if (!m_note.isEmpty()) status = m_note + " " + status;
        m_status->setText(status);
        Q_EMIT unreadChanged((int)Num(value, "unread"));
        return;
    }
    if (tag == TAG_LIST) {
        if (value.isArray()) m_letters = value;
        ShowLetters();
        return;
    }
    if (tag.startsWith(TAG_READ)) {
        if (tag.mid(strlen(TAG_READ) + 1) == m_selected) ShowLetter(value);
        // Reading it marked it read; the list and the count follow.
        Refresh();
        return;
    }
    if (tag == TAG_COLLECT) {
        m_collect->setEnabled(m_enabled);
        m_collect->setText(tr("Collect now"));
        const int64_t fetched = Num(value, "fetched");
        const int64_t reached = Num(value, "reached");
        const int64_t boxes = Num(value, "mailboxes");
        QString text = fetched == 1 ? tr("1 new letter") : tr("%1 new letters").arg(fetched);
        text += tr(", from %1 of %2 mailboxes.").arg(reached).arg(boxes);
        const UniValue& notes = find_value(value, "notes");
        if (notes.isArray() && notes.size() > 0 && reached < boxes) {
            text += " " + QString::fromStdString(notes[0].get_str());
        }
        m_note = text;
        m_status->setText(text);
        Refresh();
        return;
    }
    if (tag == TAG_DELETE) {
        m_selected.clear();
        ClearReader();
        Refresh();
        return;
    }
}

void MailPage::onFailed(const QString& tag, const QString& message)
{
    if (tag == TAG_COLLECT) {
        m_collect->setEnabled(m_enabled);
        m_collect->setText(tr("Collect now"));
    }
    if (tag == TAG_INFO || tag == TAG_COLLECT || tag == TAG_DELETE) m_status->setText(message);
}

void MailPage::ShowLetters()
{
    const bool sent = InSent();
    m_list->setRowCount(0);
    int selected_row = -1;
    for (size_t i = 0; i < m_letters.size(); ++i) {
        const UniValue& l = m_letters[i];
        if ((Str(l, "folder") == "sent") != sent) continue;
        const int row = m_list->rowCount();
        m_list->insertRow(row);
        const std::string who = (sent ? Str(l, "to") : Str(l, "from")).toStdString();
        QTableWidgetItem* who_item = new QTableWidgetItem(ShortKey(who));
        who_item->setToolTip(QString::fromStdString(who));
        who_item->setData(Qt::UserRole, Str(l, "id"));
        QString subject = Str(l, "subject");
        if (subject.isEmpty()) subject = tr("(no subject)");
        QTableWidgetItem* subject_item = new QTableWidgetItem(subject);
        subject_item->setToolTip(sent ? tr("Left at %1 of the recipient's mailboxes").arg(Num(l, "delivered"))
                                      : subject);
        QTableWidgetItem* when_item = new QTableWidgetItem(When(sent ? Num(l, "sent") : Num(l, "received")));
        if (!sent && !find_value(l, "read").isTrue()) {
            QFont bold = who_item->font();
            bold.setBold(true);
            who_item->setFont(bold);
            subject_item->setFont(bold);
            when_item->setFont(bold);
        }
        m_list->setItem(row, WHO, who_item);
        m_list->setItem(row, SUBJECT, subject_item);
        m_list->setItem(row, WHEN, when_item);
        if (Str(l, "id") == m_selected) selected_row = row;
    }
    if (selected_row >= 0) {
        m_list->blockSignals(true);
        m_list->selectRow(selected_row);
        m_list->blockSignals(false);
    }
    const bool has = selected_row >= 0;
    m_reply->setEnabled(m_enabled && has && !sent);
    m_delete->setEnabled(has);
    if (!has && !m_selected.isEmpty()) {
        m_selected.clear();
        ClearReader();
    }
}

void MailPage::onSelection()
{
    const QList<QTableWidgetItem*> items = m_list->selectedItems();
    if (items.isEmpty()) return;
    const QTableWidgetItem* who = m_list->item(items.first()->row(), WHO);
    m_selected = who->data(Qt::UserRole).toString();
    m_reply->setEnabled(m_enabled && !InSent());
    m_delete->setEnabled(true);
    UniValue params(UniValue::VARR);
    params.push_back(m_selected.toStdString());
    m_rpc->Call(QString(TAG_READ) + ":" + m_selected, "readmail", params);
}

void MailPage::ShowLetter(const UniValue& l)
{
    const bool sent = Str(l, "folder") == "sent";
    QString head = tr("From: %1").arg(Str(l, "from").toHtmlEscaped()) + "<br>" +
                   tr("To: %1").arg(Str(l, "to").toHtmlEscaped()) + "<br>";
    head += sent ? tr("Sent %1, left at %2 of the recipient's mailboxes").arg(When(Num(l, "sent"))).arg(Num(l, "delivered"))
                 : tr("Written %1, collected %2").arg(When(Num(l, "sent"))).arg(When(Num(l, "received")));
    QString subject = Str(l, "subject");
    if (subject.isEmpty()) subject = tr("(no subject)");
    head += "<br><br><b>" + subject.toHtmlEscaped() + "</b>";
    m_reader_head->setText(head);
    m_reader->setPlainText(Str(l, "body"));
}

void MailPage::ClearReader()
{
    m_reader_head->setText(tr("Select a letter to read it."));
    m_reader->clear();
    m_reply->setEnabled(false);
    m_delete->setEnabled(false);
}

void MailPage::Compose(const QString& to, const QString& subject, const QString& body)
{
    ComposeDialog* dialog = new ComposeDialog(*m_rpc, to, subject, body, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    connect(dialog, &ComposeDialog::sent, this, &MailPage::Refresh);
    dialog->show();
}

void MailPage::onWrite() { Compose(QString(), QString(), QString()); }

void MailPage::onReply()
{
    for (size_t i = 0; i < m_letters.size(); ++i) {
        const UniValue& l = m_letters[i];
        if (Str(l, "id") != m_selected) continue;
        QString subject = Str(l, "subject");
        if (!subject.startsWith("Re: ")) subject = "Re: " + subject;
        // Quote what was written, the way mail clients do.
        QString quoted;
        for (const QString& line : m_reader->toPlainText().split('\n')) quoted += "> " + line + "\n";
        Compose(Str(l, "from"), subject.left((int)mail::MAX_SUBJECT), "\n\n" + quoted);
        return;
    }
}

void MailPage::onCollect()
{
    m_collect->setEnabled(false);
    m_collect->setText(tr("Collecting\xe2\x80\xa6"));
    m_status->setText(tr("Reaching your mailboxes through three relays each\xe2\x80\xa6"));
    m_rpc->Call(TAG_COLLECT, "checkmail");
}

void MailPage::onDelete()
{
    if (m_selected.isEmpty()) return;
    if (QMessageBox::question(this, tr("Delete letter"),
                              tr("Delete this letter from this computer? Its copies at the mailboxes were "
                                 "already removed when it was collected, so it cannot be fetched again."),
                              QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) {
        return;
    }
    UniValue params(UniValue::VARR);
    params.push_back(m_selected.toStdString());
    m_rpc->Call(TAG_DELETE, "deletemail", params);
}

void MailPage::onCopyAddress()
{
    if (!m_address.isEmpty()) QApplication::clipboard()->setText(m_address);
}

ComposeDialog::ComposeDialog(BpsRpc& rpc, const QString& to, const QString& subject, const QString& body,
                             QWidget* parent)
    : QDialog(parent), m_rpc(rpc)
{
    static int counter = 0;
    m_tag = QString("compose:%1").arg(++counter);
    setWindowTitle(tr("Write a letter"));
    resize(620, 520);

    QVBoxLayout* layout = new QVBoxLayout(this);
    QFormLayout* form = new QFormLayout();
    m_to = new QLineEdit(to, this);
    m_to->setPlaceholderText(tr("a name, a petname from your address book, or a roster key"));
    m_to->setFont(GUIUtil::fixedPitchFont());
    form->addRow(tr("To"), m_to);
    m_subject = new QLineEdit(subject, this);
    m_subject->setMaxLength((int)mail::MAX_SUBJECT);
    form->addRow(tr("Subject"), m_subject);
    layout->addLayout(form);

    m_body = new QPlainTextEdit(this);
    m_body->setPlainText(body);
    layout->addWidget(m_body, 1);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    layout->addWidget(m_status);

    QDialogButtonBox* buttons = new QDialogButtonBox(this);
    m_send = buttons->addButton(tr("Send"), QDialogButtonBox::AcceptRole);
    buttons->addButton(QDialogButtonBox::Cancel);
    layout->addWidget(buttons);

    connect(m_send, &QPushButton::clicked, this, &ComposeDialog::onSend);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(&m_rpc, &BpsRpc::result, this, &ComposeDialog::onResult);
    connect(&m_rpc, &BpsRpc::failed, this, &ComposeDialog::onFailed);

    if (to.isEmpty()) {
        m_to->setFocus();
    } else {
        m_body->setFocus();
        m_body->moveCursor(QTextCursor::Start);
    }
}

void ComposeDialog::onSend()
{
    const QString to = m_to->text().trimmed();
    if (to.isEmpty()) {
        m_status->setText(tr("Who is it for? A name, a petname or a roster key."));
        return;
    }
    const std::string body = m_body->toPlainText().toStdString();
    if (body.size() > mail::MAX_BODY) {
        m_status->setText(tr("The letter is %1 KB; the most a letter can be is %2 KB.")
                              .arg(body.size() / 1024).arg(mail::MAX_BODY / 1024));
        return;
    }
    UniValue params(UniValue::VARR);
    params.push_back(to.toStdString());
    params.push_back(m_subject->text().toStdString());
    params.push_back(body);
    m_send->setEnabled(false);
    m_status->setText(tr("Sealing the letter and leaving it at the recipient's mailboxes, through three relays "
                         "each. This takes a few seconds\xe2\x80\xa6"));
    m_rpc.Call(m_tag, "sendmail", params);
}

void ComposeDialog::onResult(const QString& tag, const UniValue& value)
{
    if (tag != m_tag) return;
    Q_EMIT sent();
    const int64_t delivered = Num(value, "delivered");
    const int64_t boxes = Num(value, "mailboxes");
    if (delivered < boxes) {
        QMessageBox::information(this, tr("Sent"),
            tr("The letter was left at %1 of the recipient's %2 mailboxes. One is enough for it to arrive.")
                .arg(delivered).arg(boxes));
    }
    accept();
}

void ComposeDialog::onFailed(const QString& tag, const QString& message)
{
    if (tag != m_tag) return;
    m_send->setEnabled(true);
    m_status->setText(tr("Not sent: %1").arg(message));
}
