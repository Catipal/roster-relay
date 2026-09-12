// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/bpswindow.h>

#include <qt/bps/bpsrpc.h>
#include <qt/bps/discoverypage.h>
#include <qt/bps/overlaypage.h>

#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/networkstyle.h>
#include <qt/platformstyle.h>
#include <qt/rpcconsole.h>

#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <node/ui_interface.h>
#include <util/translation.h>

#include <QApplication>
#include <QDateTime>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QMetaObject>
#include <QSettings>
#include <QStackedWidget>
#include <QStatusBar>
#include <QWidget>

#include <assert.h>
#include <functional>

Q_DECLARE_METATYPE(bool*)

namespace {
//! Core wants to say something. Marshalled onto the GUI thread by name, which
//! is the only way to reach a slot from a thread that has no Qt connection.
bool ThreadSafeMessageBox(BpsWindow* window, const bilingual_str& message,
                          const std::string& caption, unsigned int style)
{
    const bool modal = (style & CClientUIInterface::MODAL);
    style &= ~CClientUIInterface::SECURE;
    bool ret = false;

    QString detailed;
    if (message.original != message.translated) {
        detailed = BpsWindow::tr("Original message:") + "\n" + QString::fromStdString(message.original);
    }

    const bool invoked = QMetaObject::invokeMethod(
        window, "message",
        modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(caption)),
        Q_ARG(QString, QString::fromStdString(message.translated)),
        Q_ARG(unsigned int, style),
        Q_ARG(bool*, &ret),
        Q_ARG(QString, detailed));
    assert(invoked);
    return ret;
}
} // namespace

BpsWindow::BpsWindow(interfaces::Node& node, const PlatformStyle* platformStyle,
                     const NetworkStyle* networkStyle, QWidget* parent)
    : QMainWindow(parent), m_node(node), m_platform_style(platformStyle)
{
    QSettings settings;
    if (!restoreGeometry(settings.value("BpsWindowGeometry").toByteArray())) {
        resize(1000, 700);
    }

    setWindowTitle(tr("BPS Discovery") + " " + networkStyle->getTitleAddText());
    setWindowIcon(networkStyle->getTrayAndWindowIcon());
    setMinimumSize(900, 600);

    m_rpc.reset(new BpsRpc(node, this));

    m_discovery = new DiscoveryPage(*m_rpc, this);
    m_overlay = new OverlayPage(*m_rpc, this);
    // Not a reimplementation: this is the wallet client's own console, peer
    // table and traffic graph, linked rather than copied.
    m_console = new RPCConsole(node, platformStyle, nullptr);

    m_pages = new QStackedWidget(this);
    m_pages->addWidget(m_discovery);
    m_pages->addWidget(m_overlay);
    m_pages->addWidget(m_console);

    m_nav = new QListWidget(this);
    m_nav->addItem(tr("Discovery"));
    m_nav->addItem(tr("Overlay"));
    m_nav->addItem(tr("Node"));
    m_nav->setFixedWidth(180);
    m_nav->setFrameShape(QFrame::NoFrame);
    m_nav->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_nav->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // Palette roles rather than fixed colours, so the sidebar follows whatever
    // theme the desktop is using instead of insisting on one.
    m_nav->setStyleSheet(
        "QListWidget { background: palette(alternate-base); border: none; outline: none;"
        "              padding-top: 10px; }"
        "QListWidget::item { padding: 11px 16px; border: none; }"
        "QListWidget::item:selected { background: palette(highlight);"
        "                             color: palette(highlighted-text); }"
        "QListWidget::item:hover:!selected { background: palette(midlight); }");
    m_nav->setCurrentRow(0);
    connect(m_nav, &QListWidget::currentRowChanged, m_pages, &QStackedWidget::setCurrentIndex);

    QWidget* central = new QWidget(this);
    QHBoxLayout* layout = new QHBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(m_nav);
    layout->addWidget(m_pages, 1);
    setCentralWidget(central);

    m_status_chain = new QLabel(tr("connecting\xe2\x80\xa6"), this);
    m_status_peers = new QLabel(this);
    statusBar()->addWidget(m_status_chain);
    statusBar()->addPermanentWidget(m_status_peers);

    subscribeToCoreSignals();
}

BpsWindow::~BpsWindow()
{
    QSettings settings;
    settings.setValue("BpsWindowGeometry", saveGeometry());
    // m_console is a child of the page stack, so Qt owns it from here.
}

void BpsWindow::subscribeToCoreSignals()
{
    m_handler_message_box = m_node.handleMessageBox(
        std::bind(ThreadSafeMessageBox, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    m_handler_question = m_node.handleQuestion(
        std::bind(ThreadSafeMessageBox, this, std::placeholders::_1, std::placeholders::_3, std::placeholders::_4));
}

void BpsWindow::unsubscribeFromCoreSignals()
{
    if (m_handler_message_box) m_handler_message_box->disconnect();
    if (m_handler_question) m_handler_question->disconnect();
}

void BpsWindow::setClientModel(ClientModel* model, interfaces::BlockAndHeaderTipInfo* tip_info)
{
    m_client_model = model;

    if (model) {
        setNumConnections(model->getNumConnections());
        connect(model, &ClientModel::numConnectionsChanged, this, &BpsWindow::setNumConnections);
        connect(model, &ClientModel::numBlocksChanged, this, &BpsWindow::setNumBlocks);
    }

    // The console owns a good deal of state tied to the model, so it is told
    // first and told the same things the wallet client tells it.
    if (m_console) {
        if (model && tip_info) {
            m_console->setClientModel(model, tip_info->block_height,
                                      tip_info->block_time, tip_info->verification_progress);
        } else {
            m_console->setClientModel(model);
        }
    }

    m_discovery->setClientModel(model);
    m_overlay->setClientModel(model);

    if (!model) {
        m_status_chain->setText(tr("shutting down\xe2\x80\xa6"));
        m_status_peers->clear();
    }
}

void BpsWindow::setNumConnections(int count)
{
    m_status_peers->setText(count == 1 ? tr("1 connection") : tr("%1 connections").arg(count));
}

void BpsWindow::setNumBlocks(int count, const QDateTime& block_date, double progress,
                             bool header, SynchronizationState sync_state)
{
    if (header) return;
    if (progress < 0.999) {
        m_status_chain->setText(tr("catching up \xe2\x80\x94 %1%").arg(progress * 100, 0, 'f', 1));
    } else {
        m_status_chain->setText(tr("block %1").arg(count));
    }
}

void BpsWindow::detectShutdown()
{
    if (m_node.shutdownRequested()) {
        if (m_console) m_console->hide();
        qApp->quit();
    }
}

void BpsWindow::message(const QString& title, const QString& text, unsigned int style,
                        bool* ret, const QString& detailed_message)
{
    QString caption = title.isEmpty() ? tr("BPS Discovery") : title;

    QMessageBox::Icon icon = QMessageBox::Information;
    switch (style & ((CClientUIInterface::ICON_MASK) & ~CClientUIInterface::ICON_INFORMATION)) {
    case CClientUIInterface::ICON_WARNING: icon = QMessageBox::Warning; break;
    case CClientUIInterface::ICON_ERROR: icon = QMessageBox::Critical; break;
    default: break;
    }

    QMessageBox::StandardButton buttons =
        (QMessageBox::StandardButton)(style & CClientUIInterface::BTN_MASK);
    if (!buttons) buttons = QMessageBox::Ok;

    QMessageBox box(icon, caption, text, buttons, this);
    box.setTextFormat(Qt::PlainText);
    box.setDetailedText(detailed_message);
    const int r = box.exec();
    if (ret != nullptr) *ret = r == QMessageBox::Ok || r == QMessageBox::Yes;
}
