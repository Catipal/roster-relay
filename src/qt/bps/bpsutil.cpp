// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/bpsutil.h>

#include <qt/guiutil.h>

#include <univalue.h>

#include <QAbstractSpinBox>
#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QEvent>
#include <QFormLayout>
#include <QLabel>
#include <QProxyStyle>
#include <QStyleOptionButton>
#include <QTimer>

#include <algorithm>

namespace BpsUtil {

QString HumanBlocks(int blocks)
{
    if (blocks <= 0) return QCoreApplication::translate("BpsUtil", "less than a minute");
    return HumanSeconds((qint64)blocks * SECONDS_PER_BLOCK);
}

QString HumanSeconds(qint64 seconds)
{
    // Written out longhand rather than with Qt's %n plural form. Without a
    // translation loaded %n falls back to the source string, so "%n month(s)"
    // reaches the screen with the brackets still in it.
    // The context is written out in every call, not kept in a variable:
    // lupdate reads it from the source and cannot follow a variable.
    if (seconds < 60) return QCoreApplication::translate("BpsUtil", "less than a minute");

    const qint64 minutes = seconds / 60;
    if (minutes < 90) {
        if (minutes <= 1) return QCoreApplication::translate("BpsUtil", "a minute");
        return QCoreApplication::translate("BpsUtil", "%1 minutes").arg(minutes);
    }

    const qint64 hours = minutes / 60;
    if (hours < 48) {
        if (hours == 1) return QCoreApplication::translate("BpsUtil", "an hour");
        return QCoreApplication::translate("BpsUtil", "%1 hours").arg(hours);
    }

    const qint64 days = hours / 24;
    if (days < 60) return QCoreApplication::translate("BpsUtil", "%1 days").arg(days);

    const qint64 months = days / 30;
    if (months < 12) {
        if (months == 1) return QCoreApplication::translate("BpsUtil", "a month");
        return QCoreApplication::translate("BpsUtil", "%1 months").arg(months);
    }
    if (months < 24) return QCoreApplication::translate("BpsUtil", "about a year");
    return QCoreApplication::translate("BpsUtil", "over a year");
}

QString ShortKey(const QString& hex)
{
    if (hex.size() <= 16) return hex;
    return hex.left(8) + QString::fromUtf8("\xe2\x80\xa6") + hex.right(6);
}

QString DescribeEndpoint(const UniValue& endpoint)
{
    if (!endpoint.isObject()) return QString();

    const UniValue& network = find_value(endpoint, "network");
    const UniValue& address = find_value(endpoint, "address");
    const UniValue& address_hex = find_value(endpoint, "address_hex");
    const UniValue& port = find_value(endpoint, "port");

    QString host;
    if (address.isStr()) {
        host = QString::fromStdString(address.get_str());
        // An IPv6 literal needs brackets before a port can be appended.
        if (host.contains(':')) host = "[" + host + "]";
    } else if (address_hex.isStr()) {
        // onion, i2p and cjdns arrive as raw bytes. Rendering the real textual
        // form means reimplementing each network's encoding, and getting one of
        // them subtly wrong would print an address that does not exist. The
        // network name plus a recognisable prefix is honest about what is known.
        const QString raw = QString::fromStdString(address_hex.get_str());
        host = (network.isStr() ? QString::fromStdString(network.get_str()) : QCoreApplication::translate("BpsUtil", "unknown"))
               + " " + raw.left(10) + QString::fromUtf8("\xe2\x80\xa6");
    } else {
        return QString();
    }

    if (port.isNum()) return host + ":" + QString::number(port.get_int());
    return host;
}

QFont FixedPitchFont()
{
    return GUIUtil::fixedPitchFont();
}

namespace {

/** Passes a wheel turn on to the page unless the box has been clicked into. */
class WheelGuard : public QObject
{
public:
    explicit WheelGuard(QObject* parent) : QObject(parent) {}

    bool eventFilter(QObject* watched, QEvent* event) override
    {
        if (event->type() == QEvent::Wheel) {
            QWidget* w = qobject_cast<QWidget*>(watched);
            if (w && !w->hasFocus()) {
                // Ignored, so it goes on to the page behind the box.
                event->ignore();
                return true;
            }
        }
        return QObject::eventFilter(watched, event);
    }
};

} // namespace

void KeepWheelForPage(QWidget* page)
{
    WheelGuard* guard = new WheelGuard(page);
    for (QAbstractSpinBox* box : page->findChildren<QAbstractSpinBox*>()) {
        box->setFocusPolicy(Qt::StrongFocus);
        box->installEventFilter(guard);
    }
    for (QComboBox* box : page->findChildren<QComboBox*>()) {
        box->setFocusPolicy(Qt::StrongFocus);
        box->installEventFilter(guard);
    }
}

void TidyForms(QWidget* page)
{
    int widest = 0;
    QList<QWidget*> labels;
    for (QFormLayout* form : page->findChildren<QFormLayout*>()) {
        for (int row = 0; row < form->rowCount(); ++row) {
            QLayoutItem* label = form->itemAt(row, QFormLayout::LabelRole);
            if (label && label->widget()) {
                labels.append(label->widget());
                widest = std::max(widest, label->widget()->sizeHint().width());
            }
            QLayoutItem* field = form->itemAt(row, QFormLayout::FieldRole);
            QWidget* box = field ? field->widget() : nullptr;
            if (qobject_cast<QAbstractSpinBox*>(box) || qobject_cast<QComboBox*>(box)) {
                const int least = box->fontMetrics().averageCharWidth() * 16;
                box->setMaximumWidth(std::max(box->sizeHint().width(), least));
            }
        }
    }
    for (QWidget* label : labels) label->setMinimumWidth(widest);
}

namespace {

/**
 * On any of its labels resizing, sets them all to the height the tallest needs
 * at its width - once the layout has settled, since while it is being worked
 * out a label can briefly be a hundred pixels wide and many lines tall.
 */
class HeightMatcher : public QObject
{
public:
    HeightMatcher(const QList<QLabel*>& labels, QObject* parent) : QObject(parent), m_labels(labels) {}

    bool eventFilter(QObject* watched, QEvent* event) override
    {
        const QEvent::Type type = event->type();
        if ((type == QEvent::Resize || type == QEvent::Show || type == QEvent::Hide) && !m_pending) {
            m_pending = true;
            QTimer::singleShot(0, this, [this] { Match(); });
        }
        return QObject::eventFilter(watched, event);
    }

private:
    void Match()
    {
        m_pending = false;
        int tallest = 0;
        for (QLabel* label : m_labels) {
            if (label->isVisible()) tallest = std::max(tallest, label->heightForWidth(label->width()));
        }
        for (QLabel* label : m_labels) {
            if (label->minimumHeight() != tallest) label->setMinimumHeight(tallest);
        }
    }

    const QList<QLabel*> m_labels;
    bool m_pending{false};
};

class BpsStyle : public QProxyStyle
{
public:
    QSize sizeFromContents(ContentsType type, const QStyleOption* option, const QSize& contents,
                           const QWidget* widget) const override
    {
        QSize size = QProxyStyle::sizeFromContents(type, option, contents, widget);
        if (!option) return size;
        const int em = option->fontMetrics.averageCharWidth();
        if (type == CT_PushButton) {
            const QStyleOptionButton* button = qstyleoption_cast<const QStyleOptionButton*>(option);
            // About two characters' room either side of the text.
            if (button && !button->text.isEmpty()) size.setWidth(std::max(size.width(), contents.width() + 4 * em));
        } else if (type == CT_HeaderSection) {
            size.setWidth(size.width() + 2 * em);
        }
        return size;
    }
};

} // namespace

void SameHeight(const QList<QLabel*>& labels)
{
    if (labels.isEmpty()) return;
    HeightMatcher* matcher = new HeightMatcher(labels, labels.front());
    for (QLabel* label : labels) {
        label->setAlignment(Qt::AlignLeft | Qt::AlignTop);
        label->installEventFilter(matcher);
    }
}

void InstallStyle()
{
    // With no base given, the proxy draws with the platform's own style.
    QApplication::setStyle(new BpsStyle());
}

} // namespace BpsUtil
