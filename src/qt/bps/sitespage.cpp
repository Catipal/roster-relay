// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bps/sitespage.h>

#include <qt/bps/bpsrpc.h>

#include <QApplication>
#include <QDesktopServices>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QHBoxLayout>
#include <QImage>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegExp>
#include <QScrollBar>
#include <QSettings>
#include <QMouseEvent>
#include <QTextEdit>
#include <QTextDocument>
#include <QUrl>
#include <QVBoxLayout>

#include <functional>

/**
 * Qt's rich text view, read-only, asking the page for every resource instead
 * of any network. A text edit rather than Qt's text browser, which the Qt
 * every release is built against leaves out: the edit lays pages out the same
 * way, and the clicks on links are caught here, so nothing is followed by
 * itself.
 */
class SiteBrowser : public QTextEdit
{
public:
    explicit SiteBrowser(QWidget* parent) : QTextEdit(parent)
    {
        setReadOnly(true);
        setTextInteractionFlags(Qt::TextBrowserInteraction);
        viewport()->setMouseTracking(true);
    }
    std::function<QVariant(int, const QUrl&)> resource;
    std::function<void(const QUrl&)> clicked;

    QVariant loadResource(int type, const QUrl& name) override
    {
        return resource ? resource(type, name) : QVariant();
    }

protected:
    void mousePressEvent(QMouseEvent* e) override
    {
        m_pressed = e->button() == Qt::LeftButton ? anchorAt(e->pos()) : QString();
        m_pressed_at = e->pos();
        QTextEdit::mousePressEvent(e);
    }
    void mouseReleaseEvent(QMouseEvent* e) override
    {
        QTextEdit::mouseReleaseEvent(e);
        // A click is a press and a release on the same link, not a drag that
        // happened to end on one.
        const QString href = e->button() == Qt::LeftButton ? anchorAt(e->pos()) : QString();
        const bool still = (e->pos() - m_pressed_at).manhattanLength() < QApplication::startDragDistance();
        if (!href.isEmpty() && href == m_pressed && still && clicked) clicked(QUrl(href));
        m_pressed.clear();
    }
    void mouseMoveEvent(QMouseEvent* e) override
    {
        QTextEdit::mouseMoveEvent(e);
        viewport()->setCursor(anchorAt(e->pos()).isEmpty() ? Qt::IBeamCursor : Qt::PointingHandCursor);
    }

private:
    QString m_pressed;
    QPoint m_pressed_at;
};

namespace {

const char* TAG_PREFIX = "sites:";
//! Every page is laid out against this host, so a link back into the same
//! site is told apart from one to another site whatever the real host is.
const QString SAME_SITE = QStringLiteral("this-site");
//! Resources one page may ask for, so a page cannot keep the viewer busy.
constexpr int MAX_RESOURCES = 64;

bool IsHexKey(const QString& s)
{
    static const QRegExp hex(QStringLiteral("[0-9a-fA-F]{64}"));
    return hex.exactMatch(s);
}

QString Extension(const QString& path)
{
    return QFileInfo(path).suffix().toLower();
}

bool IsPage(const QString& path)
{
    const QString ext = Extension(path);
    return ext == "html" || ext == "htm";
}

bool IsImage(const QString& path)
{
    const QString ext = Extension(path);
    return ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "gif" || ext == "bmp";
}

bool IsText(const QString& path)
{
    const QString ext = Extension(path);
    return ext == "txt" || ext == "md" || ext == "css" || ext == "json" || ext == "xml" || ext == "csv";
}

UniValue Params(const QString& a, const QString& b = QString())
{
    UniValue p(UniValue::VARR);
    p.push_back(a.toStdString());
    if (!b.isNull()) p.push_back(b.toStdString());
    return p;
}

} // namespace

SitesPage::SitesPage(BpsRpc& rpc, QWidget* parent) : QWidget(parent), m_rpc(rpc)
{
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 18, 24, 12);
    outer->setSpacing(8);

    QLabel* title = new QLabel(tr("Sites"), this);
    QFont title_font = title->font();
    title_font.setPointSizeF(title_font.pointSizeF() * 1.6);
    title_font.setBold(true);
    title->setFont(title_font);
    outer->addWidget(title);

    QLabel* subtitle = new QLabel(
        tr("Sites hosted over the overlay, opened by a name or a key that someone shared with you. Pages are "
           "shown here with no scripts, and nothing on them is fetched from outside BPS, so a page cannot "
           "learn where you are."),
        this);
    subtitle->setWordWrap(true);
    subtitle->setEnabled(false);
    outer->addWidget(subtitle);

    QHBoxLayout* bar = new QHBoxLayout();
    m_back = new QPushButton(QString::fromUtf8("\xe2\x86\x90"), this);
    m_back->setToolTip(tr("Back"));
    m_forward = new QPushButton(QString::fromUtf8("\xe2\x86\x92"), this);
    m_forward->setToolTip(tr("Forward"));
    m_reload = new QPushButton(QString::fromUtf8("\xe2\x86\xbb"), this);
    m_reload->setToolTip(tr("Fetch the page again"));
    for (QPushButton* b : {m_back, m_forward, m_reload}) {
        b->setFixedWidth(36);
        bar->addWidget(b);
    }
    m_address = new QLineEdit(this);
    m_address->setPlaceholderText(tr("bps://name/ or a site's key"));
    bar->addWidget(m_address, 1);
    QPushButton* go = new QPushButton(tr("Open"), this);
    bar->addWidget(go);
    outer->addLayout(bar);

    m_route = new QLabel(this);
    m_route->setWordWrap(true);
    m_route->setEnabled(false);
    m_route->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outer->addWidget(m_route);

    m_notice = new QLabel(this);
    m_notice->setWordWrap(true);
    m_notice->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_notice->setStyleSheet("QLabel { border-left: 3px solid palette(highlight); padding: 4px 8px; }");
    m_notice->setVisible(false);
    outer->addWidget(m_notice);

    m_view = new SiteBrowser(this);
    m_view->resource = [this](int type, const QUrl& url) { return Resource(type, url); };
    outer->addWidget(m_view, 1);

    m_save = new QPushButton(tr("Save this file\xe2\x80\xa6"), this);
    m_save->setVisible(false);
    m_browser = new QPushButton(tr("Open in your browser"), this);
    m_browser->setToolTip(tr("The same site in an ordinary browser, through a server on this computer only. "
                             "Pages there may run scripts, so the viewer here stays the safer way to read a "
                             "hidden site."));
    m_browser->setEnabled(false);
    m_program = new QPushButton(tr("Connect to a program\xe2\x80\xa6"), this);
    m_program->setToolTip(tr("Reach a program this site runs - a chat server, a game - from a program on this "
                             "computer: BPS Relay listens on a port here and carries each connection to it over "
                             "the overlay."));
    m_program->setEnabled(false);
    QHBoxLayout* save_row = new QHBoxLayout();
    save_row->addWidget(m_browser);
    save_row->addWidget(m_program);
    save_row->addWidget(m_save);
    save_row->addStretch(1);
    outer->addLayout(save_row);

    connect(go, &QPushButton::clicked, this, &SitesPage::onGo);
    connect(m_address, &QLineEdit::returnPressed, this, &SitesPage::onGo);
    connect(m_back, &QPushButton::clicked, this, &SitesPage::onBack);
    connect(m_forward, &QPushButton::clicked, this, &SitesPage::onForward);
    connect(m_reload, &QPushButton::clicked, this, &SitesPage::onReload);
    connect(m_save, &QPushButton::clicked, this, &SitesPage::onSave);
    connect(m_browser, &QPushButton::clicked, this, &SitesPage::onBrowser);
    connect(m_program, &QPushButton::clicked, this, &SitesPage::onConnectService);
    m_view->clicked = [this](const QUrl& url) { onAnchor(url); };
    connect(&m_rpc, &BpsRpc::result, this, &SitesPage::onRpcResult);
    connect(&m_rpc, &BpsRpc::failed, this, &SitesPage::onRpcFailed);
    UpdateButtons();
}

bool SitesPage::Parse(const QString& address, Location& out)
{
    QString s = address.trimmed();
    if (s.startsWith(QStringLiteral("bps://"), Qt::CaseInsensitive)) s = s.mid(6);
    const int hash = s.indexOf('#');
    if (hash >= 0) {
        out.fragment = s.mid(hash + 1);
        s = s.left(hash);
    } else {
        out.fragment.clear();
    }
    const int query = s.indexOf('?');
    if (query >= 0) s = s.left(query);
    const int slash = s.indexOf('/');
    out.host = (slash < 0 ? s : s.left(slash)).trimmed();
    if (out.host.isEmpty() || out.host.contains(':')) return false;
    if (IsHexKey(out.host)) out.host = out.host.toLower();
    // The path as the site lists it: no leading slash, no "." or "..".
    QStringList parts;
    for (const QString& part : (slash < 0 ? QString() : s.mid(slash + 1)).split('/')) {
        if (part.isEmpty() || part == ".") continue;
        if (part == "..") {
            if (!parts.isEmpty()) parts.removeLast();
            continue;
        }
        parts << QUrl::fromPercentEncoding(part.toUtf8());
    }
    const bool dir = slash < 0 || s.endsWith('/') || parts.isEmpty();
    out.path = parts.join('/');
    if (dir) out.path += out.path.isEmpty() ? QStringLiteral("index.html") : QStringLiteral("/index.html");
    return true;
}

void SitesPage::Open(const QString& address)
{
    Location loc;
    if (!Parse(address, loc)) {
        ShowError(tr("That is not a site's address. Write a name or a key, like bps://pilot/."));
        return;
    }
    Navigate(loc, true);
}

void SitesPage::Navigate(const Location& loc, bool remember)
{
    if (remember && m_have_loc && loc.Address() != m_loc.Address()) {
        m_history << m_loc.Address();
        m_ahead.clear();
    }
    const bool same_site = m_have_loc && loc.host == m_loc.host;
    m_loc = loc;
    m_have_loc = true;
    m_address->setText(loc.Address());
    m_notice->setVisible(false);
    m_save->setVisible(false);
    m_file.clear();
    UpdateButtons();
    ++m_seq;

    if (same_site && !m_key.isEmpty()) {
        Fetch();
        return;
    }
    m_key.clear();
    m_cache.clear();
    if (IsHexKey(loc.host)) {
        m_key = loc.host;
        Fetch();
        return;
    }
    m_route->setText(tr("Looking up %1\xe2\x80\xa6").arg(loc.host));
    m_rpc.Call(QString("%1resolve:%2").arg(TAG_PREFIX).arg(m_seq), "resolvename", Params(loc.host));
}

void SitesPage::Fetch()
{
    const QString cached = m_key + "/" + m_loc.path;
    m_pending.clear();
    m_failed.clear();
    if (m_cache.contains(cached)) {
        Show(m_cache.value(cached));
        return;
    }
    m_route->setText(tr("Fetching %1 over the overlay\xe2\x80\xa6").arg(m_loc.Address()));
    m_rpc.Call(QString("%1page:%2").arg(TAG_PREFIX).arg(m_seq), "getsite", Params(m_key, m_loc.path));
}

void SitesPage::Show(const QByteArray& bytes)
{
    m_arrived = false;
    const QString path = m_loc.path;
    const int slash = path.lastIndexOf('/');
    const QString dir = slash < 0 ? QString() : path.left(slash + 1);
    m_view->document()->setBaseUrl(QUrl("bps://" + SAME_SITE + "/" + dir));

    if (IsPage(path)) {
        m_source = QString::fromUtf8(bytes);
        m_html = WithStyles();
        m_view->setHtml(m_html);
    } else if (IsImage(path)) {
        m_source.clear();
        m_html = QString("<p><img src=\"bps://%1/%2\"></p>").arg(SAME_SITE, path.toHtmlEscaped());
        m_view->setHtml(m_html);
    } else if (IsText(path)) {
        m_source.clear();
        m_html.clear();
        m_view->setPlainText(QString::fromUtf8(bytes));
    } else {
        m_html.clear();
        m_file = bytes;
        m_view->setPlainText(tr("%1 is not a page this viewer shows (%2 bytes). Save it to open it with "
                                "another program.")
                                 .arg(QFileInfo(path).fileName())
                                 .arg(bytes.size()));
        m_save->setVisible(true);
    }
    if (!m_loc.fragment.isEmpty()) m_view->scrollToAnchor(m_loc.fragment);
}

QVariant SitesPage::Resource(int type, const QUrl& asked)
{
    // A stylesheet's address can come as written in the page, not yet
    // resolved against it.
    const QUrl url = asked.isRelative() ? m_view->document()->baseUrl().resolved(asked) : asked;
    // Only from the site being shown: an image or a stylesheet from anywhere
    // else would be a request that could say where the reader is.
    if (url.scheme() != "bps" || url.host() != SAME_SITE || m_key.isEmpty()) return QVariant();
    if (type != QTextDocument::ImageResource && type != QTextDocument::StyleSheetResource) return QVariant();
    Location loc;
    if (!Parse("bps://x" + url.path(), loc)) return QVariant();
    const QString cached = m_key + "/" + loc.path;
    if (m_cache.contains(cached)) {
        const QByteArray& bytes = m_cache[cached];
        if (type == QTextDocument::ImageResource) return QImage::fromData(bytes);
        return QString::fromUtf8(bytes);
    }
    Want(loc.path);
    return QVariant();
}

void SitesPage::onRpcResult(const QString& tag, const UniValue& value)
{
    if (!tag.startsWith(TAG_PREFIX)) return;
    const QStringList parts = tag.mid(QString(TAG_PREFIX).size()).split(':');
    if (parts.size() < 2 || parts[1].toInt() != m_seq) return; // an answer to a page left behind
    const QString kind = parts[0];

    if (kind == "program") {
        const UniValue& address = find_value(value, "address");
        ShowNotice(tr("Point the program on this computer at %1: BPS Relay carries every connection made there to "
                      "the site's program, over the overlay, until it restarts.")
                       .arg(QString::fromStdString(address.getValStr())));
        return;
    }

    if (kind == "browser") {
        const UniValue& browser = find_value(value, "browser");
        if (!browser.isStr()) {
            ShowNotice(tr("The site server for browsers is not running. It starts with BPS Relay unless -siteproxy=0 "
                          "was given."));
            return;
        }
        OpenInBrowser(QString::fromStdString(browser.get_str()));
        return;
    }

    if (kind == "resolve") {
        const UniValue& key = find_value(value, "key");
        if (!key.isStr()) {
            ShowError(tr("%1 does not resolve to a key.").arg(m_loc.host));
            return;
        }
        m_key = QString::fromStdString(key.get_str());
        // A name can change hands. Say so when it now points somewhere else.
        QSettings settings;
        const QString remembered = settings.value("bps/sitekeys/" + m_loc.host).toString();
        if (!remembered.isEmpty() && remembered != m_key) {
            ShowNotice(tr("%1 now points to a different key than when you last opened it. Whoever holds the "
                          "name now may not be who you read before.")
                           .arg(m_loc.host));
        }
        settings.setValue("bps/sitekeys/" + m_loc.host, m_key);
        Fetch();
        return;
    }

    const UniValue& hex = find_value(value, "hex");
    const QByteArray bytes = QByteArray::fromHex(hex.isStr() ? QByteArray::fromStdString(hex.get_str()) : QByteArray());

    if (kind == "page") {
        m_cache[m_key + "/" + m_loc.path] = bytes;
        const UniValue& route = find_value(value, "route");
        const int hops = find_value(route, "hops").isNum() ? find_value(route, "hops").get_int() : 0;
        if (find_value(route, "hidden").isTrue()) {
            m_route->setText(tr("Met at one of its meeting points, through %1 relays of yours: neither you nor "
                                "the host learns where the other is.")
                                 .arg(hops));
        } else if (hops > 0) {
            m_route->setText(tr("Reached at its address through %1 relays: the host does not learn who you are.")
                                 .arg(hops));
        } else {
            m_route->setText(tr("Your own site, read from this computer."));
        }
        // A radio link carries a few kilobytes a minute: a slow page is not a broken one.
        if (find_value(route, "radio").isTrue()) {
            m_route->setText(m_route->text() + " " + tr("It is reached over the radio, so pages come slowly."));
        }
        Show(bytes);
        return;
    }

    if (kind == "res" && parts.size() >= 3) {
        const QString path = QStringList(parts.mid(2)).join(':');
        const QString cached = m_key + "/" + path;
        m_pending.remove(cached);
        m_cache[cached] = bytes;
        m_arrived = true;
        // Laid out again once everything asked for is back, so the page does
        // not jump at every image.
        if (m_pending.isEmpty()) Relayout();
    }
}

void SitesPage::onRpcFailed(const QString& tag, const QString& message)
{
    if (!tag.startsWith(TAG_PREFIX)) return;
    const QStringList parts = tag.mid(QString(TAG_PREFIX).size()).split(':');
    if (parts.size() < 2 || parts[1].toInt() != m_seq) return;
    const QString kind = parts[0];
    if (kind == "resolve") {
        ShowError(tr("%1 is not a name this node knows: %2").arg(m_loc.host, message));
    } else if (kind == "program" || kind == "browser") {
        ShowNotice(message);
    } else if (kind == "page") {
        ShowError(tr("Could not open %1: %2").arg(m_loc.Address(), message));
    } else if (kind == "res" && parts.size() >= 3) {
        const QString cached = m_key + "/" + QStringList(parts.mid(2)).join(':');
        m_pending.remove(cached);
        m_failed.insert(cached);
        if (m_pending.isEmpty()) Relayout();
    }
}

void SitesPage::onAnchor(const QUrl& raw)
{
    // Qt hands a link over as written in the page: a place in it, or an
    // address still to resolve against the page's own.
    if (raw.toString().startsWith('#')) {
        m_view->scrollToAnchor(raw.fragment());
        return;
    }
    const QUrl url = raw.isRelative() ? m_view->document()->baseUrl().resolved(raw) : raw;
    if (url.scheme() == "bps") {
        if (url.host() == SAME_SITE) {
            Location loc;
            if (Parse("bps://" + m_loc.host + url.path() + (url.hasFragment() ? "#" + url.fragment() : QString()), loc)) {
                if (loc.path == m_loc.path && !loc.fragment.isEmpty()) {
                    m_view->scrollToAnchor(loc.fragment);
                    return;
                }
                Navigate(loc, true);
            }
        } else {
            Open(url.toString());
        }
        return;
    }
    if (url.scheme().isEmpty() && url.hasFragment()) {
        m_view->scrollToAnchor(url.fragment());
        return;
    }
    ShowNotice(tr("This link leads outside BPS, so it was not followed: %1\nOpen it in an ordinary browser if "
                  "you choose to; whoever runs it will see your address.")
                   .arg(url.toString()));
}

void SitesPage::onConnectService()
{
    if (!m_have_loc) return;
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Connect to a program"),
        tr("The name the site gave its program:"), QLineEdit::Normal, QString(), &ok).trimmed();
    if (!ok || name.isEmpty()) return;
    m_rpc.Call(QString("%1program:%2").arg(TAG_PREFIX).arg(m_seq), "connectservice", Params(m_loc.host, name));
}

void SitesPage::onBrowser()
{
    if (!m_have_loc) return;
    m_rpc.Call(QString("%1browser:%2").arg(TAG_PREFIX).arg(m_seq), "getsiteaddress", Params(m_loc.host));
}

void SitesPage::OpenInBrowser(const QString& base)
{
    // Said once, the first time: what a browser can do that the viewer cannot.
    QSettings settings;
    if (!settings.value("bps/siteproxywarned", false).toBool()) {
        const auto answer = QMessageBox::information(this, tr("Opening a site in your browser"),
            tr("Your browser will ask this computer for the site, and BPS Relay fetches it over the overlay, as "
               "it does here. Each page may load only from its own site, so it cannot pull anything from the open "
               "internet to learn where you are.\n\nWhat a browser can still do: a script can use WebRTC to show "
               "a page this computer's addresses, and a link you follow to an ordinary site leaves as any link "
               "does. The viewer in BPS Relay runs no scripts and stays the safer way to read a hidden site."),
            QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Ok);
        if (answer != QMessageBox::Ok) return;
        settings.setValue("bps/siteproxywarned", true);
    }
    const QString path = m_loc.path == "index.html" ? QString() : m_loc.path;
    QDesktopServices::openUrl(QUrl(base + path));
}

void SitesPage::onGo()
{
    if (!m_address->text().trimmed().isEmpty()) Open(m_address->text());
}

void SitesPage::onBack()
{
    if (m_history.isEmpty()) return;
    const QString prev = m_history.takeLast();
    if (m_have_loc) m_ahead << m_loc.Address();
    Location loc;
    if (Parse(prev, loc)) Navigate(loc, false);
}

void SitesPage::onForward()
{
    if (m_ahead.isEmpty()) return;
    const QString next = m_ahead.takeLast();
    if (m_have_loc) m_history << m_loc.Address();
    Location loc;
    if (Parse(next, loc)) Navigate(loc, false);
}

void SitesPage::onReload()
{
    if (!m_have_loc) return;
    m_cache.remove(m_key + "/" + m_loc.path);
    ++m_seq;
    if (m_key.isEmpty()) {
        Navigate(m_loc, false);
    } else {
        Fetch();
    }
}

void SitesPage::onSave()
{
    if (m_file.isEmpty() && !m_have_loc) return;
    const QString name = QFileDialog::getSaveFileName(this, tr("Save the file"), QFileInfo(m_loc.path).fileName());
    if (name.isEmpty()) return;
    QFile f(name);
    if (!f.open(QIODevice::WriteOnly) || f.write(m_file) != m_file.size()) {
        ShowNotice(tr("Could not save %1.").arg(name));
    }
}

void SitesPage::Relayout()
{
    if (!m_arrived || m_html.isEmpty()) return;
    m_arrived = false;
    if (!m_source.isEmpty()) m_html = WithStyles();
    // Where the reader was, kept across laying the page out again.
    const int at = m_view->verticalScrollBar()->value();
    m_view->setHtml(m_html);
    m_view->verticalScrollBar()->setValue(at);
}

QString SitesPage::WithStyles()
{
    // A linked stylesheet is fetched here like an image and put in the page,
    // rather than left to Qt's parser: it loads one only when the link says
    // type="text/css", which pages written today leave out.
    static const QRegExp link(QStringLiteral("<link\\b[^>]*\\brel\\s*=\\s*[\"']?stylesheet[\"']?[^>]*>"),
                              Qt::CaseInsensitive);
    static const QRegExp href(QStringLiteral("\\bhref\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))"),
                              Qt::CaseInsensitive);
    QString html = m_source;
    int at = 0;
    while ((at = link.indexIn(html, at)) >= 0) {
        const QString tag = link.cap(0);
        QString inline_css;
        if (href.indexIn(tag) >= 0) {
            const QString target = !href.cap(2).isEmpty() ? href.cap(2) : !href.cap(3).isEmpty() ? href.cap(3) : href.cap(4);
            const QUrl url = m_view->document()->baseUrl().resolved(QUrl(target));
            Location loc;
            // Only from the site being shown, as everything else on the page.
            if (url.scheme() == "bps" && url.host() == SAME_SITE && Parse("bps://x" + url.path(), loc)) {
                const QString cached = m_key + "/" + loc.path;
                if (m_cache.contains(cached)) {
                    inline_css = QString("<style>%1</style>").arg(QString::fromUtf8(m_cache.value(cached)));
                } else {
                    Want(loc.path);
                }
            }
        }
        html.replace(at, tag.size(), inline_css);
        at += inline_css.size();
    }
    return html;
}

void SitesPage::Want(const QString& path)
{
    const QString cached = m_key + "/" + path;
    if (m_pending.contains(cached) || m_failed.contains(cached) || m_pending.size() + m_failed.size() >= MAX_RESOURCES) {
        return;
    }
    m_pending.insert(cached);
    m_rpc.Call(QString("%1res:%2:%3").arg(TAG_PREFIX).arg(m_seq).arg(path), "getsite", Params(m_key, path));
}

void SitesPage::ShowError(const QString& text)
{
    m_route->setText(QString());
    m_html.clear();
    m_view->setPlainText(text);
}

void SitesPage::ShowNotice(const QString& text)
{
    m_notice->setText(text);
    m_notice->setVisible(true);
}

void SitesPage::UpdateButtons()
{
    m_browser->setEnabled(m_have_loc);
    m_program->setEnabled(m_have_loc);
    m_back->setEnabled(!m_history.isEmpty());
    m_forward->setEnabled(!m_ahead.isEmpty());
    m_reload->setEnabled(m_have_loc);
}
