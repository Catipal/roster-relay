// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BPS_SITESPAGE_H
#define BITCOIN_QT_BPS_SITESPAGE_H

#include <univalue.h>

#include <QByteArray>
#include <QMap>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QWidget>

class BpsRpc;
class SiteBrowser;

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
class QPushButton;
QT_END_NAMESPACE

/**
 * Reading sites hosted over the overlay (design note §11·6).
 *
 * The safe way in. Pages are shown in Qt's rich text view, which renders HTML
 * and a subset of CSS with images, runs no scripts and has no network of its
 * own: everything it shows was fetched over the overlay, by getsite, from the
 * site it is showing and nowhere else. A link to bps://name/path or
 * bps://<key>/path is followed over the overlay; any other link is shown, not
 * followed. So a page cannot learn where its reader is, whatever it contains.
 *
 * A name can change hands (§11). The page remembers the key behind each name
 * it has shown, and says so plainly when a name later points elsewhere.
 */
class SitesPage : public QWidget
{
    Q_OBJECT

public:
    explicit SitesPage(BpsRpc& rpc, QWidget* parent = nullptr);

    /** Open an address: bps://name/path, name/path, a key, or a key and a path. */
    void Open(const QString& address);

private Q_SLOTS:
    void onGo();
    void onBack();
    void onForward();
    void onReload();
    void onSave();
    void onBrowser();
    void onConnectService();
    void onAnchor(const QUrl& raw);
    void onRpcResult(const QString& tag, const UniValue& value);
    void onRpcFailed(const QString& tag, const QString& message);

private:
    /** Where one address points. */
    struct Location {
        QString host;     //!< a name, or the key in hex
        QString path;     //!< within the site, never empty
        QString fragment; //!< a place in the page, if any
        QString Address() const { return "bps://" + host + "/" + path; }
    };
    static bool Parse(const QString& address, Location& out);

    void Navigate(const Location& loc, bool remember);
    void Fetch();
    void Show(const QByteArray& bytes);
    /** Lay the page out again once what it showed has arrived, keeping the reader's place. */
    void Relayout();
    /** The page with its stylesheets put in it, asking for those not here yet. */
    QString WithStyles();
    /** Ask for one file of the site shown, as part of the page. */
    void Want(const QString& path);
    void ShowError(const QString& text);
    void ShowNotice(const QString& text);
    void UpdateButtons();
    /** Open `base` (the site in a browser) and the current page in it, saying once what that means. */
    void OpenInBrowser(const QString& base);
    QVariant Resource(int type, const QUrl& url);

    BpsRpc& m_rpc;
    QLineEdit* m_address{nullptr};
    QPushButton* m_back{nullptr};
    QPushButton* m_forward{nullptr};
    QPushButton* m_reload{nullptr};
    QPushButton* m_save{nullptr};
    QPushButton* m_browser{nullptr};
    QPushButton* m_program{nullptr};
    QLabel* m_route{nullptr};
    QLabel* m_notice{nullptr};
    SiteBrowser* m_view{nullptr};

    QStringList m_history;   //!< addresses behind the current one
    QStringList m_ahead;     //!< addresses Back left
    Location m_loc;
    bool m_have_loc{false};
    QString m_key;           //!< the site key the current host resolved to
    int m_seq{0};            //!< answers to older requests are ignored
    QString m_source;        //!< the page as fetched
    QString m_html;          //!< the page shown, to lay out again as pieces of it arrive
    QMap<QString, QByteArray> m_cache;  //!< key/path -> bytes, this site's files
    QSet<QString> m_pending;            //!< resources asked for and not yet back
    QSet<QString> m_failed;             //!< resources that could not be had
    bool m_arrived{false};              //!< a resource came since the page was laid out
    QByteArray m_file;                  //!< a file that is not a page, to save
};

#endif // BITCOIN_QT_BPS_SITESPAGE_H
