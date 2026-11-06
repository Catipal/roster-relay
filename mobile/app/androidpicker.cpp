// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <androidpicker.h>

#include <QJniObject>
#include <QMetaObject>
#include <QPointer>

namespace {

constexpr int REQUEST = 0x5143; // Ours among the activity's results.
constexpr int RESULT_OK = -1;   // Activity.RESULT_OK

QJniObject JString(const char* text)
{
    return QJniObject::fromString(QString::fromLatin1(text));
}

} // namespace

void AndroidPicturePicker::open()
{
    QJniObject intent("android/content/Intent", "(Ljava/lang/String;)V",
                      JString("android.intent.action.GET_CONTENT").object<jstring>());
    intent.callObjectMethod("setType", "(Ljava/lang/String;)Landroid/content/Intent;",
                            JString("image/*").object<jstring>());
    intent.callObjectMethod("addCategory", "(Ljava/lang/String;)Landroid/content/Intent;",
                            JString("android.intent.category.OPENABLE").object<jstring>());
    QtAndroidPrivate::startActivity(intent, REQUEST, this);
}

void AndroidPicturePicker::handleActivityResult(int request, int result, const QJniObject& data)
{
    if (request != REQUEST || result != RESULT_OK || !data.isValid()) return;
    const QJniObject uri = data.callObjectMethod("getData", "()Landroid/net/Uri;");
    if (!uri.isValid()) return;
    const QUrl url(uri.callObjectMethod("toString", "()Ljava/lang/String;").toString());
    // Answered on Android's thread; the picker lives on the GUI one.
    QPointer<AndroidPicturePicker> self(this);
    QMetaObject::invokeMethod(this, [self, url] {
        if (self) Q_EMIT self->picked(url);
    }, Qt::QueuedConnection);
}
