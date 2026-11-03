import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

ColumnLayout {
    spacing: 16

    Item { implicitHeight: 40 }
    PageTitle { text: qsTr("This phone is locked"); Layout.fillWidth: true }
    Label {
        text: qsTr("Five wrong PINs in a row. Unlock it on the home node: BPS Relay, Server, Phone companion, Unlock. Nothing can be sent until then.")
        color: Theme.muted
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Label {
        visible: backend.error !== ""
        text: backend.error
        color: Theme.danger
        font.pixelSize: 14
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Item { Layout.fillHeight: true }
    PrimaryButton {
        text: qsTr("Check again")
        enabled: !backend.busy
        Layout.fillWidth: true
        onClicked: backend.refresh()
    }
}
