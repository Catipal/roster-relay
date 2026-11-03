import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

Flickable {
    id: root
    property bool confirming: false
    contentHeight: column.implicitHeight + 48
    clip: true

    component Row2: RowLayout {
        property alias key: k.text
        property alias value: v.text
        property bool mono: false
        Layout.fillWidth: true
        Layout.margins: 12
        Label { id: k; color: Theme.muted; Layout.fillWidth: true }
        Label { id: v; color: Theme.text; font.family: parent.mono ? Theme.mono : Qt.application.font.family; horizontalAlignment: Text.AlignRight }
    }

    ColumnLayout {
        id: column
        x: Theme.gutter
        y: 24
        width: root.width - 2 * Theme.gutter
        spacing: 16

        PageTitle { text: qsTr("Settings"); Layout.fillWidth: true }
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: rows.implicitHeight
            radius: 16
            color: Theme.surface
            border.color: Theme.line
            ColumnLayout {
                id: rows
                anchors.fill: parent
                spacing: 0
                Row2 { key: qsTr("This phone"); value: backend.phoneName }
                Row2 { key: qsTr("Home node"); value: backend.homeNode; mono: true }
                Row2 { key: qsTr("Network"); value: backend.network }
                Row2 { key: qsTr("Relays known"); value: backend.relaysKnown }
                Row2 {
                    key: qsTr("Device key")
                    value: backend.keyInKeystore ? qsTr("in the system keystore") : qsTr("in a plain file")
                }
                Row2 {
                    key: qsTr("Limits")
                    value: backend.status.perTx ? qsTr("%1 a payment, %2 a day").arg(backend.status.perTx).arg(backend.status.perDay) : "—"
                }
            }
        }
        Label {
            text: qsTr("The limits are set on the home node and only it can change them. This phone holds no coin keys: only a key of its own, which can spend nothing by itself.")
            color: Theme.muted
            font.pixelSize: 13
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Label {
            visible: !backend.keyInKeystore
            text: qsTr("No keystore was found on this system, so the device key is kept in a file only you can read. It still cannot spend without your PIN.")
            color: Theme.muted
            font.pixelSize: 13
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
        QuietButton {
            text: root.confirming ? qsTr("Unpair: are you sure?") : qsTr("Unpair this phone")
            tint: Theme.danger
            enabled: !backend.busy
            Layout.fillWidth: true
            onClicked: root.confirming ? backend.unpair() : (root.confirming = true)
        }
        QuietButton {
            visible: root.confirming
            flat: true
            text: qsTr("Forget the home node here only (it cannot be reached)")
            tint: Theme.muted
            Layout.fillWidth: true
            onClicked: backend.forget()
        }
    }
}
