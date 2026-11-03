import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// The six digits to compare with the home node's, while it decides.
ColumnLayout {
    id: root
    signal giveUp()
    spacing: 20

    Item { implicitHeight: 24 }
    PageTitle { text: qsTr("Compare these digits"); Layout.fillWidth: true }
    Label {
        text: qsTr("Your home node shows six digits too. Accept there only if they are the same as these.")
        color: Theme.muted
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Label {
        text: backend.pairingCode
        font.family: Theme.mono
        font.pixelSize: 44
        font.weight: Font.DemiBold
        font.letterSpacing: 4
        color: Theme.text
        Layout.alignment: Qt.AlignHCenter
        Layout.topMargin: 8
        Layout.bottomMargin: 8
    }
    RowLayout {
        spacing: 10
        Layout.fillWidth: true
        BusyIndicator { running: true; implicitWidth: 28; implicitHeight: 28 }
        Label {
            text: qsTr("Waiting to be accepted on the home node…")
            color: Theme.label
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
    }
    Label {
        visible: backend.error !== ""
        text: backend.error
        color: Theme.danger
        font.pixelSize: 14
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Label {
        text: qsTr("If they differ, someone else answered the code first. Reject it there and show a new one.")
        color: Theme.muted
        font.pixelSize: 14
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Item { Layout.fillHeight: true }
    QuietButton {
        text: qsTr("Start again")
        Layout.fillWidth: true
        onClicked: root.giveUp()
    }
}
