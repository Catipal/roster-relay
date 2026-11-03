import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// A page's heading, with a way back when `back` is set.
RowLayout {
    id: root
    property alias text: heading.text
    property bool back: false
    signal backClicked()
    spacing: 8

    ToolButton {
        visible: root.back
        text: "←"
        font.pixelSize: 22
        implicitWidth: 44
        implicitHeight: 44
        Accessible.name: qsTr("Back")
        onClicked: root.backClicked()
        background: Item {}
    }
    Label {
        id: heading
        font.pixelSize: root.back ? 20 : 28
        font.weight: Font.Bold
        color: Theme.text
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
}
