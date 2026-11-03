import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// A label over a text field, with an optional note under it.
ColumnLayout {
    id: root
    property alias label: caption.text
    property alias text: input.text
    property alias placeholder: input.placeholderText
    property alias inputMethodHints: input.inputMethodHints
    property alias field: input
    property string note: ""
    spacing: 6

    Label {
        id: caption
        font.pixelSize: 13
        font.weight: Font.DemiBold
        color: Theme.label
    }
    TextField {
        id: input
        Layout.fillWidth: true
        implicitHeight: 48
        font.pixelSize: 16
        color: Theme.text
        leftPadding: 12
        rightPadding: 12
        background: Rectangle {
            radius: Theme.radius
            color: Theme.surface
            border.width: input.activeFocus ? 2 : 1
            border.color: input.activeFocus ? Theme.accent : Theme.border
        }
    }
    Label {
        visible: root.note !== ""
        text: root.note
        font.pixelSize: 13
        color: Theme.muted
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
}
