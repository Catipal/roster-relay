import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// Dots for the digits typed and a keypad: six to twelve digits, then OK.
ColumnLayout {
    id: root
    property string pin: ""
    property bool active: true
    signal entered(string pin)
    spacing: 16

    function clear() { pin = "" }

    Row {
        Layout.alignment: Qt.AlignHCenter
        spacing: 14
        Accessible.name: qsTr("%n digit(s) entered", "", root.pin.length)
        Repeater {
            model: Math.max(6, root.pin.length)
            Rectangle {
                width: 14
                height: 14
                radius: 7
                color: index < root.pin.length ? Theme.accent : "transparent"
                border.width: 2
                border.color: index < root.pin.length ? Theme.accent : Theme.border
            }
        }
    }

    GridLayout {
        Layout.alignment: Qt.AlignHCenter
        columns: 3
        rowSpacing: 10
        columnSpacing: 22
        Repeater {
            model: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "ok", "0", "back"]
            Button {
                id: key
                readonly property bool digit: modelData !== "ok" && modelData !== "back"
                implicitWidth: 76
                implicitHeight: 64
                enabled: root.active && (digit ? root.pin.length < 12
                                                : modelData === "ok" ? root.pin.length >= 6 : root.pin.length > 0)
                text: modelData === "ok" ? qsTr("OK") : modelData === "back" ? "⌫" : modelData
                Accessible.name: modelData === "back" ? qsTr("Delete") : text
                font.pixelSize: digit ? 26 : 18
                font.weight: digit ? Font.Normal : Font.DemiBold
                contentItem: Text {
                    text: key.text
                    font: key.font
                    color: !key.enabled ? Theme.border : modelData === "ok" ? Theme.accent : Theme.text
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    radius: 32
                    color: key.down ? Theme.line : key.digit ? Theme.surface : "transparent"
                }
                onClicked: {
                    if (digit) root.pin += modelData
                    else if (modelData === "back") root.pin = root.pin.slice(0, -1)
                    else root.entered(root.pin)
                }
            }
        }
    }
}
