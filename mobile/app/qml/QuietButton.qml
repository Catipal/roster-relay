import QtQuick
import QtQuick.Controls.Basic

// A button with a border and no fill, or with neither when `flat`.
Button {
    id: control
    property color tint: Theme.text
    implicitHeight: flat ? 44 : 52
    font.pixelSize: flat ? 14 : 16
    font.weight: Font.DemiBold
    contentItem: Text {
        text: control.text
        font: control.font
        color: control.enabled ? control.tint : Theme.muted
        horizontalAlignment: control.flat ? Text.AlignLeft : Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }
    background: Rectangle {
        radius: Theme.radius
        color: control.flat ? "transparent" : control.down ? Theme.line : Theme.surface
        border.width: control.flat ? 0 : 1
        border.color: Theme.border
    }
}
