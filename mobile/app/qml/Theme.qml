pragma Singleton
import QtQuick

// The simulation's colours and sizes, in one place.
QtObject {
    readonly property color accent: "#1F6FB2"
    readonly property color accentDark: "#174F80"
    readonly property color background: "#F3F5F8"
    readonly property color surface: "#FFFFFF"
    readonly property color text: "#16202B"
    readonly property color label: "#3A4654"
    readonly property color muted: "#5A6675"
    readonly property color line: "#E1E6EC"
    readonly property color border: "#C9D2DC"
    readonly property color danger: "#B42318"
    readonly property color good: "#1A7F4B"
    readonly property int gutter: 24
    readonly property int radius: 12
    readonly property string mono: "monospace"
}
