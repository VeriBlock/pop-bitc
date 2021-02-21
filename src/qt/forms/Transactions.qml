import QtQuick 2.7
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0
import QtQuick.Layouts 1.3

Item {
    id: transactionsForm
    width: 1280
    height: 900

    property int  datewidth : 150
    property int  typewidth : 150
    property int  addresswidth : 150
    property int  amountwidth : 220
    property int  amountusdwidth : 220
    property int  amountgoldwidth : 220
    property alias listView: listView
    property alias listViewlinks: listViewlinks

    property int  datewidthan : 150
    property int  btnswidthan : 50
    property int  btnswidth2an : 50
    property int  linkwidthan : 400
    property int  amountwidthan : 220
    property int currencywidthan: 70
    property string txidtext

    function settxdetailsintern(text, txid) {
        detailarea.text=text
        detaildialog.visible=true
        txidtext = txid
    }

    signal showtxdetailsintern(int index)
    signal filtereditchangedsignalintern(string text)
    signal datefiltersignalintern(int index)
    signal downloadtransactionsSignalintern()
    signal deletelinksignalintern(string link)
    signal undolinkremovalSignalintern()
    signal abandonTxSignalintern(string txidtext)
    signal printstatementsignalintern(int month, int year, int currency)

    function setactualmonthandyearintern(month, year)
    {
        printstatements.spinBox.value = month;
        printstatements.spinBoxyear.value = year;
    }

    function addbitcashexpresslinkintern(link,desc,amount,date,currency) {
        linksmodel.insert(0,{
                               "name": link,
                               "description": desc,
                               "amount": amount,
                               "txdate": date,
                               "currency": currency
                           })
    }

    function closelinksundoinfointern(show) {
        infobox.visible=show
    }
    function clearlinklistmodelintern() {
        linksmodel.clear()
    }

    function geticonname(nr)
    {
        if (nr===1) return "../res/assets/Type of Transaction/history-type-sent.png";else
        if (nr===2) return "../res/assets/Type of Transaction/history-type-mined.png";else
        return "../res/assets/Type of Transaction/history-type-received.png";
    }

    ListModel {
        id: linksmodel

       /* ListElement {
            name: "Apple"
            amount: 2.45
            description: "hgfhdh"
        }
        ListElement {
            name: "Orange"
            amount: 3.25
            description: "f435345"
        }
        ListElement {
            name: "Banana"
            amount: 1.95
            description: "ffff"
        }*/
    }

    Image {
        id: historyicon
        y: 36
        anchors.verticalCenter: historycap.verticalCenter
        anchors.left: parent.left
        anchors.leftMargin: 30
        fillMode: Image.PreserveAspectFit
        source: "../res/assets/Headlines/history.png"
    }

    Text {
        id: historycap
        y: 30
        width: 97
        color: "#202124"
        anchors.left: historyicon.right
        anchors.leftMargin: 15
        text: qsTr("History")
        font.pixelSize: 20
        font.family: "Montserrat SemiBold"
        font.weight: Font.DemiBold
    }

    TabBar {
        id: tabBar
        font.capitalization: Font.MixedCase
        font.family: "Montserrat SemiBold"
        currentIndex: swipeView.currentIndex
        width: parent.width
        height: 60
        visible: true

        position: TabBar.Header
        anchors.topMargin: 10
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: historycap.bottom
        font.weight: Font.DemiBold
        font.pixelSize: 14

        TabButton {
            id: tabButton1
            y: 0
            text: qsTr("Transactions")
            rightPadding: 15
            leftPadding: 30
            width: implicitWidth
            height: 60
            contentItem: Text {
                id: textbitcash
                x: 58
                text: parent.text
                leftPadding: 0
                font: parent.font
                opacity: enabled ? 1.0 : 0.3
                color: "#4d505e"
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
            }
        }

        TabButton {
            id: tabButton2
            text: qsTr("Generated links")
            rightPadding: 15
            font.capitalization: Font.MixedCase
            leftPadding: 15
            width: implicitWidth
            height: 60

            contentItem: Text {
                id: textanyone
                text: parent.text
                font: parent.font
                opacity: enabled ? 1.0 : 0.3
                color: "#4d505e"
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
            }
        }
        TabButton {
            id: tabButton3
            text: qsTr("Print eStatements")
            rightPadding: 15
            font.capitalization: Font.MixedCase
            leftPadding: 15
            width: implicitWidth
            height: 60

            contentItem: Text {
                id: textstatements
                text: parent.text
                font: parent.font
                opacity: enabled ? 1.0 : 0.3
                color: "#4d505e"
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
            }
        }

    }

    SwipeView {
        id: swipeView
        clip: true
        //interactive: false
        anchors.top: tabBar.bottom
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        currentIndex: tabBar.currentIndex
        Component.onCompleted: contentItem.interactive = false
        Item {
            id: transactions


            Row {
                id: header
                clip: true
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.leftMargin: 30
                anchors.rightMargin: 30
                anchors.top: filterEdit.bottom
                anchors.topMargin: 30
                spacing: 0
                height: 44


                Label {
                    //without this column the background color of the next colum is not displayed???
                    width: 1
                    height: 44
                    text: ""
                }
                Label {
                    width: datewidth
                    height: 44
                    text: qsTr("Date")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.family: "Montserrat SemiBold"
                    font.weight: Font.DemiBold
                    font.pixelSize: 13
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: typewidth
                    height: 44
                    text: qsTr("Type")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.family: "Montserrat SemiBold"
                    font.weight: Font.DemiBold
                    font.pixelSize: 13
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: addresswidth
                    height: 44
                    text: qsTr("Address")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.family: "Montserrat SemiBold"
                    font.weight: Font.DemiBold
                    font.pixelSize: 13
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: transactionsForm.width-datewidth-typewidth-addresswidth-amountwidth-amountusdwidth-amountgoldwidth-30-30
                    height: 44
                    text: qsTr("Description")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.family: "Montserrat SemiBold"
                    font.weight: Font.DemiBold
                    font.pixelSize: 13
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: amountwidth
                    height: 44
                    text: qsTr("BITC")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.family: "Montserrat SemiBold"
                    font.weight: Font.DemiBold
                    horizontalAlignment: Text.AlignRight
                    font.pixelSize: 13
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: amountusdwidth
                    height: 44
                    text: qsTr("USD")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.family: "Montserrat SemiBold"
                    font.weight: Font.DemiBold
                    horizontalAlignment: Text.AlignRight
                    font.pixelSize: 13
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: amountgoldwidth
                    height: 44
                    text: qsTr("Bitcoin")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.family: "Montserrat SemiBold"
                    font.weight: Font.DemiBold
                    horizontalAlignment: Text.AlignRight
                    font.pixelSize: 13
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
            }
            TextField
            {
                id: copytextfield
                width: 0
                height: 0
                visible: false
            }

            ListView {
                id: listView
                anchors.bottomMargin: 0
                anchors.top: header.bottom
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                clip: true

                    contentWidth: header.width
                    flickableDirection: Flickable.VerticalFlick

                    model: transactionsmodel
                    delegate: Column {
                        id: delegate
                        property int row: index


                        Row {
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.leftMargin: 30
                                anchors.rightMargin: 30
                                height: 65
                                spacing: 0
                                ItemDelegate {
                                    property int column: 0
                                    width: datewidth
                                    id: date
                                    text: ""
                                    clip: true
                                    Label {
                                        text: transactiondate
                                        anchors.leftMargin: 20
                                        anchors.rightMargin: 8
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        font.weight: Font.DemiBold
                                        font.family: "Montserrat SemiBold"
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: transactiondate+"\n"+tooltip
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenu.x = mouse.x;
                                            contextMenu.y = mouse.y;
                                            contextMenu.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenu.x = mouse.x;
                                                contextMenu.y = mouse.y;
                                                contextMenu.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenu
                                        MenuItem {
                                            text: qsTr("Copy date")
                                            onTriggered: {
                                                copytextfield.text=transactiondate
                                                copytextfield.selectAll()
                                                copytextfield.copy()
                                            }
                                        }
                                    }
                                    onDoubleClicked: {
                                        showtxdetailsintern(index)
                                    }
                                }
                                ItemDelegate {
                                    property int column: 1
                                    width: typewidth
                                    text: ""
                                    clip: true
                                    Image {
                                        id: typimage
                                        anchors.left: parent.left
                                        anchors.leftMargin: 20
                                        anchors.verticalCenter: parent.verticalCenter

                                        fillMode: Image.PreserveAspectFit
                                        source: geticonname(transactiontypeno)
                                    }
                                    Label {
                                        text: transactiontype
                                        anchors.leftMargin: 8
                                        anchors.rightMargin: 8
                                        anchors.left: typimage.right
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        font.weight: Font.Normal
                                        font.family: "Montserrat"
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: transactiontype+"\n"+tooltip
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenutyp.x = mouse.x;
                                            contextMenutyp.y = mouse.y;
                                            contextMenutyp.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenutyp.x = mouse.x;
                                                contextMenutyp.y = mouse.y;
                                                contextMenutyp.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenutyp
                                        MenuItem {
                                            text: qsTr("Copy type")
                                            onTriggered: {
                                                copytextfield.text=transactiontype
                                                copytextfield.selectAll()
                                                copytextfield.copy()
                                            }
                                        }
                                    }
                                    onDoubleClicked: {
                                        showtxdetailsintern(index)
                                    }
                                }
                                ItemDelegate {
                                    property int column: 2
                                    width: addresswidth
                                    text: ""
                                    Label {
                                        text: transactionaddress
                                        anchors.leftMargin: 20
                                        anchors.rightMargin: 8
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        font.weight: Font.Normal
                                        font.family: "Montserrat"
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    clip: true
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: transactionaddress+"\n"+tooltip
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenuaddress.x = mouse.x;
                                            contextMenuaddress.y = mouse.y;
                                            contextMenuaddress.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenuaddress.x = mouse.x;
                                                contextMenuaddress.y = mouse.y;
                                                contextMenuaddress.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenuaddress
                                        MenuItem {
                                            text: qsTr("Copy address")
                                            onTriggered: {
                                                copytextfield.text=transactionaddress
                                                copytextfield.selectAll()
                                                copytextfield.copy()
                                            }
                                        }
                                    }
                                    onDoubleClicked: {
                                        showtxdetailsintern(index)
                                    }
                                }
                                ItemDelegate {
                                    property int column: 3
                                    width: transactionsForm.width-datewidth-typewidth-addresswidth-amountwidth-amountusdwidth-amountgoldwidth-30-30
                                    text: ""
                                    Label {
                                        text: transactionreferenceline
                                        anchors.leftMargin: 20
                                        anchors.rightMargin: 8
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        font.weight: Font.Normal
                                        font.family: "Montserrat"
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    clip: true
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: transactionreferenceline+"\n"+tooltip
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenurefline.x = mouse.x;
                                            contextMenurefline.y = mouse.y;
                                            contextMenurefline.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenurefline.x = mouse.x;
                                                contextMenurefline.y = mouse.y;
                                                contextMenurefline.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenurefline
                                        MenuItem {
                                            text: qsTr("Copy description")
                                            onTriggered: {
                                                copytextfield.text=transactionreferenceline
                                                copytextfield.selectAll()
                                                copytextfield.copy()
                                            }
                                        }
                                    }
                                    onDoubleClicked: {
                                        showtxdetailsintern(index)
                                    }
                                }
                                ItemDelegate {
                                    property int column: 4
                                    width: amountwidth
                                    text: ""
                                    Label {
                                        text: transactionamountbitc
                                        anchors.leftMargin: 8
                                        anchors.rightMargin: 20
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        horizontalAlignment: Text.AlignRight
                                        font.weight: Font.Bold
                                        font.family: "Montserrat"
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    clip: true
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: transactionamountbitc+"\n"+tooltip
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenuamount.x = mouse.x;
                                            contextMenuamount.y = mouse.y;
                                            contextMenuamount.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenuamount.x = mouse.x;
                                                contextMenuamount.y = mouse.y;
                                                contextMenuamount.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenuamount
                                        MenuItem {
                                            text: qsTr("Copy amount BITC")
                                            onTriggered: {
                                                copytextfield.text= transactionamountbitc
                                                copytextfield.selectAll()
                                                copytextfield.copy()
                                            }
                                        }
                                    }
                                    onDoubleClicked: {
                                        showtxdetailsintern(index)
                                    }
                                }
                                ItemDelegate {
                                    property int column: 5
                                    width: amountusdwidth
                                    text: ""
                                    Label {
                                        text: transactionamountusd
                                        anchors.leftMargin: 8
                                        anchors.rightMargin: 20
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        horizontalAlignment: Text.AlignRight
                                        font.weight: Font.Bold
                                        font.family: "Montserrat"
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    clip: true
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: transactionamountusd+"\n"+tooltip
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenuamountusd.x = mouse.x;
                                            contextMenuamountusd.y = mouse.y;
                                            contextMenuamountusd.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenuamountusd.x = mouse.x;
                                                contextMenuamountusd.y = mouse.y;
                                                contextMenuamountusd.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenuamountusd
                                        MenuItem {
                                            text: qsTr("Copy amount USD")
                                            onTriggered: {
                                                copytextfield.text = transactionamountusd
                                                copytextfield.selectAll()
                                                copytextfield.copy()
                                            }
                                        }
                                    }
                                    onDoubleClicked: {
                                        showtxdetailsintern(index)
                                    }
                                }

                                ItemDelegate {
                                    property int column: 6
                                    width: amountgoldwidth
                                    text: ""
                                    Label {
                                        text: transactionamountbitcoin
                                        anchors.leftMargin: 8
                                        anchors.rightMargin: 20
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        horizontalAlignment: Text.AlignRight
                                        font.weight: Font.Bold
                                        font.family: "Montserrat"
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    clip: true
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: transactionamountbitcoin+"\n"+tooltip
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenuamountusd.x = mouse.x;
                                            contextMenuamountusd.y = mouse.y;
                                            contextMenuamountusd.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenuamountusd.x = mouse.x;
                                                contextMenuamountusd.y = mouse.y;
                                                contextMenuamountusd.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenuamountgold
                                        MenuItem {
                                            text: qsTr("Copy amount Bitcoin")
                                            onTriggered: {
                                                copytextfield.text = transactionamountbitcoin
                                                copytextfield.selectAll()
                                                copytextfield.copy()
                                            }
                                        }
                                    }
                                    onDoubleClicked: {
                                        showtxdetailsintern(index)
                                    }
                                }

                        }
                        Rectangle {
                            width: parent.width
                            height: 1
                            color: Material.accent
                        }
                    }

                    ScrollIndicator.horizontal: ScrollIndicator { }
                    ScrollIndicator.vertical: ScrollIndicator { }
            }

            MenuTextField {
                id: filterEdit
                y: 31
                height: 44
                text: ""
                font.pixelSize: 14
                font.family: "Montserrat"
                placeholderText: qsTr("Search for address, transaction id or description...")
                bottomPadding: 10
                topPadding: 10
                rightPadding: 16
                leftPadding: 46
                anchors.topMargin: 30
                anchors.top:parent.top
                anchors.right: downloadlistbtn.left
                anchors.rightMargin: 20
                anchors.left: dateselect.right
                anchors.leftMargin: 20
                selectByMouse: true
                onTextChanged: filtereditchangedsignalintern(text)
                background: Rectangle
                {
                    radius: 3
                    border.width: 1
                    border.color: "#eeeeef"
                    Image {
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.left: parent.left
                        anchors.leftMargin: 20
                        fillMode: Image.PreserveAspectFit
                        source: "../res/assets/Miscellaneous/search.png"
                    }

                }

            }

            Rectangle {
                id: detaildialog
                width: 600
                height: 500
                anchors.horizontalCenter: parent.horizontalCenter
                anchors.verticalCenter: parent.verticalCenter
                color:Material.background
                radius: 10
                border.width: 3
                visible: false

                TextArea{
                    id: detailarea
                    textFormat: Text.RichText
                    readOnly: true
                    anchors.left:parent.left
                    anchors.leftMargin: 10
                    anchors.top:parent.top
                    anchors.topMargin: 10
                    anchors.right: parent.right
                    anchors.rightMargin: 10
                    anchors.bottom:parent.bottom
                    anchors.bottomMargin: 70
                    selectByMouse: true
                    wrapMode: TextEdit.Wrap
                }
                Button{
                    text: qsTr("Ok")
                    anchors.horizontalCenterOffset: -100
                    id: okBtn
                    anchors.top:detailarea.bottom
                    anchors.topMargin: 10
                    anchors.horizontalCenter: parent.horizontalCenter
                    onClicked: detaildialog.visible=false
                }
                Button{
                    text: qsTr("Copy TX ID")
                    anchors.left: okBtn.right
                    anchors.leftMargin: 20
                    id: copyTxIdBtn
                    anchors.top:detailarea.bottom
                    anchors.topMargin: 10
                    onClicked: {
                        copytextfieldlinks.text = txidtext
                        copytextfieldlinks.selectAll()
                        copytextfieldlinks.copy()
                        text = "Copied"
                        timer.setTimeout(function(){
                            text = "Copy TX ID"
                        }, 3000);
                    }
                }
                Button{
                    text: qsTr("Abandon")
                    anchors.left: copyTxIdBtn.right
                    anchors.leftMargin: 20
                    id: removeBtn
                    anchors.top:detailarea.bottom
                    anchors.topMargin: 10
                    onClicked:abandonTxSignalintern(txidtext)
                }

            }

            ComboBox {
                currentIndex: 4
                id: dateselect
                onActivated: datefiltersignalintern(index)
                width: 200
                font.pixelSize: 14
                font.family: "Montserrat"
                anchors.top: parent.top
                anchors.topMargin: 28
                anchors.left: parent.left
                anchors.leftMargin: 30
                textRole: "key"
                model: ListModel {
                       ListElement { key: "Last month"; value: 1 }
                       ListElement { key: "Last 3 months"; value: 2 }
                       ListElement { key: "Last 6 months"; value: 3 }
                       ListElement { key: "Last year"; value: 4 }
                       ListElement { key: "Anytime"; value: 5 }
                }
            }


            Button {
                id: downloadlistbtn
                anchors.right: parent.right
                anchors.rightMargin: 40
                anchors.verticalCenter: filterEdit.verticalCenter
                width: 207
                onClicked: {
                    downloadtransactionsSignalintern()
                }
                y: 13
                background: Image {
                    id: imageforbutton
                    fillMode: Image.PreserveAspectFit
                    source: "../res/assets/Miscellaneous/download.png"
                    Label {
                        id: labelforbutton
                        color: "#3e45ac"
                        text: qsTr("Download list of transactions")
                        font.weight: Font.DemiBold
                        anchors.verticalCenterOffset: 0
                        font.pixelSize: 13
                        font.family: "Montserrat SemiBold"
                        anchors.left: parent.right
                        anchors.leftMargin: 10
                        anchors.verticalCenter: parent.verticalCenter
                    }
                }
            }
        } /////////////////// ENDE: transaction history

        Item {//////////// Generated links
            id: anyonelinke

            Row {
                id: headerlinks
                clip: true
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.leftMargin: 30
                anchors.rightMargin: 30
                anchors.top: parent.top
                anchors.topMargin: 20
                spacing: 0
                height: 44

                Label {
                    //without this column the background color of the next colum is not displayed???
                    width: 1
                    height: 44
                    text: ""
                }

                Label {
                    width: datewidth
                    height: 44
                    text: qsTr("Date")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.weight: Font.DemiBold
                    font.pixelSize: 13
                    font.family: "Montserrat SemiBold"
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: transactionsForm.width-amountwidthan-linkwidthan-btnswidth2an-btnswidthan-datewidthan-currencywidthan-30-30
                    height: 44
                    text: qsTr("Description")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.weight: Font.DemiBold
                    font.pixelSize: 13
                    font.family: "Montserrat SemiBold"
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }

                Label {
                    width: linkwidthan
                    height: 44
                    text: qsTr("Link")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.weight: Font.DemiBold
                    font.pixelSize: 13
                    font.family: "Montserrat SemiBold"
                    color:"#202124"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: btnswidthan
                    height: 44
                    text: ""
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.weight: Font.DemiBold
                    font.pixelSize: 13
                    font.family: "Montserrat SemiBold"
                    color:"black"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: amountwidthan
                    height: 44
                    text: qsTr("Amount")
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.weight: Font.DemiBold
                    horizontalAlignment: Text.AlignRight
                    font.pixelSize: 13
                    font.family: "Montserrat SemiBold"
                    color:"black"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: currencywidthan
                    height: 44
                    text: ""
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.weight: Font.DemiBold
                    horizontalAlignment: Text.AlignRight
                    font.pixelSize: 13
                    font.family: "Montserrat SemiBold"
                    color:"black"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
                Label {
                    width: btnswidth2an
                    height: 44
                    text: ""
                    verticalAlignment: Text.AlignVCenter
                    anchors.verticalCenter: parent.verticalCenter
                    rightPadding: 20
                    leftPadding: 20
                    font.weight: Font.DemiBold
                    font.pixelSize: 13
                    font.family: "Montserrat SemiBold"
                    color:"black"
                    padding: 10
                    background: Rectangle { color: "#ebebeb" }
                }
            }

            TextField
            {
                id: copytextfieldlinks
                width: 0
                height: 0
                visible: false
            }

            Timer {
                id: timer
                function setTimeout(cb, delayTime) {
                    timer.interval = delayTime;
                    timer.repeat = false;
                    timer.triggered.connect(cb);
                    timer.triggered.connect(function() {
                        timer.triggered.disconnect(cb); // This is important
                    });
                    timer.start();
                }
            }

            property alias listViewlinks: listViewlinks
            ListView {
                id: listViewlinks
                anchors.topMargin: 0
                anchors.bottomMargin: 0
                anchors.top: headerlinks.bottom
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                clip: true

                    contentWidth: headerlinks.width
                    flickableDirection: Flickable.VerticalFlick

                    model: linksmodel
                    delegate: Column {
                        id: delegatelinks
                        property int row: index


                        Row {
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.leftMargin: 30
                                anchors.rightMargin: 30
                                spacing: 0
                                height: 65

                                ItemDelegate {
                                    property int column: 0
                                    width: datewidth
                                    id: datelinks
                                    text: ""
                                    clip: true
                                    Label {
                                        text: txdate
                                        anchors.leftMargin: 20
                                        anchors.rightMargin: 8
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        font.pixelSize: 14
                                        font.weight: Font.DemiBold
                                        font.family: "Montserrat SemiBold"
                                        color: "#202124"
                                    }
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: txdate
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenulinks.x = mouse.x;
                                            contextMenulinks.y = mouse.y;
                                            contextMenulinks.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenulinks.x = mouse.x;
                                                contextMenulinks.y = mouse.y;
                                                contextMenulinks.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenulinks
                                        MenuItem {
                                            text: qsTr("Copy date")
                                            onTriggered: {
                                                copytextfieldlinks.text=txdate
                                                copytextfieldlinks.selectAll()
                                                copytextfieldlinks.copy()
                                            }
                                        }
                                    }
                                }

                                ItemDelegate {
                                    property int column: 1
                                    width: transactionsForm.width-linkwidthan-amountwidthan-datewidthan-btnswidthan-btnswidth2an-currencywidthan-30-30
                                    text: ""
                                    Label {
                                        text: description
                                        anchors.leftMargin: 20
                                        anchors.rightMargin: 8
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        font.weight: Font.Normal
                                        font.family: "Montserrat"
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    clip: true
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: description
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenureflinelinks.x = mouse.x;
                                            contextMenureflinelinks.y = mouse.y;
                                            contextMenureflinelinks.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenureflinelinks.x = mouse.x;
                                                contextMenureflinelinks.y = mouse.y;
                                                contextMenureflinelinks.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenureflinelinks
                                        MenuItem {
                                            text: qsTr("Copy description")
                                            onTriggered: {
                                                copytextfieldlinks.text=description
                                                copytextfieldlinks.selectAll()
                                                copytextfieldlinks.copy()
                                            }
                                        }
                                    }

                                }

                                ItemDelegate {
                                    property int column: 2
                                    width: linkwidthan
                                    text: ""
                                    Label {
                                        text: name
                                        anchors.leftMargin: 20
                                        anchors.rightMargin: 8
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        font.weight: Font.Normal
                                        font.family: "Montserrat"
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    clip: true
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: name
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenuaddresslinks.x = mouse.x;
                                            contextMenuaddresslinks.y = mouse.y;
                                            contextMenuaddresslinks.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenuaddresslinks.x = mouse.x;
                                                contextMenuaddresslinks.y = mouse.y;
                                                contextMenuaddresslinks.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenuaddresslinks
                                        MenuItem {
                                            text: qsTr("Copy link")
                                            onTriggered: {
                                                copytextfieldlinks.text=name
                                                copytextfieldlinks.selectAll()
                                                copytextfieldlinks.copy()
                                            }
                                        }
                                    }
                                }
                                ItemDelegate {
                                    property int column: 4
                                    width: btnswidthan
                                    text: ""
                                    Button {
                                        anchors.horizontalCenter: parent.horizontalCenter
                                        anchors.verticalCenter: parent.verticalCenter
                                        ToolTip.text: qsTr("Copy link")
                                        ToolTip.delay: 1000
                                        ToolTip.timeout: 5000
                                        ToolTip.visible: hovered
                                        id: copybtn
                                        onClicked: {
                                            copytextfieldlinks.text=name
                                            copytextfieldlinks.selectAll()
                                            copytextfieldlinks.copy()
                                            infoboxcopied.visible=true
                                            timer.setTimeout(function(){
                                                infoboxcopied.visible=false
                                            }, 3000);
                                        }
                                        background: Image {
                                            id: imageforbuttonlinks
                                            fillMode: Image.PreserveAspectFit
                                            source: "../res/assets/Miscellaneous/copy-link.png"
                                        }
                                    }
                                    clip: true

                                }
                                ItemDelegate {
                                    property int column: 3
                                    width: amountwidthan
                                    text: ""
                                    Label {
                                        text: amount
                                        anchors.leftMargin: 8
                                        anchors.rightMargin: 20
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        horizontalAlignment: Text.AlignRight

                                        font.family: "Montserrat"
                                        font.bold: true
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    clip: true
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: amount
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenuamountan.x = mouse.x;
                                            contextMenuamountan.y = mouse.y;
                                            contextMenuamountan.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenuamountan.x = mouse.x;
                                                contextMenuamountan.y = mouse.y;
                                                contextMenuamountan.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenuamountan
                                        MenuItem {
                                            text: qsTr("Copy amount")
                                            onTriggered: {
                                                copytextfieldlinks.text=amount
                                                copytextfieldlinks.selectAll()
                                                copytextfieldlinks.copy()
                                            }
                                        }
                                    }
                                }
                                ItemDelegate {
                                    property int column: 4
                                    width: currencywidthan
                                    text: ""
                                    Label {
                                        text: currency
                                        anchors.leftMargin: 8
                                        anchors.rightMargin: 20
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        horizontalAlignment: Text.AlignRight

                                        font.family: "Montserrat"
                                        font.bold: true
                                        font.pixelSize: 14
                                        color: "#202124"
                                    }
                                    clip: true
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    ToolTip.text: amount
                                    MouseArea {
                                        anchors.fill: parent
                                        acceptedButtons: Qt.RightButton
                                        hoverEnabled: true
                                        onClicked: {
                                            contextMenucurrencyan.x = mouse.x;
                                            contextMenucurrencyan.y = mouse.y;
                                            contextMenuamountan.open();
                                        }
                                        onPressAndHold: {
                                            if (mouse.source === Qt.MouseEventNotSynthesized) {
                                                contextMenucurrencyan.x = mouse.x;
                                                contextMenucurrencyan.y = mouse.y;
                                                contextMenucurrencyan.open();
                                            }
                                        }
                                    }
                                    Menu {
                                        id: contextMenucurrencyan
                                        MenuItem {
                                            text: qsTr("Copy currency")
                                            onTriggered: {
                                                copytextfieldlinks.text=currency
                                                copytextfieldlinks.selectAll()
                                                copytextfieldlinks.copy()
                                            }
                                        }
                                    }
                                }
                                ItemDelegate {
                                    property int column: 5
                                    width: btnswidth2an
                                    text: ""
                                    ToolTip.text: qsTr("Remove link")
                                    ToolTip.delay: 1000
                                    ToolTip.timeout: 5000
                                    ToolTip.visible: hovered
                                    Button {
                                        anchors.leftMargin: 20
                                        anchors.left: parent.left
                                        anchors.verticalCenter: parent.verticalCenter
                                        onClicked: {
                                            deletelinksignalintern(name)
                                            linksmodel.remove(index)
                                        }
                                        background: Image {
                                            id: imageforbutton2
                                            fillMode: Image.PreserveAspectFit
                                            source: "../res/assets/Miscellaneous/delete.png"
                                        }
                                    }
                                    clip: true

                                }

                        }
                        Rectangle {
                            width: parent.width
                            height: 1
                            color: Material.accent
                        }
                    }

                    ScrollIndicator.horizontal: ScrollIndicator { }
                    ScrollIndicator.vertical: ScrollIndicator { }
            }

            Label {
                id: label
                x: 8
                y: 234
                text: qsTr("Created links:")
                visible: false
            }

            Rectangle{
                id: infoboxcopied
                visible: false
                anchors.left:parent.left
                anchors.bottom:parent.bottom
                anchors.leftMargin: 30
                anchors.bottomMargin: 80
                height: 44
                width: 270
                radius: 3
                border.width: 0
                color: "#4d505e"
                Label{
                    text: qsTr("Link copied to clipboard.")
                    font.weight: Font.DemiBold
                    font.pixelSize: 14
                    font.family: "Montserrat SemiBold"
                    color: "#ffffff"
                    anchors.left:parent.left
                    anchors.leftMargin: 20
                    anchors.verticalCenter: parent.verticalCenter
                }
                Button {
                    id: closebuttoncopy
                    onClicked: infoboxcopied.visible = false
                    anchors.right: parent.right
                    anchors.rightMargin: 20
                    anchors.verticalCenter: parent.verticalCenter
                    width: 16
                    height: 16
                    background: Image {
                        x:0
                        y:0
                        fillMode: Image.PreserveAspectFit
                        source: "../res/icons/closebtngrey.png"
                    }
                }

            }

            Rectangle{
                id: infobox
                visible: false
                anchors.left:parent.left
                anchors.bottom:parent.bottom
                anchors.leftMargin: 30
                anchors.bottomMargin: 30
                height: 44
                width: 270
                radius: 3
                border.width: 0
                color: "#4d505e"
                Label{
                    text: qsTr("Removed link.")
                    font.weight: Font.DemiBold
                    font.pixelSize: 14
                    font.family: "Montserrat SemiBold"
                    color: "#ffffff"
                    anchors.left:parent.left
                    anchors.leftMargin: 20
                    anchors.verticalCenter: parent.verticalCenter
                }
                Button {
                    id: closebutton
                    onClicked: infobox.visible = false
                    anchors.right: parent.right
                    anchors.rightMargin: 20
                    anchors.verticalCenter: parent.verticalCenter
                    width: 16
                    height: 16
                    background: Image {
                        x:0
                        y:0
                        fillMode: Image.PreserveAspectFit
                        source: "../res/icons/closebtngrey.png"
                    }
                }
                Mybutton{
                    width: 61
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.right: closebutton.left
                    anchors.rightMargin: 20
                    text: qsTr("Undo")
                    font.weight: Font.DemiBold
                    leftPadding: 10
                    height:28
                    font.capitalization: Font.MixedCase
                    font.family: "Montserrat SemiBold"
                    btncolor: "#ffffff"
                    btncolordown: "#e5e5e5"
                    txtcolor: "#3e45ac"
                    txtcolordown: "#353b9b"
                    onClicked: undolinkremovalSignalintern()
                }
            }

            Rectangle{
                id: infoboxerror
                visible: false
                anchors.left:parent.left
                anchors.verticalCenter: parent.verticalCenter
                anchors.right: parent.right
                anchors.rightMargin: 30
                anchors.leftMargin: 30
                anchors.bottomMargin: 30
                height: 44
                width: 240
                radius: 3
                border.width: 0
                color: "#4d505e"
                Label{
                    id: errorlabel
                    text: ""
                    font.family: "Montserrat"
                    font.pixelSize: 11
                    color: "#ffffff"
                    anchors.left:parent.left
                    anchors.leftMargin: 20
                    anchors.verticalCenter: parent.verticalCenter
                }
                Button {
                    id: closebuttonerror
                    onClicked: infoboxerror.visible = false
                    anchors.right: parent.right
                    anchors.rightMargin: 20
                    anchors.verticalCenter: parent.verticalCenter
                    width: 16
                    height: 16
                    background: Image {
                        x:0
                        y:0
                        fillMode: Image.PreserveAspectFit
                        source: "../res/icons/closebtngrey.png"
                    }
                }

            }
        }/////////////// END generated links

        PrinteStatements {
            id: printstatements
            printbtn.onClicked: {
                var currencyforstatement = 0;
                if (radioButtonDollar.checked) {
                    currencyforstatement = 1;
                }

                printstatementsignalintern(spinBox.value, spinBoxyear.value, currencyforstatement)
            }
        }
  }

}
