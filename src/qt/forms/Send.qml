import QtQuick 2.7
import QtQuick.Controls 2.0
import DestCheckValidator 1.0
import AmountEntryValidator 1.0
import DestCheckValidator2 1.0

SendForm {    
    signal sendBtnSignalIntern(string destination, string label, string description, double amount, bool substractfee)
    signal sendBtnDoSignalIntern(string destination, string label, string description, double amount, bool substractfee)
    signal sendBtnBiSignalIntern(string destination, string label, string description, double amount, bool substractfee)
    signal sendBtnGoSignalIntern(string destination, string label, string description, double amount, bool substractfee)
    signal printBtnDoSignalIntern()
    signal printBtnSignalIntern()
    signal sendBtntwSignalIntern(string destination, string description, double amount, int currency)
    signal sendBtninSignalIntern(string destination, string description, double amount, int currency)
    signal sendBtnreSignalIntern(string destination, string description, double amount, int currency)
    signal sendconfirmedBtntwSignalIntern(string destination, string description, double amount, int currency)
    signal sendconfirmedBtninSignalIntern(string destination, string description, double amount, int currency)
    signal sendconfirmedBtnreSignalIntern(string destination, string description, double amount, int currency)
    signal sendlinkBtnSignalIntern(string description, double amount, int currency)
    signal sendtoanyoneSignalIntern()
    signal viewaccounthistorysignal()
    signal gotooverviewsignal()

    property int confirmmode;

    Timer {
        id: timer
        function setTimeout(cb, delayTime) {
            timer.interval = delayTime
            timer.repeat = false
            timer.triggered.connect(cb)
            timer.triggered.connect(function () {
                timer.triggered.disconnect(cb) // This is important
            })
            timer.start()
        }        
    }

    function sendforinstaswapintern(amount, address)
    {
        tabBar.currentIndex=0
        paytoEdit.text = address
        descriptionEdit.text = "Send coins to InstaSwap to sell BitCash"
        amountEdit.text = amount
        amountEdit.forceActiveFocus()
        radioButton1.checked=true
    }

    function sendtodollarintern(address)
    {
        tabBar.currentIndex=0
        paytoEdit.text = address
        descriptionEdit.text = "Convert BitCash into BitCash Dollars; conversion price approx.: "+priceindollar2+" USD/BitCash"
        amountEdit.forceActiveFocus()
        radioButton1.checked=true
    }

    function sendtobitcashintern(address)
    {
        tabBar.currentIndex=0
        paytoEdit.text = address
        descriptionEdit.text = "Convert BitCash Dollars into BitCash; conversion price approx.: "+priceindollar+" USD/BitCash"
        amountEdit.forceActiveFocus()
        radioButton2.checked=true
    }

    function sendtogoldintern(address)
    {
        tabBar.currentIndex=0
        paytoEdit.text = address
        descriptionEdit.text = "Convert BitCash Dollars into Gold; conversion price approx.: "+priceingold+" USD/Gold ounce"
        amountEdit.forceActiveFocus()
        radioButton2.checked=true
    }

    function sendtodollarfromgoldintern(address)
    {
        tabBar.currentIndex=0
        paytoEdit.text = address
        descriptionEdit.text = "Convert Gold into BitCash Dollars; conversion price approx.: "+priceingold+" USD/Gold ounce"
        amountEdit.forceActiveFocus()
        radioButton3.checked=true
    }

    function displayerrormessageintern(msg) {
        errorlabel.text = msg
        infoboxerror.visible = true
        timer.setTimeout(function(){
            infoboxerror.visible = false
        }, 5000);
    }

    function gotosendtoanyone()
    {
        /**************************************/
        tabBar.currentIndex=4
        /**************************************/
    }

    function generatedlinkintern() {
        text11.text = qsTr("You have successfully generated a link which you can send to anyone. The link has been copied to the clipboard.")
        toolBar2.visible = true;
        timer.setTimeout(function(){
            toolBar2.visible = false
        }, 5000);
    }

    property string currency: "BITC"
    function showconfirmtwitterintern(msg)
    {
        confirmmode = 0

        if (radioButton2tw.checked){
            currency = "BTC";
        } else
        if (radioButton1tw.checked){
            currency = "BITC";
        } else
        if (radioButton3tw.checked){
            currency = "GOLD ounces";
        }

        if (descriptionEdittw.text !== ""){
            confirmtext.text = "You're about to send "+amountEdittw.text+" "+currency+" to @"+paytoEdittw.text+" with the following description: '"+descriptionEdittw.text+"'.\n\n Please confirm this transaction."
        }else
        {
            confirmtext.text = "You're about to send "+amountEdittw.text+" "+currency+" to @"+paytoEdittw.text+".\n\n Please confirm this transaction."
        }
        twitteruser.text = msg;
        twitteruser2.text = "@"+paytoEdittw.text;
        profileimage.source ="https://wallet.choosebitcash.com/gettwitteruserpic.php?twitteruser="+paytoEdittw.text;
        badgeimage.source = "../res/assets/Miscellaneous/twitter-badge.png"
        whitebox.visible = false
        whitebox2.visible = false
        whitebox3.visible = true
    }

    function showconfirminstaintern(msg)
    {
        confirmmode = 1
        if (radioButton2in.checked){
            currency = "BTC";
        } else
        if (radioButton1in.checked){
            currency = "BITC";
        } else
        if (radioButton3in.checked){
            currency = "GOLD ounces";
        }
        if (descriptionEditin.text !== ""){
            confirmtext.text = "You're about to send "+amountEditin.text+" "+currency+" to @"+paytoEditin.text+" with the following description: '"+descriptionEditin.text+"'.\n\n Please confirm this transaction."
        }else
        {
            confirmtext.text = "You're about to send "+amountEditin.text+" "+currency+" to @"+paytoEditin.text+".\n\n Please confirm this transaction."
        }
        twitteruser.text = msg;
        twitteruser2.text = "@"+paytoEditin.text;
        profileimage.source = "https://wallet.choosebitcash.com/getinstauserpic.php?instauser="+paytoEditin.text;
        badgeimage.source = "../res/assets/Miscellaneous/instagram-badge.png"
        whitebox.visible = false
        whitebox2.visible = false
        whitebox3.visible = true
    }

    function showconfirmtwitchintern(msg)
    {
        confirmmode = 2
        if (radioButton2re.checked){
            currency = "BTC";
        } else
        if (radioButton1re.checked){
            currency = "BITC";
        } else
        if (radioButton3re.checked){
            currency = "GOLD ounces";
        }
        if (descriptionEditre.text !== ""){
            confirmtext.text = "You're about to send "+amountEditre.text+" "+currency+" to @"+paytoEditre.text+" with the following description: '"+descriptionEditre.text+"'.\n\n Please confirm this transaction."
        }else
        {
            confirmtext.text = "You're about to send "+amountEditre.text+" "+currency+" to @"+paytoEditre.text+".\n\n Please confirm this transaction."
        }
        twitteruser.text = msg;
        twitteruser2.text = "@"+paytoEditre.text;
        profileimage.source = "https://wallet.choosebitcash.com/gettwitchuserpic.php?twitchuser="+paytoEditre.text;
        badgeimage.source = "../res/assets/Miscellaneous/twitch-badge.png"
        whitebox.visible = false
        whitebox2.visible = false
        whitebox3.visible = true
    }

    function clearsendentriesintern(msg) {
        paytoEdit.text = ""
        labelEdit.text = ""
        descriptionEdit.text = ""
        amountEdit.text = ""
        whitebox2.visible = true
        whitebox.visible = false
        whitebox3.visible = false
    }

    function clearsendentriesinternDo(msg) {
        /*paytoEditDo.text = ""
        labelEditDo.text = ""
        descriptionEditDo.text = ""
        amountEditDo.text = ""*/
        whitebox2.visible = true
        whitebox.visible = false
        whitebox3.visible = false
    }

    function clearsendentriesinterntw(msg) {
        /************************/
        paytoEdittw.text = ""
        labelEdittw.text = ""
        descriptionEdittw.text = ""
        amountEdittw.text = ""
        whitebox2.visible = false
        whitebox.visible = true
        whitebox3.visible = false
        /*****************/
    }

    function clearsendentriesinternin(msg) {
        /************************/
        paytoEditin.text = ""
        labelEditin.text = ""
        descriptionEditin.text = ""
        amountEditin.text = ""
        whitebox2.visible = false
        whitebox.visible = true
        whitebox3.visible = false
        /*****************/
    }

    function clearsendentriesinternre(msg) {
        /************************/
        paytoEditre.text = ""
        labelEditre.text = ""
        descriptionEditre.text = ""
        amountEditre.text = ""
        whitebox2.visible = false
        whitebox.visible = true
        whitebox3.visible = false
        /*****************/
    }

    property real maxbalancenum : 0
    property real maxbalancenumDo : 0
    property real maxbalancenumGo : 0
    property real maxbalancenumBi : 0

    function setleftamountbalanceitern(left) {

    }

    property real leftbalance: 0
    property real leftbalanceDo: 0
    property real leftbalancetw: 0
    property real leftbalancein: 0
    property real leftbalancere: 0
    property real leftbalancean: 0
    property real leftbalanceBi: 0
    property real priceindollar: 0
    property real priceindollar2: 0
    property real priceingold: 0

    function setpriceDointern(price, price2, pricegold) {
        priceindollar = price
        if (price2 === 0)
        priceindollar2 = price; else
        priceindollar2 = price2
        priceingold = pricegold
    }

    function calcleftbalance()
    {
        if (radioButton1.checked)
        {
            bitcashicon.text = "₡"
            currencytext.text = "BITC"
            leftbalance = maxbalancenum - amountEdit.text
            if (leftbalance < 0) leftbalance = 0
            leftamountlabel.text = leftbalance.toFixed(9)
            /*if (paytoEdit.text.toUpperCase().indexOf("DOLLAR@") == 0 && priceindollar2 != 0) {
                dollarlabel.text = amountEdit.text * priceindollar2 + " Dollar (price can change until tx is mined)"
            } else
            if (paytoEdit.text.toUpperCase().indexOf("GOLD@") == 0 && priceingold != 0 && priceindollar2 != 0) {
                dollarlabel.text = amountEdit.text * priceindollar2 / priceingold + " ounces Gold (price can change until tx is mined)"
            } else {
                dollarlabel.text = "";
            }*/
        } else
        if (radioButton2.checked)
        {
            bitcashicon.text = "BTC"
            currencytext.text = "BTC"
            leftbalance = maxbalancenumBi - amountEdit.text
            if (leftbalance < 0) leftbalance = 0
            leftamountlabel.text = leftbalance.toFixed(9)
            /*if (paytoEdit.text.toUpperCase().indexOf("DOLLAR@") == 0) {
                dollarlabel.text = "";
            } else
            if (paytoEdit.text.toUpperCase().indexOf("GOLD@") == 0 && priceingold != 0) {
                dollarlabel.text = amountEdit.text / priceingold + " ounces Gold (price can change until tx is mined)"
            } else
            if (priceindollar != 0) {
                dollarlabel.text = amountEdit.text / priceindollar + " BitCash (price can change until tx is mined)"
            } else {
                dollarlabel.text = "";
            }*/
         } else
         if (radioButton3.checked)
         {
            bitcashicon.text = "⅁"
            currencytext.text = "GOLD"
            leftbalance = maxbalancenumGo - amountEdit.text
            if (leftbalance < 0) leftbalance = 0
            leftamountlabel.text = leftbalance.toFixed(9)
            if (paytoEdit.text.toUpperCase().indexOf("GOLD@") == 0) {
                dollarlabel.text = "";
            } else
            if (paytoEdit.text.toUpperCase().indexOf("DOLLAR@") == 0 && priceingold != 0) {
                dollarlabel.text = amountEdit.text * priceingold + " Dollar (price can change until tx is mined)"
            } else
            if (priceindollar != 0 && priceingold != 0) {
                dollarlabel.text = amountEdit.text * priceingold / priceindollar + " BitCash (price can change until tx is mined)"
            } else {
                dollarlabel.text = "";
            }
         }
    }

    function calcleftbalanceDo()
    {
     /*   leftbalanceDo = maxbalancenumDo - amountEditDo.text
        if (leftbalanceDo < 0) leftbalanceDo = 0
        leftamountlabelDo.text = leftbalanceDo.toFixed(9)
        if (paytoEditDo.text.toUpperCase().indexOf("DOLLAR@") != 0 && priceindollar != 0) {
            bitcashlabel.text = amountEditDo.text / priceindollar + " BitCash"
        } else {
            bitcashlabel.text = "";
        }*/
    }

    function calcleftbalanceBi()
    {
        leftbalanceBi = maxbalancenumBi - amountEdit.text
        if (leftbalanceBi < 0) leftbalanceBi = 0
        leftamountlabel.text = leftbalanceBi.toFixed(9)
    }

    function calcleftbalancetw()
    {
        /****************************/
        if (radioButton2tw.checked)
        {
            leftbalancetw = maxbalancenumBi-amountEdittw.text
            if (leftbalancetw < 0) leftbalancetw = 0
            leftamountlabeltw.text = leftbalancetw.toFixed(9)
            bitcashicontw.text = "BTC"
        } else
        if (radioButton1tw.checked)
        {
            leftbalancetw = maxbalancenum - amountEdittw.text
            if (leftbalancetw < 0) leftbalancetw = 0
            leftamountlabeltw.text = leftbalancetw.toFixed(9)
            bitcashicontw.text = "₡"
        } else
        if (radioButton3tw.checked)
        {
            leftbalancetw = maxbalancenumGo - amountEdittw.text
            if (leftbalancetw < 0) leftbalancetw = 0
            leftamountlabeltw.text = leftbalancetw.toFixed(9)
            bitcashicontw.text = "⅁"
        }
        /*****************************/
    }

    function calcleftbalancein()
    {
        /****************************/
        if (radioButton2in.checked)
        {
            leftbalancein = maxbalancenumBi-amountEditin.text
            if (leftbalancein<0) leftbalancein=0
            leftamountlabelin.text = leftbalancein.toFixed(9)
            bitcashiconin.text = "BTC"
        } else
        if (radioButton1in.checked)
        {
            leftbalancein = maxbalancenum-amountEditin.text
            if (leftbalancein<0) leftbalancein = 0
            leftamountlabelin.text = leftbalancein.toFixed(9)
            bitcashiconin.text = "₡"
        } else
        if (radioButton3in.checked)
        {
            leftbalancein = maxbalancenumGo-amountEditin.text
            if (leftbalancein<0) leftbalancein = 0
            leftamountlabelin.text = leftbalancein.toFixed(9)
            bitcashiconin.text = "⅁"
        }
        /*****************************/
    }

    function calcleftbalancere()
    {
        /****************************/
        if (radioButton2re.checked)
        {
            leftbalancere = maxbalancenumBi-amountEditre.text
            if (leftbalancere<0) leftbalancere=0
            leftamountlabelre.text = leftbalancere.toFixed(9)
            bitcashiconre.text = "BTC"
        } else
        if (radioButton1re.checked)
        {
            leftbalancere = maxbalancenum-amountEditre.text
            if (leftbalancere < 0) leftbalancere = 0
            leftamountlabelre.text = leftbalancere.toFixed(9)
            bitcashiconre.text = "₡"
        } else
        if (radioButton3re.checked)
        {
            leftbalancere = maxbalancenumGo-amountEditre.text
            if (leftbalancere < 0) leftbalancere = 0
            leftamountlabelre.text = leftbalancere.toFixed(9)
            bitcashiconre.text = "⅁"
        }
        /*****************************/
    }

    function calcleftbalancean()
    {
        if (radioButton2an.checked)
        {
            leftbalancean = maxbalancenumBi - amountEditan.text
            if (leftbalancean < 0) leftbalancean = 0
            leftamountlabelan.text = leftbalancean.toFixed(9)
            currencytextan.text = "BTC"
            bitcashiconan.text = "BTC"
        } else
        if (radioButton1an.checked)
        {
            leftbalancean = maxbalancenum - amountEditan.text
            if (leftbalancean < 0) leftbalancean = 0
            leftamountlabelan.text = leftbalancean.toFixed(9)
            currencytextan.text = "BITC"
            bitcashiconan.text = "₡"
        } else
        if (radioButton3an.checked)
        {
            leftbalancean = maxbalancenumGo - amountEditan.text
            if (leftbalancean < 0) leftbalancean = 0
            leftamountlabelan.text = leftbalancean.toFixed(9)
            currencytextan.text = "GOLD"
            bitcashiconan.text = "⅁"
         }

    }

    function setbacksendbtnintern()
    {
        sendBtnin.text = "Send"
        sendBtntw.text = "Send"
        sendBtnre.text = "Send"
    }

    function setmaxbalanceintern(avail,availnum) {
        maxbalance.text=avail
        maxbalancenum=availnum;
        calcleftbalance()
        calcleftbalancetw()
        calcleftbalancein()
        calcleftbalancere()
        calcleftbalancean()
    }

    function setmaxbalanceinternDo(avail,availnum) {
        //maxbalanceDo.text=avail
        maxbalancenumDo=availnum;
        calcleftbalanceDo()
    }

    function setmaxbalanceinternBi(avail,availnum) {
        //maxbalanceDo.text=avail
        maxbalancenumBi=availnum;
        calcleftbalanceBi()
    }

    function setmaxbalanceinternGo(avail,availnum) {
        maxbalancenumGo=availnum;
    }

    DestCheckValidator {
        // use it
        id: destCheckVal
    }
    DestCheckValidator2 {
        // use it
        id: destCheckVal2
    }
    AmountEntryValidator {
        // use it
        id: amountCheckVal
    }

    radioButton1an.onCheckedChanged: calcleftbalancean()
    radioButton2an.onCheckedChanged: calcleftbalancean()
    radioButton3an.onCheckedChanged: calcleftbalancean()
    radioButton1tw.onCheckedChanged: calcleftbalancetw()
    radioButton2tw.onCheckedChanged: calcleftbalancetw()
    radioButton3tw.onCheckedChanged: calcleftbalancetw()
    radioButton1in.onCheckedChanged: calcleftbalancein()
    radioButton2in.onCheckedChanged: calcleftbalancein()
    radioButton3in.onCheckedChanged: calcleftbalancein()
    radioButton1re.onCheckedChanged: calcleftbalancere()
    radioButton2re.onCheckedChanged: calcleftbalancere()
    radioButton3re.onCheckedChanged: calcleftbalancere()

    amountEdit.validator: amountCheckVal       
    amountEdit.onTextChanged: calcleftbalance()
    /*amountEditDo.validator: amountCheckVal
    amountEditDo.onTextChanged: calcleftbalanceDo()*/    
    amountEditan.validator: amountCheckVal
    amountEditan.onTextChanged: calcleftbalancean()
    paytoEdit.validator: destCheckVal
    paytoEdit.onTextChanged: {
        if (paytoEdit.acceptableInput) {
            paytoEdit.ToolTip.visible = true
            paytoEdit.ToolTip.text = qsTr("This is a valid BitCash address.")
            paytoEdit.ToolTip.delay = 100
            paytoEdit.ToolTip.timeout = 5000
        } else {
            paytoEdit.ToolTip.visible = false
        }
    }
    /*paytoEditDo.validator: destCheckVal
    paytoEditDo.onTextChanged: {
        if (paytoEditDo.acceptableInput) {
            paytoEditDo.ToolTip.visible = true
            paytoEditDo.ToolTip.text = qsTr("This is a valid BitCash address.")
            paytoEditDo.ToolTip.delay = 100
            paytoEditDo.ToolTip.timeout = 5000
        } else {
            paytoEditDo.ToolTip.visible = false
        }
    }*/
/***********************************/
    paytoEdittw.validator: destCheckVal2
    amountEdittw.validator: amountCheckVal
    amountEdittw.onTextChanged: calcleftbalancetw()
    sendBtntw.onClicked: {
        sendBtntw.text = "Connecting..."
        if (radioButton1tw.checked) {
            sendBtntwSignalIntern(paytoEdittw.text, descriptionEdittw.text, amountEdittw.text, 0)
        } else
        if (radioButton2tw.checked) {
            sendBtntwSignalIntern(paytoEdittw.text, descriptionEdittw.text, amountEdittw.text, 3)
        } else
        if (radioButton3tw.checked) {
            sendBtntwSignalIntern(paytoEdittw.text, descriptionEdittw.text, amountEdittw.text, 2)
        }
    }

    paytoEditin.validator: destCheckVal2
    amountEditin.validator: amountCheckVal
    amountEditin.onTextChanged: calcleftbalancein()
    sendBtnin.onClicked: {
        sendBtnin.text = "Connecting..."
        if (radioButton1tw.checked) {
            sendBtninSignalIntern(paytoEditin.text, descriptionEditin.text, amountEditin.text, 0)
        } else
        if (radioButton2tw.checked) {
            sendBtninSignalIntern(paytoEditin.text, descriptionEditin.text, amountEditin.text, 3)
        } else
        if (radioButton3tw.checked) {
            sendBtninSignalIntern(paytoEditin.text, descriptionEditin.text, amountEditin.text, 2)
        }
    }

    paytoEditre.validator: destCheckVal2
    amountEditre.validator: amountCheckVal
    amountEditre.onTextChanged: calcleftbalancere()
    sendBtnre.onClicked: {
        sendBtnre.text = "Connecting..."
        if (radioButton1re.checked) {
            sendBtnreSignalIntern(paytoEditre.text, descriptionEditre.text, amountEditre.text, 0)
        } else
        if (radioButton2re.checked) {
            sendBtnreSignalIntern(paytoEditre.text, descriptionEditre.text, amountEditre.text, 3)
        } else
        if (radioButton3re.checked) {
            sendBtnreSignalIntern(paytoEditre.text, descriptionEditre.text, amountEditre.text, 2)
        }
    }
/***********************************/
    /*sendBtnDo.onClicked: {
        sendBtnDoSignalIntern(paytoEditDo.text, labelEditDo.text,descriptionEditDo.text, amountEditDo.text, subtractfeeCheckDo.checked)
    }*/
    printBtnDo.onClicked: {
        printBtnDoSignalIntern()
    }
    radioButton1.onCheckedChanged: calcleftbalance()
    radioButton2.onCheckedChanged: calcleftbalance()
    radioButton3.onCheckedChanged: calcleftbalance()
    sendBtn.onClicked: {
        if (radioButton1.checked) {
            sendBtnSignalIntern(paytoEdit.text, labelEdit.text, descriptionEdit.text, amountEdit.text, subtractfeeCheck.checked)
        } else
        if (radioButton2.checked) {
            sendBtnBiSignalIntern(paytoEdit.text, labelEdit.text, descriptionEdit.text, amountEdit.text, subtractfeeCheck.checked)
        } else
        if (radioButton3.checked) {
            sendBtnGoSignalIntern(paytoEdit.text, labelEdit.text, descriptionEdit.text, amountEdit.text, subtractfeeCheck.checked)
        }
    }
    printBtn.onClicked: {
        printBtnSignalIntern()
    }
    sendBtnan.onClicked: {
        if (radioButton1an.checked){
            sendlinkBtnSignalIntern(descriptionEditan.text, amountEditan.text, 0)
        } else
        if (radioButton2an.checked){
            sendlinkBtnSignalIntern(descriptionEditan.text, amountEditan.text, 3)
        } else
        if (radioButton3an.checked){
            sendlinkBtnSignalIntern(descriptionEditan.text, amountEditan.text, 2)
        }
    }
    sendconfirmtwBtn.onClicked: {               
        if (confirmmode==0){
            if (radioButton1tw.checked){
                sendconfirmedBtntwSignalIntern(paytoEdittw.text, descriptionEdittw.text, amountEdittw.text, 0)
            } else
            if (radioButton2tw.checked){
                sendconfirmedBtntwSignalIntern(paytoEdittw.text, descriptionEdittw.text, amountEdittw.text, 3)
            } else
            if (radioButton3tw.checked){
                sendconfirmedBtntwSignalIntern(paytoEdittw.text, descriptionEdittw.text, amountEdittw.text, 2)
            }
        }else
        if (confirmmode==1){
            if (radioButton1in.checked){
                sendconfirmedBtninSignalIntern(paytoEditin.text, descriptionEditin.text, amountEditin.text, 0)
            } else
            if (radioButton2in.checked){
                sendconfirmedBtninSignalIntern(paytoEditin.text, descriptionEditin.text, amountEditin.text, 3)
            } else
            if (radioButton3in.checked){
                sendconfirmedBtninSignalIntern(paytoEditin.text, descriptionEditin.text, amountEditin.text, 2)
            }
        }else
        if (confirmmode==2){
            if (radioButton1re.checked){
                sendconfirmedBtnreSignalIntern(paytoEditre.text, descriptionEditre.text, amountEditre.text, 0)
            } else
            if (radioButton2re.checked){
                sendconfirmedBtnreSignalIntern(paytoEditre.text, descriptionEditre.text, amountEditre.text, 3)
            } else
            if (radioButton3re.checked){
                sendconfirmedBtnreSignalIntern(paytoEditre.text, descriptionEditre.text, amountEditre.text, 2)
            }
        }
    }
    changetwbtn.onClicked: {
        whitebox.visible = true
        whitebox2.visible = false
        whitebox3.visible = false
    }
    linksendtoanyone.onClicked: sendtoanyoneSignalIntern()
    availableBalanceBtn.onClicked: amountEdit.text = maxbalancenum
    //availableBalanceBtnDo.onClicked: amountEditDo.text = maxbalancenumDo
    pasteaddress.onClicked: {
        paytoEdit.selectAll()
        paytoEdit.paste()
    }
    /*pasteaddressDo.onClicked: {
        paytoEditDo.selectAll()
        paytoEditDo.paste()
    }*/
    othertransactionBtn.onClicked: {
        whitebox2.visible = false
        whitebox3.visible = false
        whitebox.visible = true
    }
    viewaccounthistory.onClicked: viewaccounthistorysignal()
    gotooverview.onClicked: gotooverviewsignal()
}
