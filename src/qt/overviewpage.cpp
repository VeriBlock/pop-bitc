// Copyright (c) 2011-2017 The Bitcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/overviewpage.h>
#include <qt/forms/ui_overviewpage.h>

#include <qt/bitcashunits.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>
#include <chainparams.h>
#include <key_io.h>
#include <nicknames.h>
#include <iomanip> 
#include <sstream>
#include <rpc/blockchain.h>

#include <QAbstractItemDelegate>
#include <QPainter>

#define DECORATION_SIZE 54
#define NUM_ITEMS 5

Q_DECLARE_METATYPE(interfaces::WalletBalances)

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit TxViewDelegate(const PlatformStyle *_platformStyle, QObject *parent=nullptr):
        QAbstractItemDelegate(parent), unit(BitcashUnits::BITC),
        platformStyle(_platformStyle)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon = platformStyle->SingleColorIcon(icon);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address, &boundingRect);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool())
        {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 5, mainRect.top()+ypad+halfheight, 16, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText = BitcashUnits::formatWithUnit(unit, amount, true, BitcashUnits::separatorAlways);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
    const PlatformStyle *platformStyle;

};
#include <qt/overviewpage.moc>

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    clientModel(0),
    walletModel(0),
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    ui->setupUi(this);

    m_balances.balance = -1;

    // use a SingleColorIcon for the "out of sync warning" icon
    QIcon icon = platformStyle->SingleColorIcon(":/icons/warning");
    icon.addPixmap(icon.pixmap(QSize(64,64), QIcon::Normal), QIcon::Disabled); // also set the disabled icon because we are using a disabled QPushButton to work around missing HiDPI support of QLabel (https://bugreports.qt.io/browse/QTBUG-42503)
    ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setIcon(icon);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, SIGNAL(clicked()), this, SLOT(handleOutOfSyncWarningClicks()));
    connect(ui->labelTransactionsStatus, SIGNAL(clicked()), this, SLOT(handleOutOfSyncWarningClicks()));

}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::handleOutOfSyncWarningClicks()
{
    Q_EMIT outOfSyncWarningClicked();
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(const interfaces::WalletBalances& balances)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    m_balances = balances;
    ui->labelBalance->setText(BitcashUnits::formatWithUnit(unit, balances.balance, false, BitcashUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcashUnits::formatWithUnit(unit, balances.unconfirmed_balance, false, BitcashUnits::separatorAlways));
    ui->labelImmature->setText(BitcashUnits::formatWithUnit(unit, balances.immature_balance, false, BitcashUnits::separatorAlways));
    ui->labelTotal->setText(BitcashUnits::formatWithUnit(unit, balances.balance + balances.unconfirmed_balance + balances.immature_balance, false, BitcashUnits::separatorAlways));
    ui->labelWatchAvailable->setText(BitcashUnits::formatWithUnit(unit, balances.watch_only_balance, false, BitcashUnits::separatorAlways));
    ui->labelWatchPending->setText(BitcashUnits::formatWithUnit(unit, balances.unconfirmed_watch_only_balance, false, BitcashUnits::separatorAlways));
    ui->labelWatchImmature->setText(BitcashUnits::formatWithUnit(unit, balances.immature_watch_only_balance, false, BitcashUnits::separatorAlways));
    ui->labelWatchTotal->setText(BitcashUnits::formatWithUnit(unit, balances.watch_only_balance + balances.unconfirmed_watch_only_balance + balances.immature_watch_only_balance, false, BitcashUnits::separatorAlways));

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = balances.immature_balance != 0;
    bool showWatchOnlyImmature = balances.immature_watch_only_balance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelWatchImmature->setVisible(showWatchOnlyImmature); // show watch-only immature balance

    QVariant returnedValue;
    QVariant avail, pending, immature, total, availnum;

    avail=BitcashUnits::format(unit, balances.balance, false, BitcashUnits::separatorAlways); 
    availnum=BitcashUnits::format(unit, balances.balance, false, BitcashUnits::separatorNever); 

    pending=BitcashUnits::format(unit, balances.unconfirmed_balance, false, BitcashUnits::separatorAlways);

    immature=BitcashUnits::format(unit, balances.immature_balance, false, BitcashUnits::separatorAlways);

    total=BitcashUnits::format(unit, balances.balance + balances.unconfirmed_balance + balances.immature_balance, false, BitcashUnits::separatorAlways);

    QMetaObject::invokeMethod(qmlrootitem, "setbalances", Q_RETURN_ARG(QVariant, returnedValue), Q_ARG(QVariant, avail), Q_ARG(QVariant, pending), Q_ARG(QVariant, immature), Q_ARG(QVariant, total), Q_ARG(QVariant, availnum));

    QVariant availDo, pendingDo, immatureDo, totalDo, availnumDo, totalvalueDo;

    availDo=BitcashUnits::format(unit, balances.balanceDo, false, BitcashUnits::separatorAlways); 
    availnumDo=BitcashUnits::format(unit, balances.balanceDo, false, BitcashUnits::separatorNever); 

    pendingDo=BitcashUnits::format(unit, balances.unconfirmed_balanceDo, false, BitcashUnits::separatorAlways);

    immatureDo=BitcashUnits::format(unit, balances.immature_balanceDo, false, BitcashUnits::separatorAlways);

    totalDo=BitcashUnits::format(unit, balances.balanceDo + balances.unconfirmed_balanceDo + balances.immature_balanceDo, false, BitcashUnits::separatorAlways);

    QMetaObject::invokeMethod(qmlrootitem, "setbalancesDo", Q_RETURN_ARG(QVariant, returnedValue), Q_ARG(QVariant, availDo), Q_ARG(QVariant, pendingDo), Q_ARG(QVariant, immatureDo), Q_ARG(QVariant, totalDo), Q_ARG(QVariant, availnumDo));

    QVariant availGo, pendingGo, immatureGo, totalGo, availnumGo, totalvalueGo;

    availGo=BitcashUnits::format(unit, balances.balanceGo, false, BitcashUnits::separatorAlways); 
    availnumGo=BitcashUnits::format(unit, balances.balanceGo, false, BitcashUnits::separatorNever); 

    pendingGo=BitcashUnits::format(unit, balances.unconfirmed_balanceGo, false, BitcashUnits::separatorAlways);

    immatureGo=BitcashUnits::format(unit, balances.immature_balanceGo, false, BitcashUnits::separatorAlways);

    totalGo=BitcashUnits::format(unit, balances.balanceGo + balances.unconfirmed_balanceGo + balances.immature_balanceGo, false, BitcashUnits::separatorAlways);

    QMetaObject::invokeMethod(qmlrootitem, "setbalancesGo", Q_RETURN_ARG(QVariant, returnedValue), Q_ARG(QVariant, availGo), Q_ARG(QVariant, pendingGo), Q_ARG(QVariant, immatureGo), Q_ARG(QVariant, totalGo), Q_ARG(QVariant, availnumGo));

    QVariant availBi, pendingBi, immatureBi, totalBi, availnumBi, totalvalueBi;

    availBi=BitcashUnits::format(unit, balances.balanceBi, false, BitcashUnits::separatorAlways); 
    availnumBi=BitcashUnits::format(unit, balances.balanceBi, false, BitcashUnits::separatorNever); 

    pendingBi=BitcashUnits::format(unit, balances.unconfirmed_balanceBi, false, BitcashUnits::separatorAlways);

    immatureBi=BitcashUnits::format(unit, balances.immature_balanceBi, false, BitcashUnits::separatorAlways);

    totalBi=BitcashUnits::format(unit, balances.balanceBi + balances.unconfirmed_balanceBi + balances.immature_balanceBi, false, BitcashUnits::separatorAlways);

    QMetaObject::invokeMethod(qmlrootitem, "setbalancesBi", Q_RETURN_ARG(QVariant, returnedValue), Q_ARG(QVariant, availBi), Q_ARG(QVariant, pendingBi), Q_ARG(QVariant, immatureBi), Q_ARG(QVariant, totalBi), Q_ARG(QVariant, availnumBi));


    double pri = GetBlockPrice(1);
    if (pri == 0) pri = GetBlockPrice(0);
    if (pri <= 1) {
        totalvalueDo = "Not available";
    } else {

        CAmount totalbalance = balances.balance + balances.unconfirmed_balance + balances.immature_balance;

        double priGo = GetBlockPrice(2);
        double totalbalancedouble;
        if (priGo <= 1) {
            totalbalancedouble = totalbalance / COIN * pri + balances.balanceDo + balances.unconfirmed_balanceDo + balances.immature_balanceDo;           
        } else {
            totalbalancedouble = totalbalance / COIN * pri + balances.balanceDo + balances.unconfirmed_balanceDo + balances.immature_balanceDo + 
                                        (balances.balanceGo + balances.unconfirmed_balanceGo + balances.immature_balanceGo) * priGo / COIN;
        }
        totalvalueDo = BitcashUnits::format(unit,totalbalancedouble , false, BitcashUnits::separatorAlways);        
    }

    QMetaObject::invokeMethod(qmlrootitem, "setwalletvalue", Q_RETURN_ARG(QVariant, returnedValue), Q_ARG(QVariant, totalvalueDo));


}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    ui->lineWatchBalance->setVisible(showWatchOnly);    // show watch-only balance separator line
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance

    if (!showWatchOnly)
        ui->labelWatchImmature->hide();
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());
    }
}

bool LocalGetNonPrivateForDestination(const CTxDestination& dest)
{
    bool key2 = false;

    if (auto id = boost::get<CKeyID>(&dest)) {
        key2=id->nonprivate;
    }
    return key2;   
}

bool LocalGetHasViewKeyForDestination(const CTxDestination& dest)
{
    bool key2 = false;

    if (auto id = boost::get<CKeyID>(&dest)) {
        key2=id->hasviewkey;
    }
    return key2;   
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        qmlrootctxt->setContextProperty("overviewtransactions", QVariant::fromValue(filter.get()));

        // Keep up to date with wallet
        interfaces::Wallet& wallet = model->wallet();
        interfaces::WalletBalances balances = wallet.getBalances();
        setBalance(balances);
        connect(model, SIGNAL(balanceChanged(interfaces::WalletBalances)), this, SLOT(setBalance(interfaces::WalletBalances)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        updateWatchOnlyLabels(wallet.haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));

        CPubKey pkey = model->wallet().GetCurrentAddressPubKey();
        CTxDestination dest = PubKeyToDestination(pkey);

        QVariant returnedValue;
        QVariant address, nick, transmodel;
        std::string addr = EncodeDestination(dest, pkey);
        address = QString::fromStdString(addr);
        nick = QString::fromStdString(GetNicknameForAddress(pkey, LocalGetNonPrivateForDestination(dest), LocalGetHasViewKeyForDestination(dest)));

        QMetaObject::invokeMethod(qmlrootitem, "setreceivingaddress", Q_RETURN_ARG(QVariant, returnedValue), Q_ARG(QVariant, address), Q_ARG(QVariant, nick));

    }

    // update the display unit, to not use the default ("BITC")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        if (m_balances.balance != -1) {
            setBalance(m_balances);
        }

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}
