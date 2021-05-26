// Copyright (c) 2011-2017 The Bitcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_QT_TRANSACTIONRECORD_H
#define BITCASH_QT_TRANSACTIONRECORD_H

#include <amount.h>
#include <uint256.h>

#include <QList>
#include <QString>

namespace interfaces {
class Node;
class Wallet;
struct WalletTx;
struct WalletTxStatus;
}

/** UI model for transaction status. The transaction status is the part of a transaction that will change over time.
 */
class TransactionStatus
{
public:
    TransactionStatus():
        countsForBalance(false), sortKey(""),
        matures_in(0), status(Offline), depth(0), open_for(0), cur_num_blocks(-1)
    { }

    enum Status {
        Confirmed,          /**< Have 6 or more confirmations (normal tx) or fully mature (mined tx) **/
        /// Normal (sent/received) transactions
        OpenUntilDate,      /**< Transaction not yet final, waiting for date */
        OpenUntilBlock,     /**< Transaction not yet final, waiting for block */
        Offline,            /**< Not sent to any other nodes **/
        Unconfirmed,        /**< Not yet mined into a block **/
        Confirming,         /**< Confirmed, but waiting for the recommended number of confirmations **/
        Conflicted,         /**< Conflicts with other transaction or mempool **/
        Abandoned,          /**< Abandoned from the wallet **/
        /// Generated (mined) transactions
        Immature,           /**< Mined but waiting for maturity */
        MaturesWarning,     /**< Transaction will likely not mature because no nodes have confirmed */
        NotAccepted         /**< Mined but not accepted */
    };

    /// Transaction counts towards available balance
    bool countsForBalance;
    /// Sorting key based on status
    std::string sortKey;

    /** @name Generated (mined) transactions
       @{*/
    int matures_in;
    /**@}*/

    /** @name Reported status
       @{*/
    Status status;
    qint64 depth;
    qint64 open_for; /**< Timestamp if status==OpenUntilDate, otherwise number
                      of additional blocks that need to be mined before
                      finalization */
    /**@}*/

    /** Current number of blocks (to know whether cached status is still valid) */
    int cur_num_blocks;

    bool needsUpdate;
};

/** UI model for a transaction. A core transaction can be represented by multiple UI transactions if it has
    multiple outputs.
 */
class TransactionRecord
{
public:
    enum Type
    {
        Other,
        Generated,
        SendToAddress,
        SendToOther,
        RecvWithAddress,
        RecvFromOther,
        SendToSelf
    };

    /** Number of confirmation recommended for accepting a transaction */
    static const int RecommendedNumConfirmations = 6;

    TransactionRecord():
            hash(), time(0), type(Other), address(""), debit(0), credit(0), idx(0), currency(0), debitbitc(0), creditbitc(0), debitusd(0), creditusd(0), debitgold(0), creditgold(0), debitbitcoin(0), creditbitcoin(0)
    {
    }

    TransactionRecord(uint256 _hash, qint64 _time):
            hash(_hash), time(_time), type(Other), address(""), debit(0),
            credit(0), idx(0), currency(0), debitbitc(0), creditbitc(0), debitusd(0), creditusd(0), debitgold(0), creditgold(0), debitbitcoin(0), creditbitcoin(0)
    {
    }

    TransactionRecord(uint256 _hash, qint64 _time,
                Type _type, const std::string &_address,
                const CAmount& _debit, const CAmount& _credit, const unsigned char _currency,
                const CAmount& _debitbitc, const CAmount& _creditbitc,
                const CAmount& _debitusd, const CAmount& _creditusd,
                const CAmount& _debitgold, const CAmount& _creditgold,
                const CAmount& _debitbitcoin, const CAmount& _creditbitcoin):
            hash(_hash), time(_time), type(_type), address(_address), debit(_debit), credit(_credit),
            idx(0), currency(_currency), debitbitc(_debitbitc), creditbitc(_creditbitc), debitusd(_debitusd), creditusd(_creditusd)
                                                                                       , debitgold(_debitgold), creditgold(_creditgold)
                                                                                       , debitbitcoin(_debitbitcoin), creditbitcoin(_creditbitcoin)
    {
    }

    /** Decompose CWallet transaction to model transaction records.
     */
    static bool showTransaction();
    static QList<TransactionRecord> decomposeTransaction(const interfaces::WalletTx& wtx);

    /** @name Immutable transaction attributes
      @{*/
    uint256 hash;
    qint64 time;
    Type type;
    std::string address;
    std::string referenceline;
    CAmount debit;
    CAmount credit;
    CAmount debitbitc;
    CAmount creditbitc;
    CAmount debitusd;
    CAmount creditusd;
    CAmount debitgold;
    CAmount creditgold;
    CAmount debitbitcoin;
    CAmount creditbitcoin;
    unsigned char currency;
    /**@}*/

    /** Subtransaction index, for sort key */
    int idx;

    /** Status: can change with block chain update */
    TransactionStatus status;

    /** Whether the transaction was sent/received with a watch-only address */
    bool involvesWatchAddress;

    /** Return the unique identifier for this transaction (part) */
    QString getTxHash() const;

    /** Return the output index of the subtransaction  */
    int getOutputIndex() const;

    /** Update status from core wallet tx.
     */
    void updateStatus(const interfaces::WalletTxStatus& wtx, int numBlocks, int64_t adjustedTime);

    /** Return whether a status update is needed.
     */
    bool statusUpdateNeeded(int numBlocks) const;
};

#endif // BITCASH_QT_TRANSACTIONRECORD_H
