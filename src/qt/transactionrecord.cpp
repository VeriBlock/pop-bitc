// Copyright (c) 2011-2017 The Bitcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactionrecord.h>

#include <consensus/consensus.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <wallet/wallet.h>
#include <nicknames.h>
#include <timedata.h>
#include <validation.h>

#include <stdint.h>


/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction()
{
    // There are currently no cases where we hide transactions, but
    // we may want to use this in the future for things like RBF.
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const interfaces::WalletTx& wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.time;
    CAmount nCredit = wtx.credit;
    CAmount nDebit = wtx.debit;
    CAmount nCreditbitc = wtx.creditbitc;
    CAmount nDebitbitc = wtx.debitbitc;
    CAmount nCreditusd = wtx.creditusd;
    CAmount nDebitusd = wtx.debitusd;
    CAmount nCreditgold = wtx.creditgold;
    CAmount nDebitgold = wtx.debitgold;
    CAmount nCreditbitcoin = wtx.creditbitcoin;
    CAmount nDebitbitcoin = wtx.debitbitcoin;
    unsigned char inputcurrency = wtx.inputcurrency;

    CAmount nNet = nCredit - nDebit;
    uint256 hash = wtx.tx->GetHash();
    std::map<std::string, std::string> mapValue = wtx.value_map;

   
    bool involvesWatchAddress = false;
    isminetype fAllFromMe = ISMINE_SPENDABLE;
    for (isminetype mine : wtx.txin_is_mine)
    {
        if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
        if(fAllFromMe > mine) fAllFromMe = mine;
    }

    isminetype fAllToMe = ISMINE_SPENDABLE;
    for (isminetype mine : wtx.txout_is_mine)
    {
        if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
        if(fAllToMe > mine) fAllToMe = mine;
    }

    if (fAllFromMe && fAllToMe)
    {
        // Payment to self
        CAmount nChange = wtx.change;

        parts.append(TransactionRecord(hash, nTime, TransactionRecord::SendToSelf, "",
                            -(nDebit - nChange), nCredit - nChange, 0, -nDebitbitc, nCreditbitc, -nDebitusd, nCreditusd, -nDebitgold, nCreditgold, -nDebitbitcoin, nCreditbitcoin));
        parts.last().involvesWatchAddress = involvesWatchAddress;   // maybe pass to TransactionRecord as constructor argument

        for (unsigned int nOut = 0; nOut < wtx.tx->vout.size(); nOut++)
        {
            //sometimes the change is the first, sometimes it is the second tx output. So take the reference line from the first output with a reference line
            if (parts.last().referenceline.size() == 0) {
                parts.last().referenceline = wtx.reflines[nOut];
            }
        }

    } else
    if (nNet > 0 || wtx.is_coinbase)
    {
        //
        // Credit
        //
        for(unsigned int i = 0; i < wtx.tx->vout.size(); i++)
        {
            const CTxOut& txout = wtx.tx->vout[i];
            isminetype mine = wtx.txout_is_mine[i];
            if(mine)
            {
                TransactionRecord sub(hash, nTime);
                CTxDestination address;
                sub.idx = i; // vout index
                sub.credit = txout.nValue;
                if (txout.currency == 0)
                {
                    sub.creditbitc = txout.nValue;
                } else
                if (txout.currency == 1)
                {
                    sub.creditusd = txout.nValue;
                } else
                if (txout.currency == 3)
                {
                    sub.creditbitcoin = txout.nValue;
                } else
                {
                    sub.creditgold = txout.nValue;
                }
                sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
                sub.referenceline = wtx.reflines[i];
                sub.currency = txout.currency;

                if (wtx.txout_address_is_mine[i])
                {
                    // Received by Bitcash Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = EncodeDestinationHasSecondKey(wtx.txout_address[i]);
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.is_coinbase)
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }

                parts.append(sub);
            }
        }
    }
    else
    {
        if (fAllFromMe)
        {
            //
            // Debit
            //
            CAmount nTxFee = nDebit - wtx.tx->GetValueOut();

            for (unsigned int nOut = 0; nOut < wtx.tx->vout.size(); nOut++)
            {
                const CTxOut& txout = wtx.tx->vout[nOut];
                TransactionRecord sub(hash, nTime);
                sub.idx = nOut;
                sub.involvesWatchAddress = involvesWatchAddress;
                sub.referenceline = wtx.reflines[nOut];

                sub.currency = inputcurrency;

                if(wtx.txout_is_mine[nOut])
                {
                    // Ignore parts sent to self, as this is usually the change
                    // from a transaction sent back to our own address.
                    continue;
                }

                if (!boost::get<CNoDestination>(&wtx.txout_address[nOut]))
                {
                    // Sent to Bitcash Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = EncodeDestinationHasSecondKey(wtx.txout_address[nOut]);                   
                    std::string nick = GetNicknameForAddress(GetSecondPubKeyForDestination(wtx.txout_address[nOut]), GetNonPrivateForDestination(wtx.txout_address[nOut]), GetHasViewKeyForDestination(wtx.txout_address[nOut]));
                    if (nick.size()>0) sub.address = nick;
                }
                else
                {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                CAmount nValue = txout.nValueBitCash;
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                if (sub.currency == 0)
                {
                    sub.debitbitc = -nValue;
                } else
                if (sub.currency == 1)
                {
                    sub.debitusd = -nValue;
                } else
                if (sub.currency == 2)
                {
                    sub.debitgold = -nValue;
                } else
                if (sub.currency == 3)
                {
                    sub.debitbitcoin = -nValue;
                }

                parts.append(sub);
            }
        }
        else
        {
            //
            // Mixed debit transaction, can't break down payees
            //
            for(unsigned int i = 0; i < wtx.tx->vin.size(); i++)
            {
                if (wtx.tx->vin[i].isnickname) {
                    //nickname transaction
                    parts.append(TransactionRecord(hash, nTime, TransactionRecord::SendToOther, "", nNet, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
                    parts.last().involvesWatchAddress = involvesWatchAddress;  
         
                    parts.last().address=EncodeDestination(wtx.tx->vin[i].address);
                    parts.last().referenceline = "Registered nickname: "+wtx.tx->vin[i].nickname;

                    return parts;
                }
            }

            parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0, 0, -nDebitbitc, nCreditbitc, -nDebitusd, nCreditusd, -nDebitgold, nCreditgold, -nDebitbitcoin, nCreditbitcoin));
            parts.last().involvesWatchAddress = involvesWatchAddress;
        }
    }

    return parts;
}

void TransactionRecord::updateStatus(const interfaces::WalletTxStatus& wtx, int numBlocks, int64_t adjustedTime)
{
    // Determine transaction status

    // Sort order, unrecorded transactions sort to the top
    status.sortKey = strprintf("%010d-%01d-%010u-%03d",
        wtx.block_height,
        wtx.is_coinbase ? 1 : 0,
        wtx.time_received,
        idx);
    status.countsForBalance = wtx.is_trusted && !(wtx.blocks_to_maturity > 0);
    status.depth = wtx.depth_in_main_chain;
    status.cur_num_blocks = numBlocks;

    if (!wtx.is_final)
    {
        if (wtx.lock_time < LOCKTIME_THRESHOLD)
        {
            status.status = TransactionStatus::OpenUntilBlock;
            status.open_for = wtx.lock_time - numBlocks;
        }
        else
        {
            status.status = TransactionStatus::OpenUntilDate;
            status.open_for = wtx.lock_time;
        }
    }
    // For generated transactions, determine maturity
    else if(type == TransactionRecord::Generated)
    {
        if (wtx.blocks_to_maturity > 0)
        {
            status.status = TransactionStatus::Immature;

            if (wtx.is_in_main_chain)
            {
                status.matures_in = wtx.blocks_to_maturity;

                // Check if the block was requested by anyone
                if (adjustedTime - wtx.time_received > 2 * 60 && wtx.request_count == 0)
                    status.status = TransactionStatus::MaturesWarning;
            }
            else
            {
                status.status = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    else
    {
        if (status.depth < 0)
        {
            status.status = TransactionStatus::Conflicted;
        }
        else if (adjustedTime - wtx.time_received > 2 * 60 && wtx.request_count == 0)
        {
            status.status = TransactionStatus::Offline;
        }
        else if (status.depth == 0)
        {
            status.status = TransactionStatus::Unconfirmed;
            if (wtx.is_abandoned)
                status.status = TransactionStatus::Abandoned;
        }
        else if (status.depth < RecommendedNumConfirmations)
        {
            status.status = TransactionStatus::Confirming;
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    status.needsUpdate = false;
}

bool TransactionRecord::statusUpdateNeeded(int numBlocks) const
{
    return status.cur_num_blocks != numBlocks || status.needsUpdate;
}

QString TransactionRecord::getTxHash() const
{
    return QString::fromStdString(hash.ToString());
}

int TransactionRecord::getOutputIndex() const
{
    return idx;
}
