// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_PRIMITIVES_BLOCK_H
#define BITCASH_PRIMITIVES_BLOCK_H

#include <consensus/params.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <set>
#include <vbk/vbk.hpp>

#include "veriblock/entities/popdata.hpp"

#define hashx25Xactive ((uint32_t)1) << 6
#define gpumineractive ((uint32_t)1) << 5
#define hashx16rv2active ((uint32_t)1) << 4
#define hashx16Ractive ((uint32_t)1) << 3
#define stabletimeactive ((uint32_t)1) << 2

extern bool isX25Xactive(int32_t nVersion);
extern bool isX16Ractive(int32_t nVersion);
extern bool isstabletimeactive(int32_t nVersion);
extern bool isX16RV2active(int32_t nVersion);
extern bool isGPUMINERactive(int32_t nVersion);

//Stores a signed price information
class CPriceInfo
{
public:
    uint32_t priceTime;//Time of price information
    unsigned char priceCount;//number of stored price information
    CAmount prices[3];//only 3 of 256 prices for now to reduce memory usage

    CPriceInfo()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(priceTime);
        READWRITE(priceCount);
        unsigned char i;
        for (i=0;i<priceCount;i++) {
	    READWRITE(prices[i]);
        }
    }

    void SetNull()
    {
	priceTime = 0;
        priceCount = 1;
        unsigned char i;
        for (i = 0; i < priceCount; i++) {
	    prices[i] = 1;
        }
    }

    bool IsNull() const
    {
        return (priceTime == 0);
    }

    int64_t GetPriceTime() const
    {
        return (int64_t)priceTime;
    }
};


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    CPriceInfo nPriceInfo;
    std::vector<unsigned char> priceSig;//Signature for nPriceInfo
    CPriceInfo nPriceInfo2;
    std::vector<unsigned char> priceSig2;//Signature for nPriceInfo2
    CPriceInfo nPriceInfo3;
    std::vector<unsigned char> priceSig3;//Signature for nPriceInfo3
    uint8_t nEdgeBits;
    std::set<uint32_t> sCycle;


    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        if (isstabletimeactive(this->nVersion)) {	
            READWRITE(nPriceInfo);
            READWRITE(priceSig);
            READWRITE(nPriceInfo2);
            READWRITE(priceSig2);
            READWRITE(nPriceInfo3);
            READWRITE(priceSig3);
        } else {
          nPriceInfo.prices[0] = 1;
          nPriceInfo.priceCount = 1;
          nPriceInfo2.prices[0] = 1;
          nPriceInfo2.priceCount = 1;
          nPriceInfo3.prices[0] = 1;
          nPriceInfo3.priceCount = 1;
        }
        if (!isX16Ractive(this->nVersion)) {
            READWRITE(nEdgeBits);
            if (!(s.GetType() & SER_GETHASH)) {
                READWRITE(sCycle);
            }
        }        
    }

    CAmount GetPriceinCurrency(unsigned char currency) const;

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        nPriceInfo.SetNull();
        priceSig.clear();
        nPriceInfo2.SetNull();
        priceSig2.clear();
        nPriceInfo3.SetNull();
        priceSig3.clear();
        nEdgeBits = 0;        
        sCycle.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;
    // VeriBlock  data network and disk
    altintegration::PopData popData;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(CBlockHeader, *this);
        READWRITE(vtx);
        if (this->nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
            READWRITE(popData);
        }
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nPriceInfo     = nPriceInfo;
        block.priceSig       = priceSig;
        block.nPriceInfo2    = nPriceInfo2;
        block.priceSig2      = priceSig2;
        block.nPriceInfo3    = nPriceInfo3;
        block.priceSig3      = priceSig3;
        block.nEdgeBits      = nEdgeBits;
        block.sCycle         = sCycle;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCASH_PRIMITIVES_BLOCK_H
