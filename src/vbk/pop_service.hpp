// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_POP_SERVICE_HPP
#define BITCASH_SRC_VBK_POP_SERVICE_HPP

#include <consensus/validation.h>
#include <vbk/pop_common.hpp>
#include <vbk/util.hpp>

typedef int64_t CAmount;

class CBlockIndex;
class CBlock;
class CScript;
class CBlockTreeDB;
class CDBBatch;
class CDBIterator;
class CDBWrapper;
class CChainParams;
class CValidationState;

namespace VeriBlock {

using BlockBytes = std::vector<uint8_t>;
using PoPRewards = std::map<CScript, CAmount>;

void InitPopContext(CDBWrapper& db);

//! returns true if all tips are stored in database, false otherwise
bool hasPopData(CBlockTreeDB& db);
altintegration::PopData getPopData();
void saveTrees(CDBBatch* batch);
bool loadTrees(CDBWrapper& db);

//! alttree methods
bool acceptBlock(const CBlockIndex& indexNew, CValidationState& state);
bool addAllBlockPayloads(const CBlock& block);
bool setState(const uint256& hash, altintegration::ValidationState& state);

//! mempool methods
altintegration::PopData getPopData();
void removePayloadsFromMempool(const altintegration::PopData& popData);
void addDisconnectedPopdata(const altintegration::PopData& popData);

std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks);
std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks);

PoPRewards getPopRewards(const CBlockIndex& pindexPrev, const CChainParams& params);
void addPopPayoutsIntoCoinbaseTx(CMutableTransaction& coinbaseTx, const CBlockIndex& pindexPrev, const CChainParams& params);
bool checkCoinbaseTxWithPopRewards(const CTransaction& tx, const CAmount& nFees, const CBlockIndex& pindexPrev, const CChainParams& params, CValidationState& state);
CAmount getCoinbaseSubsidy(const CAmount& subsidy, int32_t height, const CChainParams& params);

CBlockIndex* compareTipToBlock(CBlockIndex* candidate);
int compareForks(const CBlockIndex& left, const CBlockIndex& right);

} // namespace VeriBlock

#endif //BITCASH_SRC_VBK_POP_SERVICE_HPP
