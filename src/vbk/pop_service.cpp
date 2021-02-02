// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <dbwrapper.h>
#include <init.h>
#include <txdb.h>
#include <validation.h>
#include <veriblock/storage/util.hpp>

#ifdef WIN32
#include <boost/thread/interruption.hpp>
#endif //WIN32

#include <vbk/adaptors/block_provider.hpp>
#include <vbk/adaptors/payloads_provider.hpp>
#include <vbk/p2p_sync.hpp>
#include <vbk/pop_common.hpp>
#include <vbk/pop_service.hpp>

namespace VeriBlock {

void InitPopContext(CDBWrapper& db)
{
    auto payloads_provider = std::make_shared<PayloadsProvider>(db);
    SetPop(payloads_provider);

    auto& app = GetPop();
    app.mempool->onAccepted<altintegration::ATV>(VeriBlock::p2p::offerPopDataToAllNodes<altintegration::ATV>);
    app.mempool->onAccepted<altintegration::VTB>(VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VTB>);
    app.mempool->onAccepted<altintegration::VbkBlock>(VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VbkBlock>);
}

bool hasPopData(CBlockTreeDB& db)
{
    return db.Exists(tip_key<altintegration::BtcBlock>()) && db.Exists(tip_key<altintegration::VbkBlock>()) && db.Exists(tip_key<altintegration::AltBlock>());
}

void saveTrees(CDBBatch* batch)
{
    AssertLockHeld(cs_main);
    VeriBlock::BlockBatch b(*batch);
    altintegration::SaveAllTrees(*GetPop().altTree, b);
}
bool loadTrees(CDBWrapper& db)
{
    altintegration::ValidationState state;

    BlockReader reader(db);
    if (!altintegration::LoadAllTrees(GetPop(), reader, state)) {
        return error("%s: failed to load trees %s", __func__, state.toString());
    }

    return true;
}

altintegration::PopData getPopData() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    return GetPop().mempool->getPop();
}

void removePayloadsFromMempool(const altintegration::PopData& popData) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    GetPop().mempool->removeAll(popData);
}

void addDisconnectedPopdata(const altintegration::PopData& popData) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    altintegration::ValidationState state;
    auto& popmp = *VeriBlock::GetPop().mempool;
    for (const auto& i : popData.context) {
        popmp.submit(i, state);
    }
    for (const auto& i : popData.vtbs) {
        popmp.submit(i, state);
    }
    for (const auto& i : popData.atvs) {
        popmp.submit(i, state);
    }
}

bool acceptBlock(const CBlockIndex& indexNew, CValidationState& state)
{
    AssertLockHeld(cs_main);
    auto containing = VeriBlock::blockToAltBlock(indexNew);
    altintegration::ValidationState instate;
    if (!GetPop().altTree->acceptBlockHeader(containing, instate)) {
        LogPrintf("ERROR: alt tree cannot accept block %s\n", instate.toString());
        return state.Invalid(false,
                             REJECT_INVALID,
                             "",
                             instate.GetDebugMessage());
    }
    return true;
}

bool checkPopDataSize(const altintegration::PopData& popData, altintegration::ValidationState& state)
{
    uint32_t nPopDataSize = ::GetSerializeSize(popData, CLIENT_VERSION);
    if (nPopDataSize >= GetPop().config->alt->getMaxPopDataSize()) {
        return state.Invalid("popdata-oversize", "popData raw size more than allowed");
    }

    return true;
}

bool popdataStatelessValidation(const altintegration::PopData& popData, altintegration::ValidationState& state)
{
    auto& pop = GetPop();
    return altintegration::checkPopData(*pop.popValidator, popData, state);
}

bool addAllBlockPayloads(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    auto bootstrapBlockHeight = GetPop().config->alt->getBootstrapBlock().height;
    auto hash = block.GetHash();
    auto* index = LookupBlockIndex(hash);

    if (index->nHeight == bootstrapBlockHeight) {
        // skip bootstrap block block
        return true;
    }

    altintegration::ValidationState instate;

    if (!popdataStatelessValidation(block.popData, instate)) {
        return error("[%s] block %s is not accepted because popData is invalid: %s", __func__, block.GetHash().ToString(),
            instate.toString());
    }

    GetPop().altTree->acceptBlock(block.GetHash().asVector(), block.popData);

    return true;
}

bool setState(const uint256& hash, altintegration::ValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    return GetPop().altTree->setState(hash.asVector(), state);
}

std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks)
{
    LOCK(cs_main);
    return altintegration::getLastKnownBlocks(GetPop().altTree->vbk(), blocks);
}

std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks)
{
    LOCK(cs_main);
    return altintegration::getLastKnownBlocks(GetPop().altTree->btc(), blocks);
}

// PoP rewards are calculated for the current tip but are paid in the next block
PoPRewards getPopRewards(const CBlockIndex& pindexPrev, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    const auto& pop = GetPop();

    if (!params.isPopActive(pindexPrev.nHeight)) {
        return {};
    }

    auto& cfg = *pop.config;
    if (pindexPrev.nHeight < (int)cfg.alt->getEndorsementSettlementInterval()) {
        return {};
    }
    if (pindexPrev.nHeight < (int)cfg.alt->getPayoutParams().getPopPayoutDelay()) {
        return {};
    }

    altintegration::ValidationState state;
    auto prevHash = pindexPrev.GetBlockHash().asVector();
    bool ret = pop.altTree->setState(prevHash, state);
    (void)ret;
    assert(ret);

    auto rewards = pop.popRewardsCalculator->getPopPayout(prevHash);
    int halvings = (pindexPrev.nHeight + 1 < params.GetConsensus().nSubsidyFirstInterval)?
        0 :
        (pindexPrev.nHeight + 1 - params.GetConsensus().nSubsidyFirstInterval) / params.GetConsensus().nSubsidyHalvingInterval;
    PoPRewards result{};
    // erase rewards, that pay 0 satoshis, then halve rewards
    for (const auto& r : rewards) {
        auto rewardValue = r.second;
        rewardValue >>= halvings;
        if ((rewardValue != 0) && (halvings < 64)) {
            CScript key = CScript(r.first.begin(), r.first.end());
            result[key] = params.PopRewardCoefficient() * rewardValue;
        }
    }

    return result;
}

void addPopPayoutsIntoCoinbaseTx(CMutableTransaction& coinbaseTx, const CBlockIndex& pindexPrev, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    PoPRewards rewards = getPopRewards(pindexPrev, params);
    assert(coinbaseTx.vout.size() == 2 && "at this place we should have only PoW and DevFund payout here");
    for (const auto& itr : rewards) {
        CTxOut out;
        out.scriptPubKey = itr.first;
        out.nValue = itr.second;
        out.nValueBitCash = itr.second;
        out.currency = 0;
        coinbaseTx.vout.push_back(out);
    }
}

bool checkCoinbaseTxWithPopRewards(const CTransaction& tx, const CAmount& nFees, const CBlockIndex& pindex, const CChainParams& params, CValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    const CBlockIndex& pindexPrev = *pindex.pprev;
    PoPRewards expectedRewards = getPopRewards(pindexPrev, params);
    CAmount nTotalPopReward = 0;

    if (tx.vout.size() < expectedRewards.size()) {
        return state.Invalid(false, REJECT_INVALID, "bad-pop-vouts-size",
            strprintf("checkCoinbaseTxWithPopRewards(): coinbase has incorrect size of pop vouts (actual vouts size=%d vs expected vouts=%d)", tx.vout.size(), expectedRewards.size()));
    }
    if (tx.vout.size() < 2) {
        return state.Invalid(false, REJECT_INVALID, "bad-coinbase-vouts-size",
            strprintf("checkCoinbaseTxWithPopRewards(): coinbase has incorrect size of vouts (actual vouts size=%d vs expected vouts=%d)", tx.vout.size(), 2));
    }

    std::map<CScript, CAmount> cbpayouts;
    // skip first reward, as it is always PoW payout
    // skip second reward as it pays to the DevFund
    for (auto out = tx.vout.begin() + 2, end = tx.vout.end(); out != end; ++out) {
        // pop payouts can not be null
        if (out->IsNull()) {
            continue;
        }
        cbpayouts[out->scriptPubKey] += out->nValue;
    }

    for (const auto& payout : expectedRewards) {
        auto& script = payout.first;
        auto& expectedAmount = payout.second;

        auto p = cbpayouts.find(script);
        // coinbase pays correct reward?
        if (p == cbpayouts.end()) {
            // we expected payout for that address
            return state.Invalid(false, REJECT_INVALID, "bad-pop-missing-payout",
                strprintf("[tx: %s] missing payout for scriptPubKey: '%s' with amount: '%d'",
                    tx.GetHash().ToString(),
                    HexStr(script),
                    expectedAmount));
        }

        // payout found
        auto& actualAmount = p->second;
        // does it have correct amount?
        if (actualAmount != expectedAmount) {
            return state.Invalid(false, REJECT_INVALID, "bad-pop-wrong-payout",
                strprintf("[tx: %s] wrong payout for scriptPubKey: '%s'. Expected %d, got %d.",
                    tx.GetHash().ToString(),
                    HexStr(script),
                    expectedAmount, actualAmount));
        }

        nTotalPopReward += expectedAmount;
    }

    CAmount PoWBlockReward =
        GetBlockSubsidy(pindex.nHeight, params);
    CAmount DevFundBlockReward =
        GetBlockSubsidyDevs(pindex.nHeight, params.GetConsensus());

    if (tx.GetValueOut() > nTotalPopReward + PoWBlockReward + DevFundBlockReward + nFees) {
        return state.Invalid(false, REJECT_INVALID,
            "bad-cb-pop-amount",
            strprintf("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)", tx.GetValueOut(), PoWBlockReward + DevFundBlockReward + nTotalPopReward));
    }

    return true;
}

CAmount getCoinbaseSubsidy(const CAmount& subsidy, int32_t height, const CChainParams& params)
{
    if (!params.isPopActive(height)) {
        return subsidy;
    }

    int64_t powRewardPercentage = 100 - params.PopRewardPercentage();
    CAmount newSubsidy = powRewardPercentage * subsidy;
    return newSubsidy / 100;
}

CBlockIndex* compareTipToBlock(CBlockIndex* candidate)
{
    AssertLockHeld(cs_main);
    assert(candidate != nullptr && "block has no according header in block tree");

    auto blockHash = candidate->GetBlockHash();
    auto* tip = chainActive.Tip();
    if (!tip) {
        // if tip is not set, candidate wins
        return nullptr;
    }

    auto tipHash = tip->GetBlockHash();
    if (tipHash == blockHash) {
        // we compare tip with itself
        return tip;
    }

    int result = 0;
    if (Params().isPopActive(tip->nHeight)) {
        result = compareForks(*tip, *candidate);
    } else {
        result = CBlockIndexWorkComparator()(tip, candidate) ? -1 : 1;
    }

    if (result < 0) {
        // candidate has higher POP score
        return candidate;
    }

    if (result == 0 && tip->nChainWork < candidate->nChainWork) {
        // candidate is POP equal to current tip;
        // candidate has higher chainwork
        return candidate;
    }

    // otherwise, current chain wins
    return tip;
}

int compareForks(const CBlockIndex& leftForkTip, const CBlockIndex& rightForkTip) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto& pop = GetPop();
    AssertLockHeld(cs_main);
    if (&leftForkTip == &rightForkTip) {
        return 0;
    }

    auto left = blockToAltBlock(leftForkTip);
    auto right = blockToAltBlock(rightForkTip);
    auto state = altintegration::ValidationState();

    if (!pop.altTree->setState(left.hash, state)) {
        if (!pop.altTree->setState(right.hash, state)) {
            throw std::logic_error("both chains are invalid");
        }
        return -1;
    }

    return pop.altTree->comparePopScore(left.hash, right.hash);
}

} // namespace VeriBlock
