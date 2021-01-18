// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dbwrapper.h>
#include <init.h>
#include <txdb.h>
#include <validation.h>
#include <veriblock/storage/util.hpp>

#ifdef WIN32
#include <boost/thread/interruption.hpp>
#endif //WIN32

#include <vbk/adaptors/block_provider.hpp>
#include <vbk/pop_common.hpp>
#include <vbk/pop_service.hpp>

namespace VeriBlock {

static std::shared_ptr<PayloadsProvider> payloads_provider = nullptr;
static std::shared_ptr<BlockProvider> block_provider = nullptr;

void SetPop(CDBWrapper& db)
{
    payloads_provider = std::make_shared<PayloadsProvider>(db);
    block_provider = std::make_shared<BlockProvider>(db);

    SetPop(std::shared_ptr<altintegration::PayloadsProvider>(payloads_provider),
        std::shared_ptr<altintegration::BlockProvider>(block_provider));
}

PayloadsProvider& GetPayloadsProvider()
{
    return *payloads_provider;
}

bool hasPopData(CBlockTreeDB& db)
{
    return db.Exists(tip_key<altintegration::BtcBlock>()) && db.Exists(tip_key<altintegration::VbkBlock>()) && db.Exists(tip_key<altintegration::AltBlock>());
}

void saveTrees(altintegration::BlockBatchAdaptor& batch)
{
    AssertLockHeld(cs_main);
    altintegration::SaveAllTrees(*GetPop().altTree, batch);
}

bool loadTrees(CDBIterator& iter)
{
    auto& pop = GetPop();
    altintegration::ValidationState state;

    if (!altintegration::LoadAllTrees(pop, state)) {
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

bool popDataStatelessValidation(const altintegration::PopData& popData, altintegration::ValidationState& state)
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
        // skip bootstrap block
        return true;
    }

    altintegration::ValidationState instate;

    if (!checkPopDataSize(block.popData, instate) || !popDataStatelessValidation(block.popData, instate)) {
        return error("[%s] block %s is not accepted because popData is invalid: %s",
                     __func__,
                     hash.ToString(),
                     instate.toString());
    }

    auto& provider = GetPayloadsProvider();
    provider.write(block.popData);

    GetPop().altTree->acceptBlock(hash.asVector(), block.popData);

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

} // namespace VeriBlock
