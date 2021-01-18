// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <vbk/pop_common.hpp>

namespace VeriBlock {

static std::shared_ptr<altintegration::PopContext> app = nullptr;
static std::shared_ptr<altintegration::Config> config = nullptr;

altintegration::PopContext& GetPop()
{
    assert(app && "Altintegration is not initialized. Invoke SetPop.");
    return *app;
}

void StopPop()
{
    if (app) {
        app->shutdown();
    }
}

void SetPopConfig(const altintegration::Config& newConfig)
{
    config = std::make_shared<altintegration::Config>(newConfig);
}

void SetPop(const std::shared_ptr<altintegration::PayloadsProvider>& payloads_provider, const std::shared_ptr<altintegration::BlockProvider>& block_provider)
{
    assert(config && "Config is not initialized. Invoke SetPopConfig.");
    app = altintegration::PopContext::create(config, payloads_provider, block_provider);
}

std::string toPrettyString(const altintegration::PopContext& pop)
{
    return pop.altTree->toPrettyString();
}

altintegration::BlockIndex<altintegration::AltBlock>* GetAltBlockIndex(const uint256& hash)
{
    return GetPop().altTree->getBlockIndex(hash.asVector());
}

altintegration::BlockIndex<altintegration::AltBlock>* GetAltBlockIndex(const CBlockIndex* index)
{
    return index == nullptr ? nullptr : GetAltBlockIndex(index->GetBlockHash());
}

} // namespace VeriBlock