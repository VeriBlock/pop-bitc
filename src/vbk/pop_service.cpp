// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <memory>

#include "vbk/pop_service.hpp"


namespace VeriBlock {

static std::shared_ptr<altintegration::Altintegration> app = nullptr;
static std::shared_ptr<altintegration::Config> config = nullptr;

altintegration::Altintegration& GetPop()
{
    assert(app && "Altintegration is not initialized. Invoke SetPop.");
    return *app;
}

void SetPopConfig(const altintegration::Config& newConfig)
{
    config = std::make_shared<altintegration::Config>(newConfig);
}

void SetPop(CDBWrapper& db)
{
    assert(config && "Config is not initialized. Invoke SetPopConfig");

    // TODO implement Repository class
    std::shared_ptr<altintegration::Repository> dbrepo = nullptr;
    app = altintegration::Altintegration::create(config, dbrepo);
}

std::string toPrettyString(const altintegration::Altintegration& pop)
{
    return pop.altTree->toPrettyString();
}

} // namespace VeriBlock