// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __BOOTSTRAPS_BITC_VBK
#define __BOOTSTRAPS_BITC_VBK

#include <string>
#include <vector>

#include <primitives/block.h>
#include <util.h>
#include <veriblock/config.hpp>

namespace VeriBlock {

extern const int testnetVBKstartHeight;
extern const std::vector<std::string> testnetVBKblocks;

extern const int testnetBTCstartHeight;
extern const std::vector<std::string> testnetBTCblocks;

struct AltChainParamsVBitCash : public altintegration::AltChainParams {
    ~AltChainParamsVBitCash() override = default;

    AltChainParamsVBitCash(const CBlock& genesis)
    {
        auto hash = genesis.GetHash();
        bootstrap.hash = std::vector<uint8_t>{hash.begin(), hash.end()};
        bootstrap.previousBlock = genesis.hashPrevBlock.asVector();
        bootstrap.height = 0; // pop is enabled starting at genesis
        bootstrap.timestamp = genesis.GetBlockTime();
    }

    altintegration::AltBlock getBootstrapBlock() const noexcept override
    {
        return bootstrap;
    }

    int64_t getIdentifier() const noexcept override
    {
        return 0x3ae6ca;
    }

    std::vector<uint8_t> getHash(const std::vector<uint8_t>& bytes) const noexcept override;

    altintegration::AltBlock bootstrap;
};

void printConfig(const altintegration::Config& config);
void selectPopConfig(const ArgsManager& mgr);
void selectPopConfig(
    const std::string& btcnet,
    const std::string& vbknet,
    bool popautoconfig = true,
    int btcstart = 0,
    const std::string& btcblocks = {},
    int vbkstart = 0,
    const std::string& vbkblocks = {});

} // namespace VeriBlock

#endif //__BOOTSTRAPS_BITC_VBK
