// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_POP_COMMON_HPP
#define BITCASH_SRC_VBK_POP_COMMON_HPP

#include <uint256.h>
#include <veriblock/pop_context.hpp>

class CBlockIndex;

namespace VeriBlock {

altintegration::PopContext& GetPop();

void StopPop();

void SetPopConfig(const altintegration::Config& config);

void SetPop(const std::shared_ptr<altintegration::PayloadsProvider>& payloads_provider,
    const std::shared_ptr<altintegration::BlockProvider>& block_provider);

altintegration::BlockIndex<altintegration::AltBlock>* GetAltBlockIndex(const uint256& hash);
altintegration::BlockIndex<altintegration::AltBlock>* GetAltBlockIndex(const CBlockIndex* index);

std::string toPrettyString(const altintegration::PopContext& pop);

} // namespace VeriBlock

#endif // BITCASH_SRC_VBK_POP_COMMON_HPP
