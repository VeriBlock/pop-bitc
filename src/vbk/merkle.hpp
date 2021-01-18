// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_MERKLE_HPP
#define BITCASH_SRC_VBK_MERKLE_HPP

#include <iostream>

#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>

namespace VeriBlock {

uint256 TopLevelMerkleRoot(const CBlockIndex* prevIndex, const CBlock& block, bool* mutated = nullptr);

bool VerifyTopLevelMerkleRoot(const CBlock& block, const CBlockIndex* pprevIndex, CValidationState& state);

} // namespace VeriBlock

#endif //BITCASH_SRC_VBK_MERKLE_HPP
