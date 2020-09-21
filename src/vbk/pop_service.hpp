// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_POP_SERVICE_HPP
#define BITCASH_SRC_VBK_POP_SERVICE_HPP

#include "veriblock/altintegration.hpp"
#include "veriblock/storage/batch_adaptor.hpp"

class CDBWrapper;
class CScript;
typedef int64_t CAmount;

namespace VeriBlock {

using BlockBytes = std::vector<uint8_t>;
using PoPRewards = std::map<CScript, CAmount>;

altintegration::Altintegration& GetPop();
void SetPopConfig(const altintegration::Config& config);
void SetPop(CDBWrapper& db);
std::string toPrettyString(const altintegration::Altintegration& pop);

} // namespace VeriBlock


#endif