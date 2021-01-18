// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_TEST_UTIL_E2E_FIXTURE_HPP
#define BITCASH_SRC_VBK_TEST_UTIL_E2E_FIXTURE_HPP

#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <test/test_bitcash.h>
#include <validation.h>
#include <vbk/bootstraps.hpp>
#include <vbk/log.hpp>
#include <vbk/util.hpp>
#include <veriblock/alt-util.hpp>
#include <veriblock/mempool.hpp>
#include <veriblock/mock_miner_2.hpp>
#include <veriblock/pop_context.hpp>
#include <consensus/merkle.h>

#include <vbk/pop_service.hpp>

using altintegration::ATV;
using altintegration::BtcBlock;
using altintegration::MockMiner2;
using altintegration::PublicationData;
using altintegration::VbkBlock;
using altintegration::VTB;

struct TestLogger : public altintegration::Logger {
    ~TestLogger() override = default;

    void log(altintegration::LogLevel lvl, const std::string& msg) override
    {
        fmt::printf("[pop] [%s]\t%s\n", altintegration::LevelToString(lvl), msg);
    }
};

struct E2eFixture : public TestChain100Setup {
    CScript cbKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    MockMiner2 popminer;
    altintegration::ValidationState state;
    altintegration::PopContext* pop;
    std::vector<uint8_t> defaultPayoutInfo = {1, 2, 3, 4, 5};

    E2eFixture()
    {
        altintegration::SetLogger<TestLogger>();
        altintegration::GetLogger().level = altintegration::LogLevel::warn;

        // create N blocks necessary to start POP fork resolution
        CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        while (!Params().isPopActive(chainActive.Tip()->nHeight)) {
            CBlock b = CreateAndProcessBlock({}, scriptPubKey);
            m_coinbase_txns.push_back(b.vtx[0]);
        }

        pop = &VeriBlock::GetPop();
    }

    void InvalidateTestBlock(CBlockIndex* pblock)
    {
        CValidationState state;
        InvalidateBlock(state, Params(), pblock);
        ActivateBestChain(state, Params());
        mempool.clear();
    }

    void ReconsiderTestBlock(CBlockIndex* pblock)
    {
        CValidationState state;

        {
            LOCK(cs_main);
            ResetBlockFailureFlags(pblock);
        }
        ActivateBestChain(state, Params(), std::shared_ptr<const CBlock>());
    }

    BtcBlock::hash_t getLastKnownBTCblock()
    {
        auto blocks = VeriBlock::getLastKnownBTCBlocks(1);
        BOOST_CHECK(blocks.size() == 1);
        return blocks[0];
    }

    VbkBlock::hash_t getLastKnownVBKblock()
    {
        auto blocks = VeriBlock::getLastKnownVBKBlocks(1);
        BOOST_CHECK(blocks.size() == 1);
        return blocks[0];
    }

    ATV endorseAltBlock(uint256 hash, const std::vector<uint8_t>& payoutInfo)
    {
        CBlockIndex* endorsed = nullptr;
        {
            LOCK(cs_main);
            endorsed = LookupBlockIndex(hash);
            BOOST_CHECK(endorsed != nullptr);
        }

        auto publicationdata = createPublicationData(endorsed, payoutInfo);
        auto vbktx = popminer.createVbkTxEndorsingAltBlock(publicationdata);
        auto atv = popminer.applyATV(vbktx, state);
        BOOST_CHECK(state.IsValid());
        return atv;
    }

    ATV endorseAltBlock(uint256 hash)
    {
        return endorseAltBlock(hash, defaultPayoutInfo);
    }

    CBlock endorseAltBlockAndMine(const std::vector<uint256>& hashes, size_t generateVtbs = 0)
    {
        return endorseAltBlockAndMine(hashes, chainActive.Tip()->GetBlockHash(), generateVtbs);
    }

    CBlock endorseAltBlockAndMine(const std::vector<uint256>& hashes, uint256 prevBlock, size_t generateVtbs = 0)
    {
        return endorseAltBlockAndMine(hashes, prevBlock, defaultPayoutInfo, generateVtbs);
    }

    CBlock endorseAltBlockAndMine(const std::vector<uint256>& hashes, uint256 prevBlock, const std::vector<uint8_t>& payoutInfo, size_t generateVtbs = 0, bool expectAccepted = false)
    {
        std::vector<VTB> vtbs;
        vtbs.reserve(generateVtbs);
        std::generate_n(std::back_inserter(vtbs), generateVtbs, [&]() {
            return endorseVbkTip();
        });

        std::vector<ATV> atvs;
        atvs.reserve(hashes.size());
        std::transform(hashes.begin(), hashes.end(), std::back_inserter(atvs), [&](const uint256& hash) -> ATV {
            return endorseAltBlock(hash, payoutInfo);
        });

        auto& pop_mempool = *pop->mempool;
        altintegration::ValidationState state;
        for (const auto& atv : atvs) {
            pop_mempool.submit(atv, state);
            // do not check the submit result - expect statefully invalid data for testing purposes
        }

        for (const auto& vtb : vtbs) {
            pop_mempool.submit(vtb, state);
            // do not check the submit result - expect statefully invalid data for testing purposes
        }

        bool isValid = false;
        const auto& block = CreateAndProcessBlock({}, prevBlock, cbKey, &isValid);
        BOOST_CHECK(isValid);
        return block;
    }

    CBlock endorseAltBlockAndMine(uint256 hash, uint256 prevBlock, const std::vector<uint8_t>& payoutInfo, size_t generateVtbs = 0)
    {
        return endorseAltBlockAndMine(std::vector<uint256>{hash}, prevBlock, payoutInfo, generateVtbs);
    }

    CBlock endorseAltBlockAndMine(uint256 hash, size_t generateVtbs = 0)
    {
        return endorseAltBlockAndMine(hash, chainActive.Tip()->GetBlockHash(), generateVtbs);
    }

    CBlock endorseAltBlockAndMine(uint256 hash, uint256 prevBlock, size_t generateVtbs = 0)
    {
        return endorseAltBlockAndMine(hash, prevBlock, defaultPayoutInfo, generateVtbs);
    }

    VTB endorseVbkTip()
    {
        auto best = popminer.vbk().getBestChain();
        auto tip = best.tip();
        BOOST_CHECK(tip != nullptr);
        return endorseVbkBlock(tip->getHeight());
    }

    VTB endorseVbkBlock(int height)
    {
        auto vbkbest = popminer.vbk().getBestChain();
        auto endorsed = vbkbest[height];
        if (!endorsed) {
            throw std::logic_error("can not find VBK block at height " + std::to_string(height));
        }

        auto btctx = popminer.createBtcTxEndorsingVbkBlock(endorsed->getHeader());
        auto* btccontaining = popminer.mineBtcBlocks(1);
        auto vbktx = popminer.createVbkPopTxEndorsingVbkBlock(btccontaining->getHeader(), btctx, endorsed->getHeader(), getLastKnownBTCblock());
        auto* vbkcontaining = popminer.mineVbkBlocks(1);

        auto vtbs = popminer.vbkPayloads[vbkcontaining->getHash()];
        BOOST_CHECK(vtbs.size() == 1);
        return vtbs[0];
    }

    PublicationData createPublicationData(CBlockIndex* endorsed, const std::vector<uint8_t>& payoutInfo)
    {
        assert(endorsed);

        auto hash = endorsed->GetBlockHash();
        CBlock block;
        bool read = ReadBlockFromDisk(block, endorsed, Params().GetConsensus());
        assert(read && "expected to read endorsed block from disk");

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << endorsed->GetBlockHeader();
        std::vector<uint8_t> header{stream.begin(), stream.end()};

        auto txRoot = BlockMerkleRoot(block, nullptr).asVector();
        auto* libendorsed = VeriBlock::GetPop().altTree->getBlockIndex(hash.asVector());
        assert(libendorsed && "expected to have endorsed header in library");
        return altintegration::GeneratePublicationData(
            header,
            *libendorsed,
            txRoot,
            block.popData,
            payoutInfo,
            *VeriBlock::GetPop().config->alt);
    }

    PublicationData createPublicationData(CBlockIndex* endorsed)
    {
        return createPublicationData(endorsed, defaultPayoutInfo);
    }
};

#endif //BITCASH_SRC_VBK_TEST_UTIL_E2E_FIXTURE_HPP
