// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <chainparams.h>
#include <consensus/validation.h>
#include <test/test_bitcash.h>
#include <validation.h>

#include <vbk/pop_service.hpp>
#include <vbk/test/util/e2e_fixture.hpp>
#include <veriblock/mock_miner.hpp>

using altintegration::BtcBlock;
using altintegration::MockMiner;
using altintegration::PublicationData;
using altintegration::VbkBlock;
using altintegration::VTB;

BOOST_AUTO_TEST_SUITE(forkresolution_tests)

BOOST_FIXTURE_TEST_CASE(not_crossing_keystone_case_1_test, E2eFixture)
{
    for (int i = 0; i < 2; i++) {
        CreateAndProcessBlock({}, cbKey);
    }

    CBlockIndex* pblock = chainActive.Tip();
    InvalidateTestBlock(pblock);

    for (int i = 0; i < 3; i++) {
        CreateAndProcessBlock({}, cbKey);
    }

    CBlockIndex* pblock2 = chainActive.Tip();

    ReconsiderTestBlock(pblock);

    BOOST_CHECK(pblock2 == chainActive.Tip());
}

BOOST_FIXTURE_TEST_CASE(not_crossing_keystone_case_2_test, E2eFixture)
{
    CreateAndProcessBlock({}, cbKey);
    CBlockIndex* pblock = chainActive.Tip();
    InvalidateTestBlock(pblock);

    CreateAndProcessBlock({}, cbKey);

    ReconsiderTestBlock(pblock);

    BOOST_CHECK(pblock == chainActive.Tip());
}

BOOST_FIXTURE_TEST_CASE(not_crossing_keystone_case_3_test, E2eFixture)
{
    for (int i = 0; i < 2; i++) {
        CreateAndProcessBlock({}, cbKey);
    }

    CBlockIndex* pblock = chainActive.Tip();
    InvalidateTestBlock(pblock);

    CBlockIndex* pblock2 = chainActive.Tip();
    InvalidateTestBlock(pblock2);

    ReconsiderTestBlock(pblock);
    ReconsiderTestBlock(pblock2);

    BOOST_CHECK(pblock == chainActive.Tip());
}

BOOST_FIXTURE_TEST_CASE(not_crossing_keystone_case_4_test, E2eFixture)
{
    CreateAndProcessBlock({}, cbKey);
    CBlockIndex* pblock = chainActive.Tip();

    CreateAndProcessBlock({}, cbKey);
    CBlockIndex* pblock2 = chainActive.Tip();

    InvalidateTestBlock(pblock);
    CreateAndProcessBlock({}, cbKey);
    CreateAndProcessBlock({}, cbKey);
    ReconsiderTestBlock(pblock);
    BOOST_CHECK(pblock2 == chainActive.Tip());
}

BOOST_FIXTURE_TEST_CASE(crossing_keystone_case_1_test, E2eFixture)
{
    CBlockIndex* pblock = chainActive.Tip();
    CreateAndProcessBlock({}, cbKey);
    InvalidateTestBlock(pblock);

    for (int i = 0; i < 3; i++) {
        CreateAndProcessBlock({}, cbKey);
    }

    CBlockIndex* pblock2 = chainActive.Tip();
    ReconsiderTestBlock(pblock);
    BOOST_CHECK(pblock2 == chainActive.Tip());
}

BOOST_FIXTURE_TEST_CASE(crossing_keystone_case_2_test, E2eFixture)
{
    CBlockIndex* pblock = chainActive.Tip();
    InvalidateTestBlock(pblock);

    for (int i = 0; i < 2; i++) {
        CreateAndProcessBlock({}, cbKey);
    }

    CBlockIndex* pblock2 = chainActive[100];
    CBlockIndex* pblock3 = chainActive.Tip();
    InvalidateTestBlock(pblock2);

    for (int i = 0; i < 2; i++) {
        CreateAndProcessBlock({}, cbKey);
    }

    ReconsiderTestBlock(pblock);
    ReconsiderTestBlock(pblock2);
    BOOST_CHECK(pblock3 == chainActive.Tip());
}

BOOST_FIXTURE_TEST_CASE(crossing_keystone_case_3_test, E2eFixture)
{
    CBlockIndex* pblock = chainActive.Tip();
    InvalidateTestBlock(pblock);
    CreateAndProcessBlock({}, cbKey);

    CBlockIndex* pblock2 = chainActive.Tip();
    InvalidateTestBlock(pblock2);
    CreateAndProcessBlock({}, cbKey);

    ReconsiderTestBlock(pblock);
    ReconsiderTestBlock(pblock2);

    BOOST_CHECK(pblock == chainActive.Tip());
}

BOOST_FIXTURE_TEST_CASE(crossing_keystone_case_4_test, E2eFixture)
{
    CBlockIndex* pblock = chainActive.Tip();
    CreateAndProcessBlock({}, cbKey);
    InvalidateTestBlock(pblock);

    for (int i = 0; i < 3; i++) {
        CreateAndProcessBlock({}, cbKey);
    }

    CBlockIndex* pblock2 = chainActive.Tip();
    InvalidateTestBlock(pblock2);

    for (int i = 0; i < 2; i++) {
        CreateAndProcessBlock({}, cbKey);
    }

    CBlockIndex* pblock3 = chainActive.Tip();

    ReconsiderTestBlock(pblock);
    ReconsiderTestBlock(pblock2);

    BOOST_CHECK(pblock3 == chainActive.Tip());
}

BOOST_FIXTURE_TEST_CASE(crossing_keystone_with_pop_invalid_1_test, E2eFixture)
{
    auto& config = *VeriBlock::GetPop().config;
    for (int i = 0; i < config.alt->getEndorsementSettlementInterval() + 2; ++i) {
        CreateAndProcessBlock({}, cbKey);
    }

    CBlockIndex* pblock = chainActive.Tip();

    auto* endorsedBlockIndex = chainActive[config.alt->getEndorsementSettlementInterval() - 2];

    endorseAltBlockAndMine(endorsedBlockIndex->GetBlockHash(), 10);
    CreateAndProcessBlock({}, cbKey);

    InvalidateTestBlock(pblock);

    CreateAndProcessBlock({}, cbKey);
    CreateAndProcessBlock({}, cbKey);
    CreateAndProcessBlock({}, cbKey);
    CreateAndProcessBlock({}, cbKey);
    CreateAndProcessBlock({}, cbKey);
    CreateAndProcessBlock({}, cbKey); // Add a few blocks which it is mean that for the old variant of the fork resolution it should be the main chain

    ReconsiderTestBlock(pblock);
}

BOOST_FIXTURE_TEST_CASE(crossing_keystone_with_pop_1_test, E2eFixture)
{
    int startHeight = chainActive.Tip()->nHeight;

    // mine 20 blocks
    for (int i = 0; i < 20; ++i) {
        CreateAndProcessBlock({}, cbKey);
    }

    auto* atip = chainActive.Tip();
    auto* forkBlockNext = atip->GetAncestor(atip->nHeight - 13);
    auto* forkBlock = forkBlockNext->pprev;
    InvalidateTestBlock(forkBlockNext);

    for (int i = 0; i < 12; ++i) {
        CreateAndProcessBlock({}, cbKey);
    }

    auto* btip = chainActive.Tip();

    BOOST_CHECK_EQUAL(atip->nHeight, startHeight + 20);
    BOOST_CHECK_EQUAL(btip->nHeight, startHeight + 18);
    BOOST_CHECK_EQUAL(forkBlock->nHeight, startHeight + 6);

    BOOST_CHECK(btip->GetBlockHash() == chainActive.Tip()->GetBlockHash());
    auto* endorsedBlock = btip->GetAncestor(btip->nHeight - 6);
    CBlock expectedTip = endorseAltBlockAndMine(endorsedBlock->GetBlockHash(), 10);

    BOOST_CHECK(expectedTip.GetHash() == chainActive.Tip()->GetBlockHash());

    ReconsiderTestBlock(forkBlockNext);

    BOOST_CHECK(expectedTip.GetHash() == chainActive.Tip()->GetBlockHash());
}

BOOST_FIXTURE_TEST_CASE(crossing_keystone_without_pop_1_test, E2eFixture)
{
    // Similar scenario like in crossing_keystone_with_pop_1_test case
    // The main difference that we do not endorse any block so the best chain is the highest chain

    // mine 20 blocks
    for (int i = 0; i < 20; ++i) {
        CreateAndProcessBlock({}, cbKey);
    }

    auto* atip = chainActive.Tip();
    auto* forkBlockNext = atip->GetAncestor(atip->nHeight - 13);
    InvalidateTestBlock(forkBlockNext);

    for (int i = 0; i < 12; ++i) {
        CreateAndProcessBlock({}, cbKey);
    }

    auto* btip = chainActive.Tip();

    BOOST_CHECK(btip->GetBlockHash() == chainActive.Tip()->GetBlockHash());
    CreateAndProcessBlock({}, cbKey);
    auto* expectedTip = chainActive.Tip();

    BOOST_CHECK(expectedTip->GetBlockHash() == chainActive.Tip()->GetBlockHash());

    ReconsiderTestBlock(forkBlockNext);

    BOOST_CHECK(atip->GetBlockHash() == chainActive.Tip()->GetBlockHash());
}

BOOST_AUTO_TEST_SUITE_END()