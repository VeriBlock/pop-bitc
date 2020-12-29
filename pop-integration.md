# Bitcash POP integration write-up

## Bitcash clone
```sh
git clone https://github.com/WillyTheCat/BitCash.git
```
## Bitcash dependencies
See [https://github.com/WillyTheCat/BitCash/tree/master/doc]

### Bitcash dependencies Ubuntu example
```sh
sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils python3
```
```sh
sudo apt-get install libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev
```
```sh
sudo apt-get install libdb-dev libcurl4-openssl-dev
```
```sh
sudo apt-get install libminiupnpc-dev
```
```sh
sudo apt-get install libzmq3-dev
```

## Bitcash build
```sh
cd BitCash
./autogen.sh
./configure --without-gui --disable-bench --with-incompatible-bdb
make
```

### run tests:
```sh
make check
```

## Install veriblock-pop-cpp library
```sh
git clone https://github.com/VeriBlock/alt-integration-cpp.git
cd alt-integration-cpp
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_PYPOPMINER=ON
make
sudo make install
```

## Add veriblock-pop-cpp library dependency
[<font style="color: red"> configure.ac </font>]
```diff
PKG_CHECK_MODULES([CRYPTO], [libcrypto],,[AC_MSG_ERROR(libcrypto not found.)])
+      # VeriBlock
+      echo "pkg-config is used..."
+      export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib64/pkgconfig
+      export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig
+      export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/lib64/pkgconfig
+      export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/lib/pkgconfig
+      PKG_CHECK_MODULES([VERIBLOCK_POP_CPP], [veriblock-pop-cpp],,[AC_MSG_ERROR(libveriblock-pop-cpp not found.)])
```
```diff
else
+  # VeriBlock
+  AC_CHECK_HEADER([veriblock/pop_context.hpp],,AC_MSG_ERROR(veriblock-pop-cpp headers missing))
+  AC_CHECK_LIB([veriblock-pop-cpp],[main],[VERIBLOCK_POP_CPP_LIBS=" -lveriblock-pop-cpp"],AC_MSG_ERROR(veriblock-pop-cpp missing))
+
+  AC_ARG_VAR(VERIBLOCK_POP_CPP_LIBS, "linker flags for VERIBLOCK_POP_CPP")
+
   AC_CHECK_HEADER([openssl/crypto.h],,AC_MSG_ERROR(libcrypto headers missing))
```
[<font style="color: red"> src/Makefile.am </font>]
```diff
bitcashd_LDADD = \
+  $(VERIBLOCK_POP_CPP_LIBS) \
   $(LIBBITCASH_SERVER) \
```
```diff
-bitcashd_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CURL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(DL_LIBS)
+bitcashd_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CURL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(VERIBLOCK_POP_CPP_LIBS)  $(DL_LIBS)
```
```diff
bitcash_cli_LDADD = \
   $(LIBBITCASH_CLI) \
   $(LIBUNIVALUE) \
   $(LIBBITCASH_UTIL) \
-  $(LIBBITCASH_CRYPTO)
+  $(LIBBITCASH_CRYPTO) \
+  $(VERIBLOCK_POP_CPP_LIBS)
```
```diff
 bitcash_tx_LDADD = \
   $(LIBUNIVALUE) \
+  $(VERIBLOCK_POP_CPP_LIBS) \
   $(LIBBITCASH_COMMON) \
   $(LIBBITCASH_UTIL) \
   $(LIBBITCASH_CRYPTO)
 
-bitcash_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
+bitcash_tx_LDADD += $(BOOST_LIBS) $(VERIBLOCK_POP_CPP_LIBS) $(CRYPTO_LIBS)
```
[<font style="color: red"> src/Makefile.bench.include </font>]
```diff
bench_bench_bitcash_LDADD = \
   $(LIBMEMENV) \
   $(LIBSECP256K1) \
   $(LIBUNIVALUE) \
-  $(DL_LIBS)
+  $(DL_LIBS) \
+  $(VERIBLOCK_POP_CPP_LIBS)
```
[<font style="color: red"> src/Makefile.test.include </font>]
```diff
-test_test_bitcash_LDADD += $(LIBBITCASH_SERVER) $(LIBBITCASH_CLI) $(LIBBITCASH_COMMON) $(LIBBITCASH_UTIL) $(LIBBITCASH_CONSENSUS) $(LIBBITCASH_CRYPTO) $(LIBUNIVALUE) \
-  $(LIBLEVELDB) $(LIBLEVELDB_SSE42) $(LIBMEMENV) $(BOOST_LIBS) $(BOOST_UNIT_TEST_FRAMEWORK_LIB) $(LIBSECP256K1) $(EVENT_LIBS) $(EVENT_PTHREADS_LIBS)
+test_test_bitcash_LDADD += $(VERIBLOCK_POP_CPP_LIBS) $(LIBBITCASH_SERVER) $(LIBBITCASH_CLI) $(LIBBITCASH_COMMON) $(LIBBITCASH_UTIL) $(LIBBITCASH_CONSENSUS) $(LIBBITCASH_CRYPTO) $(LIBUNIVALUE) \
+  $(LIBLEVELDB) $(LIBLEVELDB_SSE42) $(LIBMEMENV) $(BOOST_LIBS) $(BOOST_UNIT_TEST_FRAMEWORK_LIB) $(LIBSECP256K1) $(EVENT_LIBS) $(EVENT_PTHREADS_LIBS) $(VERIBLOCK_POP_CPP_LIBS) $(CURL_LIBS)
```
```diff
test_test_bitcash_fuzzy_LDADD = \
   $(LIBUNIVALUE) \
+  $(VERIBLOCK_POP_CPP_LIBS) \
   $(LIBBITCASH_SERVER) \
   $(LIBBITCASH_COMMON) \
   $(LIBBITCASH_UTIL) \
 
-test_test_bitcash_fuzzy_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
+test_test_bitcash_fuzzy_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS) $(VERIBLOCK_POP_CPP_LIBS)
```

## Add PopData in the Block
We should add new PopData entity into the CBlock class in the block.h file and provide new nVersion flag. It is needed for storing VeriBlock specific information such as ATVs, VTBs, VBKs.
First we will add new POP_BLOCK_VERSION_BIT flag, that will help to distinguish original blocks that don't have any VeriBlock specific data, and blocks that contain such data.
Next, update serialization of the block, that will serialize/deserialize PopData if POP_BLOCK_VERSION_BIT is set. Finally extend serialization/deserialization for the PopData, so we can use the bitcoin native serialization/deserialization.

### Define POP_BLOCK_VERSION_BIT flag.
[<font style="color: red"> src/vbk/vbk.hpp </font>]
```diff
#ifndef BITCOIN_SRC_VBK_VBK_HPP
#define BITCOIN_SRC_VBK_VBK_HPP

#include <uint256.h>

namespace VeriBlock {

using KeystoneArray = std::array<uint256, 2>;

const static int32_t POP_BLOCK_VERSION_BIT = 0x80000UL;

}  // namespace VeriBlock

#endif //BITCOIN_SRC_VBK_VBK_HPP
```
[<font style="color: red">src/primitives/block.h</font>]
```diff
#include <set>
+#include <vbk/vbk.hpp>
+
+#include "veriblock/entities/popdata.hpp"
 
 #define hashx25Xactive ((uint32_t)1) << 6
 #define gpumineractive ((uint32_t)1) << 5
```
_class CBlock_
```diff
public:
     // network and disk
     std::vector<CTransactionRef> vtx;
+    // VeriBlock  data network and disk
+    altintegration::PopData popData;
 
     // memory only
     mutable bool fChecked;
     inline void SerializationOp(Stream& s, Operation ser_action) {
         READWRITEAS(CBlockHeader, *this);
         READWRITE(vtx);
+        if (this->nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+            READWRITE(popData);
+        }
     }
```

We should also update p2p networking objects such as CBlockHeaderAndShortTxIDs, BlockTransaction, PartiallyDownloadedBlock with the VeriBlock PopData for the correct broadcasting of the VeriBlock data to the network.

### Add new PopData filed into the BlockTransaction, CBlockHeaderAndShortTxIDs, PartiallyDownloadedBlock and update their serialization/deserialization.
[<font style="color: red"> src/blockencodings.h </font>]  
_class BlockTransactions_
```diff
// A BlockTransactions message
     uint256 blockhash;
     std::vector<CTransactionRef> txn;
+    // VeriBlock data
+    altintegration::PopData popData;
 
     BlockTransactions() {}
     explicit BlockTransactions(const BlockTransactionsRequest& req) :
             for (size_t i = 0; i < txn.size(); i++)
                 READWRITE(TransactionCompressor(txn[i]));
         }
+
+        // VeriBlock data
+        READWRITE(popData);
     }
```
_class CBlockHeaderAndShortTxIDs_
```diff
public:
     CBlockHeader header;
+    // VeriBlock data
+    altintegration::PopData popData;
 
     // Dummy for deserialization
     CBlockHeaderAndShortTxIDs() {}
             }
         }
 
+        if (this->header.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+            READWRITE(popData);
+        }
+
+
         READWRITE(prefilledtxn);
```
_class PartiallyDownloadedBlock_
```diff
CTxMemPool* pool;
 public:
     CBlockHeader header;
+    // VeriBlock data
+    altintegration::PopData popData;
+
     explicit PartiallyDownloadedBlock(CTxMemPool* poolIn) : pool(poolIn) {}
 
     // extra_txn is a list of extra transactions to look at, in <witness hash, reference> form
     ReadStatus InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn);
     bool IsTxAvailable(size_t index) const;
     ReadStatus FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing);
+    ReadStatus FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing, const altintegration::PopData& popData);
 };
```

### Update PartiallyDownloadedBlock object initializing - fill PopData field.
[<font style="color: red"> src/blockencodings.cpp </font>]  
_method PartiallyDownloadedBlock::InitData_
```diff
-    LogPrint(BCLog::CMPCTBLOCK, "Initialized PartiallyDownloadedBlock for block %s using a cmpctblock of size %lu\n", cmpctblock.header.GetHash().ToString(), GetSerializeSize(cmpctblock, SER_NETWORK, PROTOCOL_VERSION));
+    // VeriBlock: set pop data
+    this->popData = cmpctblock.popData;
+
+    LogPrint(BCLog::CMPCTBLOCK, "Initialized PartiallyDownloadedBlock for block %s using a cmpctblock of size %lu with %d VBK %d VTB %d ATV\n", cmpctblock.header.GetHash().ToString(), GetSerializeSize(cmpctblock, PROTOCOL_VERSION), this->popData.context.size(), this->popData.vtbs.size(), this->popData.atvs.size());
 
     return READ_STATUS_OK;
 }
```
_method PartiallyDownloadedBlock::FillBlock_
```diff
     if (vtx_missing.size() != tx_missing_offset)
         return READ_STATUS_INVALID;
 
+    // VeriBlock: set popData before CheckBlock
+    block.popData = this->popData;
+
     CValidationState state;
```
```diff
+
+ReadStatus PartiallyDownloadedBlock::FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing, const altintegration::PopData& popData) {
+    block.popData = popData;
+    ReadStatus status = FillBlock(block, vtx_missing);
+    return status;
+}
```

### Also update setup of the PopData fields during the net processing.
[<font style="color: red"> src/net_processing.cpp </font>]  
_method SendBlockTransactions_
```diff
}
         resp.txn[i] = block.vtx[req.indexes[i]];
     }
+
+    // VeriBlock: add popData
+    resp.popData = block.popData;
+
     LOCK(cs_main);
     const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
     int nSendFlags = State(pfrom->GetId())->fWantsCmpctWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS;
```
_method ProcessMessage_
```diff
 status = tempBlock.FillBlock(*pblock, dummy);
                 if (status == READ_STATUS_OK) {
                     fBlockReconstructed = true;
+                    // VeriBlock: check for empty popData
+                    if(pblock && pblock->nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+                        VBK_ASSERT(!pblock->popData.empty() && "POP bit is set and POP data is empty");
+                    }
                 }
             }
```
_method ProcessMessage_
```diff
for (unsigned int n = 0; n < nCount; n++) {
             vRecv >> headers[n];
             ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
+            if (headers[n].nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+                altintegration::PopData tmp;
+                vRecv >> tmp;
+            }
         }
```

The last step is to update validation rules, add check that if block contains VeriBlock PopData, then block.nVersion must contain POP_BLOCK_VERSION_BIT. Otherwise block.nVersion should not contain POP_BLOCK_VERSION_BIT. 

### Update CheckBlock function in the validation.cpp for this check.
[<font style="color: red"> src/validation.cpp </font>]  
_method UpdateTip_
```diff
         for (int i = 0; i < 100 && pindex != nullptr; i++)
         {
             int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, chainParams.GetConsensus());
-            if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
+            // do not expect this flag to be set
+            auto version = pindex->nVersion & (~VeriBlock::POP_BLOCK_VERSION_BIT);
+            if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (version & ~nExpectedVersion) != 0)
                 ++nUpgraded;
             pindex = pindex->pprev;
```
_method CheckBlock_
```diff
         return false;
     }

+    // VeriBlock: merkle root verification currently depends on a context, so it has been moved to ContextualCheckBlock
+    if(block.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT && block.popData.empty()) {
+        return state.DoS(100, false, REJECT_INVALID, "bad-block-pop-version", false, "POP bit is set, but pop data is empty");
+    }
+    if(!(block.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) && !block.popData.empty()) {
+        return state.DoS(100, false, REJECT_INVALID, "bad-block-pop-version", false, "POP bit is NOT set, and pop data is NOT empty");
+    }
+
     // Check the merkle root.
     if (fCheckMerkleRoot) {
         bool mutated;
```

### Also should update the mining function to setup POP_BLOCK_VERSION_BIT if VeriBlock PopData is contained in the block.
[<font style="color: red"> src/miner.cpp </font>]  
_method BlockAssembler::CreateNewBlockWithScriptPubKey_
```diff
     int nDescendantsUpdated = 0;
     addPackageTxs(nPackagesSelected, nDescendantsUpdated);

+    // VeriBlock: add PopData into the block
+    if (!pblock->popData.atvs.empty() || !pblock->popData.context.empty() || !pblock->popData.vtbs.empty()) {
+        pblock->nVersion |= VeriBlock::POP_BLOCK_VERSION_BIT;
+    }
+
     nLastBlockTx = nBlockTx;
     nLastBlockWeight = nBlockWeight;
```
_method BlockAssembler::CreateNewBlock_
```diff
     int nDescendantsUpdated = 0;
     addPackageTxs(nPackagesSelected, nDescendantsUpdated);

+    // VeriBlock: add PopData into the block
+    if (!pblock->popData.atvs.empty() || !pblock->popData.context.empty() || !pblock->popData.vtbs.empty()) {
+        pblock->nVersion |= VeriBlock::POP_BLOCK_VERSION_BIT;
+    }
+
     nLastBlockTx = nBlockTx;
     nLastBlockWeight = nBlockWeight;
```

### Overload serialization operations for the VeriBlock PopData and other VeriBlock entities.
[<font style="color: red"> src/serialize.h </font>]  
```diff
 #include <prevector.h>
 #include <span.h>

+#include "veriblock/serde.hpp"
+#include "veriblock/entities/popdata.hpp"
+#include "veriblock/entities/btcblock.hpp"
+#include "veriblock/entities/altblock.hpp"
+#include "veriblock/blockchain/block_index.hpp"
+
 static const unsigned int MAX_SIZE = 0x02000000;
```
```diff
+// VeriBlock: Serialize a PopData object
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::PopData& pop_data) {
+    std::vector<uint8_t> bytes_data = pop_data.toVbkEncoding();
+    Serialize(s, bytes_data);
+}
+
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::PopData& pop_data) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    pop_data = altintegration::PopData::fromVbkEncoding(bytes_data);
+}
+
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::ATV& atv) {
+    std::vector<uint8_t> bytes_data = atv.toVbkEncoding();
+    Serialize(s, bytes_data);
+
+}
+
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::ATV& atv) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    atv = altintegration::ATV::fromVbkEncoding(bytes_data);
+}
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::VTB& vtb) {
+    std::vector<uint8_t> bytes_data = vtb.toVbkEncoding();
+    Serialize(s, bytes_data);
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::VTB& vtb) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    vtb = altintegration::VTB::fromVbkEncoding(bytes_data);
+}
+
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::BlockIndex<altintegration::BtcBlock>& b) {
+    std::vector<uint8_t> bytes_data = b.toRaw();
+    Serialize(s, bytes_data);
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::BlockIndex<altintegration::BtcBlock>& b) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    b = altintegration::BlockIndex<altintegration::BtcBlock>::fromRaw(bytes_data);
+}
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::BlockIndex<altintegration::VbkBlock>& b) {
+    std::vector<uint8_t> bytes_data = b.toRaw();
+    Serialize(s, bytes_data);
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::BlockIndex<altintegration::VbkBlock>& b) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    b = altintegration::BlockIndex<altintegration::VbkBlock>::fromRaw(bytes_data);
+}
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::BlockIndex<altintegration::AltBlock>& b) {
+    std::vector<uint8_t> bytes_data = b.toRaw();
+    Serialize(s, bytes_data);
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::BlockIndex<altintegration::AltBlock>& b) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    b = altintegration::BlockIndex<altintegration::AltBlock>::fromRaw(bytes_data);
+}
+template<typename Stream, size_t N> inline void Serialize(Stream& s, const altintegration::Blob<N>& b) {
+    Serialize(s, b.asVector());
+}
+template<typename Stream, size_t N> inline void Unserialize(Stream& s, altintegration::Blob<N>& b) {
+    std::vector<uint8_t> bytes;
+    Unserialize(s, bytes);
+    b = altintegration::Blob<N>(bytes);
+}

+template<typename Stream> inline void Serialize(Stream& s, const altintegration::VbkBlock& block) {
+    altintegration::WriteStream stream;
+    block.toVbkEncoding(stream);
+    Serialize(s, stream.data());
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::VbkBlock& block) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    altintegration::ReadStream stream(bytes_data);
+    block = altintegration::VbkBlock::fromVbkEncoding(stream);
+}
```

## Add PopSecurity fork point parameter.

For the already running blockchains, the only way to enable VeriBlock security is to made a fork.For this purpose we will provide a height of the fork point. Add into the Consensus::Params a block height from which PopSecurity is enabled.

[<font style="color: red"> src/consensus/params.h </font>]  
_struct Params_
```diff
     uint64_t X25XTIME;
     uint64_t DEACTIVATEDOLLAR;
     uint64_t DEACTIVATEPRICESERVERS;
+    // VeriBlock
+    uint64_t VeriBlockPopSecurityHeight;
 };
```

### Define VeriBlockPopSecurityHeight variable.
[<font style="color: red"> src/chainparams.cpp </font>]  
_class CMainParams_
```diff
+
+        // VeriBlock
+        // TODO: should determine the correct height
+        //consensus.VeriBlockPopSecurityHeight = -1;
+
+        // The best chain should have at least this much work.
         consensus.nMinimumChainWork = uint256S("0x00");
```
_class CTestNetParams_
```diff
+
+        // VeriBlock
+        // TODO: should determine the correct height
+        // consensus.VeriBlockPopSecurityHeight = -1;

         // The best chain should have at least this much work.
         consensus.nMinimumChainWork = uint256S("0x00");
```
_class CRegTestParams_
```diff
+
+        // VeriBlock
+        // TODO: should determine the correct height
+        // consensus.VeriBlockPopSecurityHeight = -1;

         // The best chain should have at least this much work.
         consensus.nMinimumChainWork = uint256S("0x00");
```

### Update validation for the block, if PoPSecurity is disabled, so POP_BLOCK_VERSION_BIT should not be set.
[<font style="color: red"> src/validation.cpp </font>]  
_method ContextualCheckBlockHeader_
```diff
+    // VeriBlock validation
+    if((block.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) && consensusParams.VeriBlockPopSecurityHeight > nHeight)
+    {
+        return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-pop-version(0x%08x)", block.nVersion),
+         strprintf("block contains PopData before PopSecurity has been enabled"));
+    }
+
     return true;
```

## Add VeriBlock config.

Before adding using and defining some objects from the VeriBlock library, we should define some VeriBlock specific parameters for library. For that we have to add new Config class which inherits from the altintegration::AltChainParams.
But first we will add functions that will wrap the interaction with the library. For that create two new source files pop_common.hpp, pop_common.cpp.

[<font style="color: red"> src/vbk/pop_common.hpp </font>]  
```diff
+// Copyright (c) 2019-2020 Xenios SEZC
+// https://www.veriblock.org
+// Distributed under the MIT software license, see the accompanying
+// file COPYING or http://www.opensource.org/licenses/mit-license.php.
+
+#ifndef BITCASH_SRC_VBK_POP_COMMON_HPP
+#define BITCASH_SRC_VBK_POP_COMMON_HPP
+
+#include <veriblock/pop_context.hpp>
+
+namespace VeriBlock {
+
+altintegration::PopContext& GetPop();
+
+void SetPopConfig(const altintegration::Config& config);
+
+void SetPop(std::shared_ptr<altintegration::PayloadsProvider>& db);
+
+std::string toPrettyString(const altintegration::PopContext& pop);
+
+} // namespace VeriBlock
+
+#endif // BITCASH_SRC_VBK_POP_COMMON_HPP
```

[<font style="color: red"> src/vbk/pop_common.cpp </font>]  
```diff
+// Copyright (c) 2019-2020 Xenios SEZC
+// https://www.veriblock.org
+// Distributed under the MIT software license, see the accompanying
+// file COPYING or http://www.opensource.org/licenses/mit-license.php.
+
+#include <vbk/pop_common.hpp>
+
+namespace VeriBlock {
+
+static std::shared_ptr<altintegration::PopContext> app = nullptr;
+static std::shared_ptr<altintegration::Config> config = nullptr;
+
+altintegration::PopContext& GetPop()
+{
+    assert(app && "Altintegration is not initialized. Invoke SetPop.");
+    return *app;
+}
+
+void SetPopConfig(const altintegration::Config& newConfig)
+{
+    config = std::make_shared<altintegration::Config>(newConfig);
+}
+
+void SetPop(std::shared_ptr<altintegration::PayloadsProvider>& db)
+{
+    assert(config && "Config is not initialized. Invoke SetPopConfig");
+    app = altintegration::PopContext::create(config, db);
+}
+
+std::string toPrettyString(const altintegration::PopContext& pop)
+{
+    return pop.altTree->toPrettyString();
+}
+
+} // namespace VeriBlock
```