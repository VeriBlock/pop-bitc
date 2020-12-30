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
[<font style="color: red"> src/primitives/block.h </font>]
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
```
_class CBlock_
```diff
     // memory only
     mutable bool fChecked;
     inline void SerializationOp(Stream& s, Operation ser_action) {
         READWRITEAS(CBlockHeader, *this);
         READWRITE(vtx);
+        if (this->nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+            READWRITE(popData);
+        }
     }

     void SetNull()
     {
         CBlockHeader::SetNull();
         vtx.clear();
+        popData.context.clear();
+        popData.vtbs.clear();
+        popData.atvs.clear();
         fChecked = false;
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
_method CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs_
```diff
         const CTransaction& tx = *block.vtx[i];
         shorttxids[i - 1] = GetShortID(fUseWTXID ? tx.GetWitnessHash() : tx.GetHash());
     }
+    // VeriBlock
+    this->popData = block.popData;
```  
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
_method PartiallyDownloadedBlock::FillBlock_
```diff
-    LogPrint(BCLog::CMPCTBLOCK, "Successfully reconstructed block %s with %lu txn prefilled, %lu txn from mempool (incl at least %lu from extra pool) and %lu txn requested\n", hash.ToString(), prefilled_count, mempool_count, extra_count, vtx_missing.size());
+    LogPrint(BCLog::CMPCTBLOCK, "Successfully reconstructed block %s with %lu txn prefilled, %lu txn from mempool (incl at least %lu from extra pool) and %lu txn requested, and %d VBK %d VTB %d ATV\n", hash.ToString(), prefilled_count, mempool_count, extra_count, vtx_missing.size(), this->popData.context.size(), this->popData.vtbs.size(), this->popData.atvs.size());
     if (vtx_missing.size() < 5) {
         for (const auto& tx : vtx_missing) {
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
     int nSendFlags = State(pfrom->GetId())->fWantsCmpctWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS;
+    // VeriBlock: add popData
+    resp.popData = block.popData;
     connman->PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::BLOCKTXN, resp));
```
_method ProcessMessage_
```diff
                     BlockTransactions txn;
                     txn.blockhash = cmpctblock.header.GetHash();
+                    txn.popData = cmpctblock.popData;
                     blockTxnMsg << txn;
                     fProcessBLOCKTXN = true;
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
             PartiallyDownloadedBlock& partialBlock = *it->second.second->partialBlock;
-            ReadStatus status = partialBlock.FillBlock(*pblock, resp.txn);
+            ReadStatus status = partialBlock.FillBlock(*pblock, resp.txn, resp.popData);
             if (status == READ_STATUS_INVALID) {
                 MarkBlockAsReceived(resp.blockhash); // Reset in-flight state in case of whitelist
```
_method ProcessMessage_
```diff
             vRecv >> headers[n];
             ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
+            if (headers[n].nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+                altintegration::PopData tmp;
+                vRecv >> tmp;
+            }
         }
```

Next step is to update validation rules, add check that if block contains VeriBlock PopData, then block.nVersion must contain POP_BLOCK_VERSION_BIT. Otherwise block.nVersion should not contain POP_BLOCK_VERSION_BIT. 

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
+    if(!pblock->popData.empty()) {
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
+    if(!pblock->popData.empty()) {
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
     a.Unserialize(is);
 }

+// VeriBlock: Serialize a PopData object
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::PopData& pop_data) {
+    std::vector<uint8_t> bytes_data = pop_data.toVbkEncoding();
+    Serialize(s, bytes_data);
+}
+
+template <typename T>
+void UnserializeOrThrow(const std::vector<uint8_t>& in, T& out) {
+    altintegration::ValidationState state;
+    altintegration::ReadStream stream(in);
+    if(!altintegration::DeserializeFromVbkEncoding(stream, out, state)) {
+        throw std::invalid_argument(state.toString());
+    }
+}
+
+template <typename T>
+void UnserializeOrThrow(const std::vector<uint8_t>& in, T& out, typename T::hash_t precalculatedHash) {
+    altintegration::ValidationState state;
+    altintegration::ReadStream stream(in);
+    if(!altintegration::DeserializeFromVbkEncoding(stream, out, state, precalculatedHash)) {
+        throw std::invalid_argument(state.toString());
+    }
+}
+
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::PopData& pop_data) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    UnserializeOrThrow(bytes_data, pop_data);
+}

+template<typename Stream> inline void Serialize(Stream& s, const altintegration::ATV& atv) {
+    std::vector<uint8_t> bytes_data = atv.toVbkEncoding();
+    Serialize(s, bytes_data);
+}

+template<typename Stream> inline void Unserialize(Stream& s, altintegration::ATV& atv) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    UnserializeOrThrow(bytes_data, atv);
+}
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::VTB& vtb) {
+    std::vector<uint8_t> bytes_data = vtb.toVbkEncoding();
+    Serialize(s, bytes_data);
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::VTB& vtb) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    UnserializeOrThrow(bytes_data, vtb);
+}

+template<typename Stream> inline void Serialize(Stream& s, const altintegration::BlockIndex<altintegration::BtcBlock>& b) {
+    std::vector<uint8_t> bytes_data = b.toVbkEncoding();
+    Serialize(s, bytes_data);
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::BlockIndex<altintegration::BtcBlock>& b) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    UnserializeOrThrow(bytes_data, b);
+}
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::BlockIndex<altintegration::VbkBlock>& b) {
+    std::vector<uint8_t> bytes_data = b.toVbkEncoding();
+    Serialize(s, bytes_data);
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::BlockIndex<altintegration::VbkBlock>& b) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    UnserializeOrThrow(bytes_data, b);
+}
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::BlockIndex<altintegration::AltBlock>& b) {
+    std::vector<uint8_t> bytes_data = b.toVbkEncoding();
+    Serialize(s, bytes_data);
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::BlockIndex<altintegration::AltBlock>& b) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    UnserializeOrThrow(bytes_data, b);
+}
+template<typename Stream, size_t N> inline void Serialize(Stream& s, const altintegration::Blob<N>& b) {
+    Serialize(s, b.asVector());
+}
+template<typename Stream, size_t N> inline void Unserialize(Stream& s, altintegration::Blob<N>& b) {
+    std::vector<uint8_t> bytes;
+    Unserialize(s, bytes);
+    if(bytes.size() > N) {
+        throw std::invalid_argument("Blob: bad size. Expected <= " + std::to_string(N) + ", got=" + std::to_string(bytes.size()));
+    }
+    b = bytes;
+}
+
+template<typename Stream> inline void Serialize(Stream& s, const altintegration::VbkBlock& block) {
+    altintegration::WriteStream stream;
+    block.toVbkEncoding(stream);
+    Serialize(s, stream.data());
+}
+template<typename Stream> inline void Unserialize(Stream& s, altintegration::VbkBlock& block) {
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    UnserializeOrThrow(bytes_data, block);
+}
+
+template <typename Stream>
+inline void UnserializeWithHash(Stream& s, altintegration::BlockIndex<altintegration::VbkBlock>& block, const altintegration::VbkBlock::hash_t& precalculatedHash = altintegration::VbkBlock::hash_t())
+{
+    std::vector<uint8_t> bytes_data;
+    Unserialize(s, bytes_data);
+    UnserializeOrThrow(bytes_data, block, precalculatedHash);
+}
```

## Add PopSecurity fork point parameter.

For the already running blockchains, the only way to enable VeriBlock security is to made a fork. For this reason we will provide a height of the fork point. Add into the Consensus::Params a block height from which PopSecurity is enabled.

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

## Add the initial configuration of the VeriBlock and Bitcoin blockchains.

### Add bootstraps blocks. Create AltChainParamsBITC class with the VeriBlock configuration of the Bitcash blockchain.

[<font style="color: red"> src/vbk/bootstraps.hpp </font>]
```diff
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
```

[<font style="color: red"> src/vbk/bootstraps.cpp </font>]
```diff
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/algorithm/string.hpp>
#include <chainparams.h>
#include <vbk/bootstraps.hpp>
#include <vbk/util.hpp>
#include <vbk/pop_common.hpp>

namespace VeriBlock {

std::vector<uint8_t> AltChainParamsVBitCash::getHash(const std::vector<uint8_t>& bytes) const noexcept
{
    uint256 hash = headerFromBytes(bytes).GetHash();
    return hash.asVector();
}

static std::vector<std::string> parseBlocks(const std::string& s)
{
    std::vector<std::string> strs;
    boost::split(strs, s, boost::is_any_of(","));
    return strs;
}

void printConfig(const altintegration::Config& config)
{
    std::string btclast = config.btc.blocks.empty() ? "<empty>" : config.btc.blocks.rbegin()->getHash().toHex();
    std::string btcfirst = config.btc.blocks.empty() ? "<empty>" : config.btc.blocks.begin()->getHash().toHex();
    std::string vbklast = config.vbk.blocks.empty() ? "<empty>" : config.vbk.blocks.rbegin()->getHash().toHex();
    std::string vbkfirst = config.vbk.blocks.empty() ? "<empty>" : config.vbk.blocks.begin()->getHash().toHex();


    assert(config.alt);

    LogPrintf(R"(Applied POP config:
 BTC:
  network     : %s
  startHeight : %d
  total blocks: %d
  first       : %s
  last        : %s

 VBK:
  network     : %s
  startHeight : %d
  total blocks: %d
  first       : %s
  last        : %s

 ALT:
  network     : %s
  block height: %d
  block hash  : %s
  chain id    : %lld
)",
        config.btc.params->networkName(), config.btc.startHeight, config.btc.blocks.size(), btcfirst, btclast,

        config.vbk.params->networkName(), config.vbk.startHeight, config.vbk.blocks.size(), vbkfirst, vbklast,

        Params().NetworkIDString(), config.alt->getBootstrapBlock().height,
        altintegration::HexStr(config.alt->getBootstrapBlock().hash),
        config.alt->getIdentifier());
}

void selectPopConfig(
    const std::string& btcnet,
    const std::string& vbknet,
    bool popautoconfig,
    int btcstart,
    const std::string& btcblocks,
    int vbkstart,
    const std::string& vbkblocks)
{
    altintegration::Config popconfig;

    //! SET BTC
    if (btcnet == "test") {
        auto param = std::make_shared<altintegration::BtcChainParamsTest>();
        if (popautoconfig) {
            popconfig.setBTC(testnetBTCstartHeight, testnetBTCblocks, param);
        } else {
            popconfig.setBTC(btcstart, parseBlocks(btcblocks), param);
        }
    } else if (btcnet == "regtest") {
        auto param = std::make_shared<altintegration::BtcChainParamsRegTest>();
        if (popautoconfig) {
            popconfig.setBTC(0, {}, param);
        } else {
            popconfig.setBTC(btcstart, parseBlocks(btcblocks), param);
        }
    } else {
        throw std::invalid_argument("btcnet currently only supports test/regtest");
    }

    //! SET VBK
    if (vbknet == "test") {
        auto param = std::make_shared<altintegration::VbkChainParamsTest>();
        if (popautoconfig) {
            popconfig.setVBK(testnetVBKstartHeight, testnetVBKblocks, param);
        } else {
            popconfig.setVBK(vbkstart, parseBlocks(vbkblocks), param);
        }
    } else if (btcnet == "regtest") {
        auto param = std::make_shared<altintegration::VbkChainParamsRegTest>();
        if (popautoconfig) {
            popconfig.setVBK(0, {}, param);
        } else {
            popconfig.setVBK(vbkstart, parseBlocks(vbkblocks), param);
        }
    } else {
        throw std::invalid_argument("vbknet currently only supports test/regtest");
    }

    auto altparams = std::make_shared<AltChainParamsVBitCash>(Params().GenesisBlock());
    popconfig.alt = altparams;
    VeriBlock::SetPopConfig(popconfig);
    printConfig(popconfig);
}

void selectPopConfig(const ArgsManager& args)
{
    std::string btcnet = args.GetArg("-popbtcnetwork", "regtest");
    std::string vbknet = args.GetArg("-popvbknetwork", "regtest");
    bool popautoconfig = args.GetBoolArg("-popautoconfig", true);
    int btcstart = args.GetArg("-popbtcstartheight", 0);
    std::string btcblocks = args.GetArg("-popbtcblocks", "");
    int vbkstart = args.GetArg("-popvbkstartheight", 0);
    std::string vbkblocks = args.GetArg("-popvbkblocks", "");

    selectPopConfig(btcnet, vbknet, popautoconfig, btcstart, btcblocks, vbkstart, vbkblocks);
}

const int testnetVBKstartHeight=860529;
const int testnetBTCstartHeight=1832624;

const std::vector<std::string> testnetBTCblocks = {};

const std::vector<std::string> testnetVBKblocks = {};

} // namespace VeriBlock
```

### Create an util.hpp file with some useful functions for the VeriBlock integration.

[<font style="color: red"> src/vbk/util.hpp </font>]
```diff
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITC_SRC_VBK_UTIL_HPP
#define BITC_SRC_VBK_UTIL_HPP

#include <consensus/consensus.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <version.h>

#include <veriblock/entities/popdata.hpp>

#include <algorithm>
#include <amount.h>
#include <chain.h>
#include <functional>

namespace VeriBlock {

/**
 * Create new Container with elements filtered elements of original container. All elements for which pred returns false will be removed.
 * @tparam Container any container, such as std::vector
 * @param v instance of container to be filtered
 * @param pred predicate. Returns true for elements that need to stay in container.
 */
template <typename Container>
Container filter_if(const Container& inp, std::function<bool(const typename Container::value_type&)> pred)
{
    Container v = inp;
    v.erase(std::remove_if(
                v.begin(), v.end(), [&](const typename Container::value_type& t) {
                    return !pred(t);
                }),
        v.end());
    return v;
}

inline CBlockHeader headerFromBytes(const std::vector<uint8_t>& v)
{
    CDataStream stream(v, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader header;
    stream >> header;
    return header;
}

inline altintegration::AltBlock blockToAltBlock(int nHeight, const CBlockHeader& block)
{
    altintegration::AltBlock alt;
    alt.height = nHeight;
    alt.timestamp = block.nTime;
    alt.previousBlock = std::vector<uint8_t>(block.hashPrevBlock.begin(), block.hashPrevBlock.end());
    auto hash = block.GetHash();
    alt.hash = std::vector<uint8_t>(hash.begin(), hash.end());
    return alt;
}

inline altintegration::AltBlock blockToAltBlock(const CBlockIndex& index)
{
    return blockToAltBlock(index.nHeight, index.GetBlockHeader());
}

template <typename T>
bool FindPayloadInBlock(const CBlock& block, const typename T::id_t& id, T& out)
{
    (void)block;
    (void)id;
    (void)out;
    static_assert(sizeof(T) == 0, "Undefined type in FindPayloadInBlock");
    return false;
}

template <>
inline bool FindPayloadInBlock(const CBlock& block, const altintegration::VbkBlock::id_t& id, altintegration::VbkBlock& out)
{
    for (auto& blk : block.popData.context) {
        if (blk.getShortHash() == id) {
            out = blk;
            return true;
        }
    }

    return false;
}

template <>
inline bool FindPayloadInBlock(const CBlock& block, const altintegration::VTB::id_t& id, altintegration::VTB& out)
{
    for (auto& vtb : block.popData.vtbs) {
        if (vtb.getId() == id) {
            out = vtb;
            return true;
        }
    }

    return false;
}

template <>
inline bool FindPayloadInBlock(const CBlock& block, const altintegration::ATV::id_t& id, altintegration::ATV& out)
{
    for (auto& atv : block.popData.atvs) {
        if (atv.getId() == id) {
            out = atv;
            return true;
        }
    }
    return false;
}

inline std::vector<uint8_t> uintToVector(const uint256& from)
{
    return std::vector<uint8_t>{from.begin(), from.end()};
}

} // namespace VeriBlock
#endif //BITC_SRC_VBK_UTIL_HPP
```

## Now update the initializatio of the bitcashd, bitcash-wallet, etc to setup VeriBlock config.

[<font style="color: red"> src/bitcashd.cpp </font>]
```diff
 #include <utilstrencodings.h>
 #include <walletinitinterface.h>
+#include <vbk/bootstraps.hpp>

 #include <boost/thread.hpp>
```
_method AppInit_
```diff
         try {
             SelectParams(gArgs.GetChainName());
+            // VeriBlock
+            VeriBlock::selectPopConfig(gArgs);
         } catch (const std::exception& e) {
```

[<font style="color: red"> src/bitcash-tx.cpp </font>]
```diff
 #include <utilmoneystr.h>
 #include <utilstrencodings.h>
+#include <vbk/bootstraps.hpp>

 #include <memory>
```
_method AppInitRawTx_
```diff
     try {
         SelectParams(gArgs.GetChainName());
+        // VeriBlock
+        VeriBlock::selectPopConfig(gArgs);
     } catch (const std::exception& e) {
```

[<font style="color: red"> src/interfaces/node.cpp </font>]
```diff
     bool softSetBoolArg(const std::string& arg, bool value) override { return gArgs.SoftSetBoolArg(arg, value); }
-    void selectParams(const std::string& network) override { SelectParams(network); }
+    void selectParams(const std::string& network) override
+    {
+        SelectParams(network);
+        VeriBlock::selectPopConfig(gArgs);
+    }

[<font style="color: red"> src/test/test_bitcash.cpp </font>]
```diff
 #include <rpc/register.h>
 #include <script/sigcache.h>
+#include <vbk/bootstraps.hpp>
```
_method AddNode_
```diff
         fCheckBlockIndex = true;
         SelectParams(chainName);
+        // VeriBlock
+        VeriBlock::selectPopConfig("regtest", "regtest", true);
         noui_connect();
```
_method CreateAndProcessBlock_
```diff
     const CChainParams& chainparams = Params();
-    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
+    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlockWithScriptPubKey(scriptPubKey, false);
     CBlock& block = pblocktemplate->block;
```

### The last step is to update makefiles. Add our new source files.

[<font style="color: red"> src/Makefile.am </font>]
```diff
 libbitcash_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
 libbitcash_common_a_SOURCES = \
+  vbk/pop_common.hpp \
+  vbk/pop_common.cpp \
+  vbk/bootstraps.cpp \
   base58.cpp \
   bech32.cpp \
   chainparams.cpp \
```