# BitCash POP integration write-up

## BitCash clone
```sh
git clone https://github.com/WillyTheCat/BitCash.git
```
## BitCash dependencies
See [https://github.com/WillyTheCat/BitCash/tree/master/doc]

### BitCash dependencies Ubuntu example
```sh
sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils python3
```
```sh
sudo apt-get install libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev
```
```sh
sudo apt-get install libdb-dev libdb++-dev libcurl4-openssl-dev
```
```sh
sudo apt-get install libminiupnpc-dev
```
```sh
sudo apt-get install libzmq3-dev
```

## BitCash build
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
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_PYPOPTOOLS=ON
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

## Add PopData to the Block class
We should add new PopData entity into the CBlock class in the block.h file and provide new nVersion flag. It is needed for storing VeriBlock specific information such as ATVs, VTBs, VBKs.
First we will add new POP_BLOCK_VERSION_BIT flag, that will help to distinguish original blocks that don't have any VeriBlock specific data, and blocks that contain such data.
Next, update serialization of the block, that will serialize/deserialize PopData if POP_BLOCK_VERSION_BIT is set. Finally extend serialization/deserialization for the PopData, so we can use the BitCash native serialization/deserialization.

### Helper for the block hash serialization
[<font style="color: red"> src/uint256.hpp </font>]

_class base_blob_
```diff
     {
         s.read((char*)data, sizeof(data));
     }
+
+    std::vector<uint8_t> asVector() const {
+        return std::vector<uint8_t>{begin(), end()};
+    }
 };
```

### Define POP_BLOCK_VERSION_BIT flag.
[<font style="color: red"> src/vbk/vbk.hpp </font>]
```
#ifndef BITCASH_SRC_VBK_VBK_HPP
#define BITCASH_SRC_VBK_VBK_HPP

#include <uint256.h>

namespace VeriBlock {

using KeystoneArray = std::array<uint256, 2>;

const static int32_t POP_BLOCK_VERSION_BIT = 0x80000UL;

}  // namespace VeriBlock

#endif //BITCASH_SRC_VBK_VBK_HPP
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
```diff
                 status = tempBlock.FillBlock(*pblock, dummy);
                 if (status == READ_STATUS_OK) {
                     fBlockReconstructed = true;
+                    // VeriBlock: check for empty popData
+                    if(pblock && pblock->nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+                        assert(!pblock->popData.empty() && "POP bit is set and POP data is empty");
+                    }
                 }
             }
```
```diff
             PartiallyDownloadedBlock& partialBlock = *it->second.second->partialBlock;
-            ReadStatus status = partialBlock.FillBlock(*pblock, resp.txn);
+            ReadStatus status = partialBlock.FillBlock(*pblock, resp.txn, resp.popData);
             if (status == READ_STATUS_INVALID) {
                 MarkBlockAsReceived(resp.blockhash); // Reset in-flight state in case of whitelist
```
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
+        consensus.VeriBlockPopSecurityHeight = -1;
+
+        // The best chain should have at least this much work.
         consensus.nMinimumChainWork = uint256S("0x00");
```
_class CTestNetParams_
```diff
+
+        // VeriBlock
+        // TODO: should determine the correct height
+        consensus.VeriBlockPopSecurityHeight = -1;

         // The best chain should have at least this much work.
         consensus.nMinimumChainWork = uint256S("0x00");
```
_class CRegTestParams_
```diff
+
+        // VeriBlock
+        // TODO: should determine the correct height
+        consensus.VeriBlockPopSecurityHeight = -1;

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

Before using objects from the VeriBlock library, we should define some VeriBlock specific parameters for the library. We have to add new Config class which inherits from the altintegration::AltChainParams.
But first we will add functions that wrap interaction with the library. Create two new source files: pop_common.hpp, pop_common.cpp.

[<font style="color: red"> src/vbk/pop_common.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_POP_COMMON_HPP
#define BITCASH_SRC_VBK_POP_COMMON_HPP

#include <uint256.h>
#include <veriblock/pop_context.hpp>

namespace VeriBlock {

altintegration::PopContext& GetPop();

void StopPop();

void SetPopConfig(const altintegration::Config& config);

void SetPop(std::shared_ptr<altintegration::PayloadsStorage> payloads_provider);

altintegration::BlockIndex<altintegration::AltBlock>* GetAltBlockIndex(const uint256& hash);
altintegration::BlockIndex<altintegration::AltBlock>* GetAltBlockIndex(const CBlockIndex* index);

std::string toPrettyString(const altintegration::PopContext& pop);

} // namespace VeriBlock

#endif // BITCASH_SRC_VBK_POP_COMMON_HPP
```
[<font style="color: red"> src/vbk/pop_common.cpp </font>]
```
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

void SetPop(std::shared_ptr<altintegration::PayloadsStorage> db)
{
    assert(config && "Config is not initialized. Invoke SetPopConfig.");
    app = altintegration::PopContext::create(config, db);
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
```

## Add the initial configuration of the VeriBlock and Bitcoin blockchains.

### Add bootstraps blocks. Create AltChainParamsBITC class with the VeriBlock configuration of the BitCash blockchain.

[<font style="color: red"> src/vbk/bootstraps.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __BOOTSTRAPS_BITC_VBK
#define __BOOTSTRAPS_BITC_VBK

#include <string>
#include <vector>

namespace VeriBlock {

extern const int testnetVBKstartHeight;
extern const std::vector<std::string> testnetVBKblocks;

extern const int testnetBTCstartHeight;
extern const std::vector<std::string> testnetBTCblocks;

#endif //__BOOTSTRAPS_BITC_VBK
```

[<font style="color: red"> src/vbk/bootstraps.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <vbk/bootstraps.hpp>

namespace VeriBlock {

const int testnetVBKstartHeight=860529;
const int testnetBTCstartHeight=1832624;

const std::vector<std::string> testnetBTCblocks = {};

const std::vector<std::string> testnetVBKblocks = {};

} // namespace VeriBlock
```
[<font style="color: red"> src/vbk/params.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef INTEGRATION_REFERENCE_BITC_PARAMS_HPP
#define INTEGRATION_REFERENCE_BITC_PARAMS_HPP

#include <primitives/block.h>
#include <util.h>
#include <veriblock/blockchain/alt_chain_params.hpp>
#include <veriblock/config.hpp>

class ArgsManager;

namespace VeriBlock {

struct AltChainParamsBITC : public altintegration::AltChainParams {
    ~AltChainParamsBITC() override = default;

    AltChainParamsBITC(const CBlock& genesis)
    {
        bootstrap.hash = genesis.GetHash().asVector();
        // intentionally leave prevHash empty
        bootstrap.height = 0;
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

    // we should verify:
    // - check that 'bytes' can be deserialized to a CBlockHeader
    // - check that this CBlockHeader is valid (time, pow, version...)
    // - check that 'root' is equal to Merkle Root in CBlockHeader
    bool checkBlockHeader(
        const std::vector<uint8_t>& bytes,
        const std::vector<uint8_t>& root) const noexcept override;

    altintegration::AltBlock bootstrap;
};

void printConfig(const altintegration::Config& config);
void selectPopConfig(const ArgsManager& mgr, std::string vbk = "test", std::string btc = "test");
void selectPopConfig(
    const std::string& btcnet,
    const std::string& vbknet,
    bool popautoconfig = true,
    int btcstart = 0,
    const std::string& btcblocks = {},
    int vbkstart = 0,
    const std::string& vbkblocks = {});

} // namespace VeriBlock

#endif //INTEGRATION_REFERENCE_BITC_PARAMS_HPP
```
[<font style="color: red"> src/vbk/params.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include "params.hpp"
#include "util.hpp"
#include <boost/algorithm/string.hpp>
#include <chainparams.h>
#include <logging.h>
#include <pow.h>
#include "cuckoo/miner.h"
#include <vbk/bootstraps.hpp>
#include <vbk/pop_common.hpp>
#include <veriblock/bootstraps.hpp>

namespace VeriBlock {

bool AltChainParamsBITC::checkBlockHeader(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& root
{
    const CChainParams& params = Params();

    try {
        // this throws
        auto header = VeriBlock::headerFromBytes(bytes);
        if (isX16Ractive(header.nVersion)) {
            if (!CheckProofOfWork(header.GetHash(), header.nBits, params.GetConsensus()))
                return false;
        } else {
            if (!cuckoo::VerifyProofOfWork(header.GetHash(), header.nBits, header.nEdgeBits, header.sCycle, p
                return false;
        }
        return
            /* top level merkle `root` calculated by library is same as in endorsed header */
            header.hashMerkleRoot.asVector() == root;
    } catch (...) {
        return false;
    }
}

std::vector<uint8_t> AltChainParamsBITC::getHash(const std::vector<uint8_t>& bytes) const noexcept
{
    try {
        return VeriBlock::headerFromBytes(bytes).GetHash().asVector();
    } catch (...) {
        // return empty hash, since we can't deserialize header
        return {};
    }
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

    auto altparams = std::make_shared<VeriBlock::AltChainParamsBITC>(Params().GenesisBlock());
    popconfig.alt = altparams;
    VeriBlock::SetPopConfig(popconfig);
    printConfig(popconfig);
}

void selectPopConfig(const ArgsManager& args, std::string vbk, std::string btc)
{
    std::string btcnet = args.GetArg("-popbtcnetwork", btc);
    std::string vbknet = args.GetArg("-popvbknetwork", vbk);
    int popautoconfig = args.GetArg("-popautoconfig", 1);
    int btcstart = args.GetArg("-popbtcstartheight", 0);
    std::string btcblocks = args.GetArg("-popbtcblocks", "");
    int vbkstart = args.GetArg("-popvbkstartheight", 0);
    std::string vbkblocks = args.GetArg("-popvbkblocks", "");

    selectPopConfig(btcnet, vbknet, (bool)popautoconfig, btcstart, btcblocks, vbkstart, vbkblocks);
}

} // namespace VeriBlock
```

### Create an util.hpp file with some useful functions for the VeriBlock integration.

[<font style="color: red"> src/vbk/util.hpp </font>]
```
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

## Now update the initialization of the bitcashd, bitcash-wallet, etc to setup VeriBlock config.

[<font style="color: red"> src/bitcashd.cpp </font>]
```diff
 #include <utilstrencodings.h>
 #include <walletinitinterface.h>
+#include <vbk/params.hpp>

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
+#include <vbk/params.hpp>

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
 #include <boost/thread/thread.hpp>
 #include <univalue.h>
+#include <vbk/params.hpp>

 namespace interfaces {
```
```diff
     bool softSetBoolArg(const std::string& arg, bool value) override { return gArgs.SoftSetBoolArg(arg, value); }
-    void selectParams(const std::string& network) override { SelectParams(network); }
+    void selectParams(const std::string& network) override
+    {
+        SelectParams(network);
+        VeriBlock::selectPopConfig(gArgs);
+    }
```
[<font style="color: red"> src/test/test_bitcash.h </font>]
```diff
     // Create a new block with just given transactions, coinbase paying to
     // scriptPubKey, and try to add it to the current chain.
     CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
-                                 const CScript& scriptPubKey);
+                                 const CScript& scriptPubKey, bool* isBlockValid = nullptr);
+
+    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, uint256 prevBlock,
+                                 const CScript& scriptPubKey, bool* isBlockValid = nullptr);

     ~TestChain100Setup();

```
[<font style="color: red"> src/test/test_bitcash.cpp </font>]
```diff
 #include <rpc/server.h>
 #include <rpc/register.h>
 #include <script/sigcache.h>
+#include <vbk/params.hpp>

 void CConnmanTest::AddNode(CNode& node)
```
```diff
 CBlock
-TestChain100Setup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey)
+TestChain100Setup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, uint256 prevBlock,
+                             const CScript& scriptPubKey, bool* isBlockValid)
 {
+    CBlockIndex* pPrev = nullptr;
+    {
+        LOCK(cs_main);
+        pPrev = LookupBlockIndex(prevBlock);
+        assert(pPrev && "CreateAndProcessBlock called with unknown prev block");
+    }
+
     const CChainParams& chainparams = Params();
-    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
+    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlockWithScriptPubKey(scriptPubKey, false);
     CBlock& block = pblocktemplate->block;
```
_method TestChain100Setup::CreateAndProcessBlock_
```diff
     {
         LOCK(cs_main);
         unsigned int extraNonce = 0;
-        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
+        IncrementExtraNonce(&block, pPrev, extraNonce);
     }
-
     while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())) ++block.nNonce;

     std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
-    ProcessNewBlock(chainparams, shared_pblock, true, nullptr, true);
+    bool isValid = ProcessNewBlock(chainparams, shared_pblock, true, nullptr, true);
+    if(isBlockValid != nullptr) {
+        *isBlockValid = isValid;
+    }

     CBlock result = block;
     return result;
```
```diff
+// Create a new block with just given transactions, coinbase paying to
+// scriptPubKey, and try to add it to the current chain.
+CBlock TestChain100Setup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey, bool* isBlockValid)
+{
+    return CreateAndProcessBlock(txns, chainActive.Tip()->GetBlockHash(), scriptPubKey, isBlockValid);
+}
+
 TestChain100Setup::~TestChain100Setup()
```

### The last step is to update makefiles. Add new source files.

[<font style="color: red"> src/Makefile.am </font>]
```diff
libbitcash_server_a_SOURCES = \
   policy/policy.cpp \
   policy/rbf.cpp \
   pow.cpp \
+  vbk/params.hpp \
+  vbk/params.cpp \
   rest.cpp \
   stratum.cpp \
```
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
```diff
 bitcash_tx_LDADD = \
   $(LIBUNIVALUE) \
   $(VERIBLOCK_POP_CPP_LIBS) \
+  $(LIBBITCASH_SERVER) \
   $(LIBBITCASH_COMMON) \
   $(LIBBITCASH_UTIL) \
```

## Update BitCash persistence to store VeriBlock related data.

### Add PayloadsProvider

We should add a PayloadsProvider for the VeriBlock library. The main idea of such class is that we reuse the existing BitCash database. Our library allows to use the native implementation of the database. We implement it with PayloadsProvider class which is inherited from the [altintegration::PayloadsProvider](https://veriblock-pop-cpp.netlify.app/structaltintegration_1_1payloadsprovider) class.
First step is to create new source files: payloads_provider.hpp, block_provider.hpp.

[<font style="color: red"> src/vbk/adaptors/payloads_provider.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef INTEGRATION_REFERENCE_BITC_PAYLOADS_PROVIDER_HPP
#define INTEGRATION_REFERENCE_BITC_PAYLOADS_PROVIDER_HPP

#include <dbwrapper.h>
#include <vbk/pop_common.hpp>
#include <veriblock/storage/payloads_provider.hpp>

namespace VeriBlock {

constexpr const char DB_VBK_PREFIX = '^';
constexpr const char DB_VTB_PREFIX = '<';
constexpr const char DB_ATV_PREFIX = '>';

struct PayloadsProvider : public altintegration::PayloadsStorage {
    using key_t = std::vector<uint8_t>;
    using value_t = std::vector<uint8_t>;

    ~PayloadsProvider() = default;

    PayloadsProvider(CDBWrapper& db) : db_(db) {}

    void writePayloads(const altintegration::PopData& payloads) override
    {
        auto batch = CDBBatch(db_);
        for (const auto& b : payloads.context) {
            batch.Write(std::make_pair(DB_VBK_PREFIX, b.getId()), b);
        }
        for (const auto& b : payloads.vtbs) {
            batch.Write(std::make_pair(DB_VTB_PREFIX, b.getId()), b);
        }
        for (const auto& b : payloads.atvs) {
            batch.Write(std::make_pair(DB_ATV_PREFIX, b.getId()), b);
        }
        bool ret = db_.WriteBatch(batch, true);
        VBK_ASSERT_MSG(ret, "payloads write batch failed");
        batch.Clear();
    }

    template <typename pop_t>
    bool getPayloads(char dbPrefix, const typename pop_t::id_t& id, pop_t& out, altintegration::ValidationState& state)
    {
        auto& mempool = *GetPop().mempool;
        const auto* memval = mempool.template get<pop_t>(id);
        if (memval != nullptr) {
            out = *memval;
        } else {
            if (!db_.Read(std::make_pair(dbPrefix, id), out)) {
                return state.Invalid(pop_t::name() + "-read-error");
            }
        }
        return true;
    }

    bool getATV(const altintegration::ATV::id_t& id, altintegration::ATV& out, altintegration::ValidationState& state) override
    {
        return getPayloads(DB_ATV_PREFIX, id, out, state);
    }

    bool getVTB(const altintegration::VTB::id_t& id, altintegration::VTB& out, altintegration::ValidationState& state) override
    {
        return getPayloads(DB_VTB_PREFIX, id, out, state);
    }

    bool getVBK(const altintegration::VbkBlock::id_t& id, altintegration::VbkBlock& out, altintegration::ValidationState& state) override
    {
        return getPayloads(DB_VBK_PREFIX, id, out, state);
    }

private:
    CDBWrapper& db_;
};

} // namespace VeriBlock

#endif //INTEGRATION_REFERENCE_BITC_PAYLOADS_PROVIDER_HPP
```
[<font style="color: red"> src/vbk/adaptors/block_provider.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef INTEGRATION_REFERENCE_BITC_BLOCK_PROVIDER_HPP
#define INTEGRATION_REFERENCE_BITC_BLOCK_PROVIDER_HPP

#include <dbwrapper.h>

#include <utility>

#include "veriblock/storage/block_batch.hpp"
#include "veriblock/storage/block_iterator.hpp"

namespace VeriBlock {

using altintegration::AltBlock;
using altintegration::BlockIndex;
using altintegration::BtcBlock;
using altintegration::VbkBlock;

constexpr const char DB_BTC_BLOCK = 'Q';
constexpr const char DB_BTC_TIP = 'q';
constexpr const char DB_VBK_BLOCK = 'W';
constexpr const char DB_VBK_TIP = 'w';
constexpr const char DB_ALT_BLOCK = 'E';
constexpr const char DB_ALT_TIP = 'e';

template <typename BlockT>
std::pair<char, std::string> tip_key();

template <>
inline std::pair<char, std::string> tip_key<VbkBlock>()
{
    return std::make_pair(DB_VBK_TIP, "vbktip");
}
template <>
inline std::pair<char, std::string> tip_key<BtcBlock>()
{
    return std::make_pair(DB_BTC_TIP, "btctip");
}
template <>
inline std::pair<char, std::string> tip_key<AltBlock>()
{
    return std::make_pair(DB_ALT_TIP, "alttip");
}

template <typename BlockT>
std::pair<char, typename BlockT::hash_t> block_key(const typename BlockT::hash_t& hash);


template <>
inline std::pair<char, typename BtcBlock::hash_t> block_key<BtcBlock>(const typename BtcBlock::hash_t& hash)
{
    return std::make_pair(DB_BTC_BLOCK, hash);
}

template <>
inline std::pair<char, typename VbkBlock::hash_t> block_key<VbkBlock>(const typename VbkBlock::hash_t& hash)
{
    return std::make_pair(DB_VBK_BLOCK, hash);
}

template <>
inline std::pair<char, typename AltBlock::hash_t> block_key<AltBlock>(const typename AltBlock::hash_t& hash)
{
    return std::make_pair(DB_ALT_BLOCK, hash);
}


template <typename BlockT>
struct BlockIterator : public altintegration::BlockIterator<BlockT> {
    using hash_t = typename BlockT::hash_t;

    ~BlockIterator() override = default;

    BlockIterator(std::shared_ptr<CDBIterator> iter) : iter_(std::move(iter)) {}

    void next() override
    {
        iter_->Next();
    }

    bool value(BlockIndex<BlockT>& out) const override
    {
        return iter_->GetValue(out);
    }

    bool key(hash_t& out) const override
    {
        std::pair<char, hash_t> key;
        if (!iter_->GetKey(key)) {
            return false;
        }
        out = key.second;
        return true;
    }

    bool valid() const override
    {
        static char prefix = block_key<BlockT>(hash_t()).first;

        std::pair<char, hash_t> key;
        return iter_->Valid() && iter_->GetKey(key) && key.first == prefix;
    }

    void seek_start() override
    {
        iter_->Seek(block_key<BlockT>(hash_t()));
    }

private:
    std::shared_ptr<CDBIterator> iter_;
};

struct BlockReader : public altintegration::BlockReader {
    ~BlockReader() override = default;

    BlockReader(CDBWrapper& db) : db(&db) {}

    bool getAltTip(AltBlock::hash_t& out) const override
    {
        return db->Read(tip_key<AltBlock>(), out);
    }
    bool getVbkTip(VbkBlock::hash_t& out) const override
    {
        return db->Read(tip_key<VbkBlock>(), out);
    }
    bool getBtcTip(BtcBlock::hash_t& out) const override
    {
        return db->Read(tip_key<BtcBlock>(), out);
    }

    std::shared_ptr<altintegration::BlockIterator<AltBlock>> getAltBlockIterator() const override
    {
        std::shared_ptr<CDBIterator> it(db->NewIterator());
        return std::make_shared<BlockIterator<AltBlock>>(it);
    }
    std::shared_ptr<altintegration::BlockIterator<VbkBlock>> getVbkBlockIterator() const override
    {
        std::shared_ptr<CDBIterator> it(db->NewIterator());
        return std::make_shared<BlockIterator<VbkBlock>>(it);
    }
    std::shared_ptr<altintegration::BlockIterator<BtcBlock>> getBtcBlockIterator() const override
    {
        std::shared_ptr<CDBIterator> it(db->NewIterator());
        return std::make_shared<BlockIterator<BtcBlock>>(it);
    }

private:
    CDBWrapper* db{nullptr};
};


struct BlockBatch : public altintegration::BlockBatch {
    ~BlockBatch() override = default;

    BlockBatch(CDBBatch& batch) : batch_(&batch) {}

    void writeBlock(const BlockIndex<AltBlock>& value) override
    {
        auto key = block_key<AltBlock>(value.getHash());
        batch_->Write(key, value);
    }

    void writeBlock(const BlockIndex<VbkBlock>& value) override
    {
        auto key = block_key<VbkBlock>(value.getHash());
        batch_->Write(key, value);
    }

    void writeBlock(const BlockIndex<BtcBlock>& value) override
    {
        auto key = block_key<BtcBlock>(value.getHash());
        batch_->Write(key, value);
    }

    void writeTip(const BlockIndex<AltBlock>& value) override
    {
        auto hash = value.getHash();
        batch_->Write(tip_key<AltBlock>(), hash);
    }

    void writeTip(const BlockIndex<VbkBlock>& value) override
    {
        auto hash = value.getHash();
        batch_->Write(tip_key<VbkBlock>(), hash);
    }

    void writeTip(const BlockIndex<BtcBlock>& value) override
    {
        auto hash = value.getHash();
        batch_->Write(tip_key<BtcBlock>(), hash);
    }

private:
    CDBBatch* batch_{nullptr};
};

} // namespace VeriBlock

#endif
```

### Create wrappers for such entities.

[<font style="color: red"> src/vbk/pop_service.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_POP_SERVICE_HPP
#define BITCASH_SRC_VBK_POP_SERVICE_HPP

#include <vbk/pop_common.hpp>
#include <vbk/util.hpp>

class CBlockTreeDB;
class CDBBatch;
class CDBIterator;
class CDBWrapper;

namespace VeriBlock {

void InitPopContext(CDBWrapper& db);

//! returns true if all tips are stored in database, false otherwise
bool hasPopData(CBlockTreeDB& db);
altintegration::PopData getPopData();
void saveTrees(CDBBatch* batch);
bool loadTrees(CDBWrapper& db);

} // namespace VeriBlock

#endif //BITCASH_SRC_VBK_POP_SERVICE_HPP
```

[<font style="color: red"> src/vbk/pop_service.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dbwrapper.h>
#include <init.h>
#include <txdb.h>
#include <validation.h>
#include <veriblock/storage/util.hpp>

#ifdef WIN32
#include <boost/thread/interruption.hpp>
#endif //WIN32

#include <vbk/adaptors/block_provider.hpp>
#include <vbk/adaptors/payloads_provider.hpp>
#include <vbk/pop_common.hpp>
#include <vbk/pop_service.hpp>

namespace VeriBlock {

void InitPopContext(CDBWrapper& db)
{
    auto payloads_provider = std::make_shared<PayloadsProvider>(db);
    SetPop(payloads_provider);
}

bool hasPopData(CBlockTreeDB& db)
{
    return db.Exists(tip_key<altintegration::BtcBlock>()) && db.Exists(tip_key<altintegration::VbkBlock>()) & db.Exists(tip_key<altintegration::AltBlock>());
}

void saveTrees(CDBBatch* batch)
{
    AssertLockHeld(cs_main);
    VeriBlock::BlockBatch b(*batch);
    altintegration::SaveAllTrees(*GetPop().altTree, b);
}
bool loadTrees(CDBWrapper& db)
{
    altintegration::ValidationState state;

    BlockReader reader(db);
    if (!altintegration::LoadAllTrees(GetPop(), reader, state)) {
        return error("%s: failed to load trees %s", __func__, state.toString());
    }

    return true;
}

} // namespace VeriBlock
```

### Now we have to init the VeriBlock storage during the BitCash initializion proccess.

[<font style="color: red"> src/init.cpp </font>]
```diff
 #include <zmq/zmqnotificationinterface.h>
 #endif

+#include <vbk/pop_service.hpp>
+
```
_method Shutdown_
```diff
     // CScheduler/checkqueue threadGroup
     threadGroup.interrupt_all();
     threadGroup.join_all();
+    VeriBlock::StopPop();

     if (g_is_mempool_loaded && gArgs.GetArg("-persistmempool", DEFAULT_PERSIST_MEMPOOL)) {
         DumpMempool();
```
_method AppInitMain_
```diff
                 // fails if it's still open from the previous loop. Close it first:
                 pblocktree.reset();
                 pblocktree.reset(new CBlockTreeDB(nBlockTreeDBCache, false, fReset));
+                // VeriBlock
+                VeriBlock::InitPopContext(*pblocktree);

                 if (fReset) {
                     pblocktree->WriteReindexing(true);
```
[<font style="color: red"> src/txdb.cpp </font>]
```diff
 #include <boost/thread.hpp>

+#include <vbk/pop_service.hpp>
+
 static const char DB_COIN = 'C';
 static const char DB_COINS = 'c';
```
_method  CBlockTreeDB::WriteBatchSync_
```diff
         batch.Write(std::make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), CDiskBlockIndex(*it));
     }
+
+    // VeribBlock: write BTC/VBK/ALT blocks
+    VeriBlock::saveTrees(&batch);
     return WriteBatch(batch, true);
```
[<font style="color: red"> src/validation.cpp </font>]
```diff
 #include <boost/algorithm/string/join.hpp>
 #include <boost/thread.hpp>

+#include <vbk/pop_service.hpp>
+
 #if defined(NDEBUG)
```
_method CChainState::LoadBlockIndex_
```diff
     if (!blocktree.LoadBlockIndexGuts(consensus_params, [this](const uint256& hash){ return this->InsertBlockIndex(hash); }))
         return false;

+    // VeriBlock
+    if(!VeriBlock::hasPopData(blocktree)) {
+        LogPrintf("BTC/VBK/ALT tips not found... skipping block index loading\n");
+        return true;
+    }
+
     boost::this_thread::interruption_point();
```
```diff
+    // VeriBlock
+    // get best chain from ALT tree and update vBTC`s best chain
+    {
+        AssertLockHeld(cs_main);
+
+        // load blocks
+        if(!VeriBlock::loadTrees(blocktree)) {
+            return false;
+        }
+
+        // ALT tree tip should be set - this is our last best tip
+        auto *tip = VeriBlock::GetPop().altTree->getBestChain().tip();
+        assert(tip && "we could not load tip of alt block");
+        uint256 hash(tip->getHash());
+
+        CBlockIndex* index = LookupBlockIndex(hash);
+        assert(index);
+        if(index->IsValid(BLOCK_VALID_TREE)) {
+            pindexBestHeader = index;
+        } else {
+            return false;
+        }
+    }
+
     return true;
```

### The last step is to update test constructor of the TestingSetup struct in the test_bitcash.cpp.

[<font style="color: red"> src/test/test_bitcash.cpp </font>]
```diff

 #include <script/sigcache.h>
+#include <vbk/pop_service.hpp>

```
_method BasicTestingSetup::BasicTestingSetup_
```diff
         fCheckBlockIndex = true;
         SelectParams(chainName);
+        // VeriBlock
+        VeriBlock::selectPopConfig("regtest", "regtest", true);
         noui_connect();
```
_method TestingSetup::TestingSetup_
```diff
         pblocktree.reset(new CBlockTreeDB(1 << 20, true));
+        // VeriBlock
+        VeriBlock::InitPopContext(*pblocktree);
+
         pcoinsdbview.reset(new CCoinsViewDB(1 << 23, true));
```
_method TestingSetup::~TestingSetup_
```diff
         threadGroup.interrupt_all();
         threadGroup.join_all();
+        VeriBlock::StopPop();
         GetMainSignals().FlushBackgroundCallbacks();
         GetMainSignals().UnregisterBackgroundSignalScheduler();
```

### Add pop_service.cpp to the Makefile.

[<font style="color: red"> src/Makefile.am </font>]
```diff
 libbitcash_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
 libbitcash_server_a_SOURCES = \
+  vbk/pop_service.hpp \
+  vbk/pop_service.cpp \
   addrdb.cpp \
   addrman.cpp \
```

### Before moving further we will make a short code refactoring.

Create a function in the chainparams which detects if the Pop security is enabled.

[<font style="color: red"> src/chainparams.h </font>]

_class CChainParams_
```diff
     void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout);
+
+    // VeriBlock start
+    bool isPopActive(int height) const {
+            return height >= consensus.VeriBlockPopSecurityHeight;
+    }
+
 protected:
```

### Update validation.cpp to use refactored method for detecting Pop security height.

[<font style="color: red"> src/validation.cpp </font>]

_method ContextualCheckBlockHeader_
```diff
     // VeriBlock validation
-    if((block.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) && consensusParams.VeriBlockPopSecurityHeight > nHeight)
-    {
:
+    if((block.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) &&
+        !params.isPopActive(nHeight)) {
         return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-pop-version(0x%08x)", block.nVersion),
          strprintf("block contains PopData before PopSecurity has been enabled"));
```

### Change height of the Pop security forkpoint in the regtest. It allows to properly run the Pop tests.

[<font style="color: red"> src/chainparams.cpp </font>]

_method CRegTestParams::CRegTestParams_
```diff
+        consensus.VeriBlockPopSecurityHeight = 200;

         // The best chain should have at least this much work.
         consensus.nMinimumChainWork = uint256S("0x00");
```

## Add Pop mempool

Now we want to add the Pop mempool support to the BitCash. We should implement methods for the Pop payloads submitting to the mempool, fetching payloads during the block mining and removing payloads after successfully submitting a block to the blockchain.

### First we should implement methods in the pop_service.hpp pop_service.cpp source files.

[<font style="color: red"> src/vbk/pop_service.hpp </font>]
```diff
 bool loadTrees(CDBIterator& iter);

+//! mempool methods
+altintegration::PopData getPopData();
+void removePayloadsFromMempool(const altintegration::PopData& popData);
+void addDisconnectedPopdata(const altintegration::PopData& popData);
+
 } // namespace VeriBlock
```
[<font style="color: red"> src/vbk/pop_service.cpp </font>]
```diff
     return true;
 }

+altintegration::PopData getPopData() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
+    AssertLockHeld(cs_main);
+    return GetPop().mempool->getPop();
+}
+
+void removePayloadsFromMempool(const altintegration::PopData& popData) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
+    AssertLockHeld(cs_main);
+    GetPop().mempool->removeAll(popData);
+}
+
+void addDisconnectedPopdata(const altintegration::PopData& popData) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
+    disconnected_popdata.push_back(popData);
+}
+
 } // namespace VeriBlock
```

### Add popData during block mining. Update CreateNewBlock() and CreateNewBlockWithScriptPubKey() in the miner.cpp.

[<font style="color: red"> src/miner.cpp </font>]
```diff
 #include "RSJparser.tcc"
 #include <curl/curl.h>

+#include <vbk/pop_service.hpp>
+
```
_method BlockAssembler::CreateNewBlockWithScriptPubKey_
```diff
     addPackageTxs(nPackagesSelected, nDescendantsUpdated);

     // VeriBlock: add PopData into the block
+    if(chainparams.isPopActive(nHeight)) {
+        pblock->popData = VeriBlock::getPopData();
+        LogPrintf("pblock->popData atvs: %ld, vtbs: %ld, context: %ld \n",
+               pblock->popData.atvs.size(),
+               pblock->popData.vtbs.size(),
+               pblock->popData.context.size());
+    }
     if(!pblock->popData.empty()) {
         pblock->nVersion |= VeriBlock::POP_BLOCK_VERSION_BIT;

```
_method BlockAssembler::CreateNewBlock_
```diff
     addPackageTxs(nPackagesSelected, nDescendantsUpdated);

     // VeriBlock: add PopData into the block
+    if(chainparams.isPopActive(nHeight)) {
+        pblock->popData = VeriBlock::getPopData();
+        LogPrintf("pblock->popData atvs: %ld, vtbs: %ld, context: %ld \n",
+               pblock->popData.atvs.size(),
+               pblock->popData.vtbs.size(),
+               pblock->popData.context.size());
+    }
     if(!pblock->popData.empty()) {
         pblock->nVersion |= VeriBlock::POP_BLOCK_VERSION_BIT;
```

### We should remove popData after successfully submitting to the blockchain. Modify ConnectTip() and DisconnectTip() methods in the validation.cpp.

[<font style="color: red"> src/validation.cpp </font>]

_method CChainState::DisconnectTip_
```diff
     }

+    // VeriBlock
+    VeriBlock::addDisconnectedPopdata(block.popData);
+
     chainActive.SetTip(pindexDelete->pprev);

     UpdateTip(pindexDelete->pprev, chainparams);
```
_method CChainState::ConnectTip_
```diff
     mempool.removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
     disconnectpool.removeForBlock(blockConnecting.vtx);
+
+    // VeriBlock: remove from pop_mempool
+    VeriBlock::removePayloadsFromMempool(blockConnecting.popData);
+
     // Update chainActive & related variables.
     chainActive.SetTip(pindexNew);
     UpdateTip(pindexNew, chainparams);
```

## Add VeriBlock AltTree

At this stage we will add functions for maintaining the VeriBlock AltTree: setState(), acceptBlock(), addAllBlockPayloads(). They provide API to change the state of the VeriBlock AltTree.
acceptBlock() - adds an altchain block into to the library;  
addAllBlockPayloads() - adds popData for the current altchain block into the library and should be invoked before acceptBlock() call;  
setState() - changes the state of the VeriBlock AltTree as if the provided altchain block is the current tip of the blockchain.

[<font style="color: red"> src/vbk/pop_service.hpp </font>]
```diff
 #define BITCASH_SRC_VBK_POP_SERVICE_HPP

+#include <consensus/validation.h>
 #include <vbk/adaptors/block_batch_adaptor.hpp>
 #include <vbk/adaptors/payloads_provider.hpp>
 #include <vbk/pop_common.hpp>
 #include <vbk/util.hpp>

+typedef int64_t CAmount;
+
+class CBlockIndex;
+class CBlock;
+class CScript;
 class CBlockTreeDB;
 class CDBBatch;
 class CDBIterator;
 class CDBWrapper;
+class CChainParams;
+class CValidationState;

 namespace VeriBlock {

+using BlockBytes = std::vector<uint8_t>;
+using PoPRewards = std::map<CScript, CAmount>;
+
 void InitPopContext(CDBWrapper& db);
```
```diff
 bool loadTrees(CDBWrapper& db);

+//! alttree methods
+bool acceptBlock(const CBlockIndex& indexNew, CValidationState& state);
+bool addAllBlockPayloads(const CBlock& block);
+bool setState(const uint256& hash, altintegration::ValidationState& state);
+
+std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks);
+std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks);
+
 } // namespace VeriBlock
```
[<font style="color: red"> src/vbk/pop_service.cpp </font>]
```diff
+
+bool acceptBlock(const CBlockIndex& indexNew, CValidationState& state)
+{
+    AssertLockHeld(cs_main);
+    auto containing = VeriBlock::blockToAltBlock(indexNew);
+    altintegration::ValidationState instate;
+    if (!GetPop().altTree->acceptBlockHeader(containing, instate)) {
+        LogPrintf("ERROR: alt tree cannot accept block %s\n", instate.toString());
+        return state.Invalid(false,
+                             REJECT_INVALID,
+                             "",
+                             instate.GetDebugMessage());
+    }
+    return true;
+}
+
+bool checkPopDataSize(const altintegration::PopData& popData, altintegration::ValidationState& state)
+{
+    uint32_t nPopDataSize = ::GetSerializeSize(popData, CLIENT_VERSION);
+    if (nPopDataSize >= GetPop().config->alt->getMaxPopDataSize()) {
+        return state.Invalid("popdata-oversize", "popData raw size more than allowed");
+    }
+
+    return true;
+}
+
+bool popdataStatelessValidation(const altintegration::PopData& popData, altintegration::ValidationState& state)
+{
+    auto& pop = GetPop();
+    return altintegration::checkPopData(*pop.popValidator, popData, state);
+}
+
+bool addAllBlockPayloads(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
+    AssertLockHeld(cs_main);
+    auto bootstrapBlockHeight = GetPop().config->alt->getBootstrapBlock().height;
+    auto hash = block.GetHash();
+    auto* index = LookupBlockIndex(hash);
+
+    if (index->nHeight == bootstrapBlockHeight) {
+        // skip bootstrap block block
+        return true;
+    }
+
+    altintegration::ValidationState instate;
+
+    if (!popdataStatelessValidation(block.popData, instate)) {
+        return error("[%s] block %s is not accepted because popData is invalid: %s", __func__, block.GetHash().ToString(),
+            instate.toString());
+    }
+
+    GetPop().altTree->acceptBlock(block.GetHash().asVector(), block.popData);
+
+    return true;
+}
+
+bool setState(const uint256& hash, altintegration::ValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
+    AssertLockHeld(cs_main);
+    return GetPop().altTree->setState(hash.asVector(), state);
+}
+
+std::vector<BlockBytes> getLastKnownVBKBlocks(size_t blocks)
+{
+    LOCK(cs_main);
+    return altintegration::getLastKnownBlocks(GetPop().altTree->vbk(), blocks);
+}
+
+std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks)
+{
+    LOCK(cs_main);
+    return altintegration::getLastKnownBlocks(GetPop().altTree->btc(), blocks);
+}
+
} // namespace VeriBlock
```

### Update block processing in the ConnectBlock(), DisconnectBlock(), UpdateTip(), LoadGenesisBlock(), AcceptBlockHeader(), AcceptBlock(), TestBlockValidity().

[<font style="color: red"> src/validation.cpp</font>]

_method CChainState::DisconnectBlock_
```diff
     }

+    // VeriBlock
+    auto prevHash = pindex->pprev->GetBlockHash();
+    altintegration::ValidationState state;
+    VeriBlock::setState(prevHash, state);
+
     // move best block pointer to prevout block
     view.SetBestBlock(pindex->pprev->GetBlockHash());
```
_method CChainState::ConnectBlock_
```diff
         UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);
     }
+
+    altintegration::ValidationState _state;
+    if(!VeriBlock::setState(pindex->GetBlockHash(), _state)) {
+        return state.Invalid(false,
+         REJECT_INVALID,
+         "bad-block-pop",
+         strprintf("Block %s is POP invalid: %s",
+          pindex->GetBlockHash().ToString(),
+          _state.toString()));
+    }
+
     int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
     LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2), MILLI * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);
```
_method UpdateTip_
```diff
         g_best_block_cv.notify_all();
     }

+    // VeriBlock
+    altintegration::ValidationState state;
+    bool ret = VeriBlock::setState(pindexNew->GetBlockHash(), state);
+    assert(ret && "block has been checked previously and should be valid");
+
     std::vector<std::string> warningMessages;
     if (!IsInitialBlockDownload())
     {
```
```diff
             DoWarning(strWarning);
         }
     }
-    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)", __func__, /* Continued */
-      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight, pindexNew->nVersion,
-      log(pindexNew->nChainWork.getdouble())/log(2.0), (unsigned long)pindexNew->nChainTx,
-      FormatISO8601DateTime(pindexNew->GetBlockTime()),
-      GuessVerificationProgress(chainParams.TxData(), pindexNew), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1<<20)), pcoinsTip->GetCacheSize());
-    if (!warningMessages.empty())
-        LogPrintf(" warning='%s'", boost::algorithm::join(warningMessages, ", ")); /* Continued */
-    LogPrintf("\n");
+
+    auto& pop = VeriBlock::GetPop();
+    auto* vbktip = pop.altTree->vbk().getBestChain().tip();
+    auto* btctip = pop.altTree->btc().getBestChain().tip();
+    LogPrintf("%s: new best=ALT:%d:%s %s %s version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)%s\n", __func__,
+        pindexNew->nHeight,
+        pindexNew->GetBlockHash().GetHex(),
:
+        (vbktip ? vbktip->toShortPrettyString() : "VBK:nullptr"),
+        (btctip ? btctip->toShortPrettyString() : "BTC:nullptr"),
+        pindexNew->nVersion,
+        log(pindexNew->nChainWork.getdouble()) / log(2.0), (unsigned long)pindexNew->nChainTx,
+        FormatISO8601DateTime(pindexNew->GetBlockTime()),
+        GuessVerificationProgress(chainParams.TxData(), pindexNew), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1 << 20)), pcoinsTip->GetCacheSize(),
+        !warningMessages.empty() ? strprintf(" warning='%s'", boost::algorithm::join(warningMessages, ", ")) : "");

 }
```
_method CChainState::AcceptBlockHeader_
```diff
     CheckBlockIndex(chainparams.GetConsensus());

+    // VeriBlock
+    if(!VeriBlock::acceptBlock(*pindex, state)) {
+        return error("%s: ALT tree could not accept block ALT:%d:%s, reason: %s",
+          __func__,
+          pindex->nHeight,
+          pindex->GetBlockHash().ToString());
+    }
+
     return true;
```
_method CChainState::AcceptBlock_
```diff
         return error("%s: %s", __func__, FormatStateMessage(state));
     }

+    // VeriBlock
+    {
+        if(!VeriBlock::addAllBlockPayloads(block)) {
+            return state.Invalid(false,
+              REJECT_INVALID,
+              strprintf("Can not add POP payloads to block height: %d, hash: %s",
+              pindex->nHeight,
+              block.GetHash().ToString()));
+        }
+    }
+
     // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
```
_method TestBlockValidity_
```diff
     if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindexPrev))
         return error("%s: Consensus::ContextualCheckBlock: %s", __func__, FormatStateMessage(state));
+
+    // VeriBlock: Block that have been passed to TestBlockValidity may not exist in alt tree, because technically it was not created ("mined").
+    // in this case, add it and then remove
+    auto& tree = *VeriBlock::GetPop().altTree;
+    auto _hash = block_hash.asVector();
+    bool shouldRemove = false;
+    if (!tree.getBlockIndex(_hash)) {
+        shouldRemove = true;
+        auto containing = VeriBlock::blockToAltBlock(indexDummy);
+        altintegration::ValidationState _state;
+        bool ret = tree.acceptBlockHeader(containing, _state);
+        assert(ret && "alt tree can not accept alt block");
+
+        tree.acceptBlock(_hash, block.popData);
+    }
+
+    auto _f = altintegration::Finalizer([shouldRemove, _hash, &tree]() {
+        if (shouldRemove) {
+            tree.removeSubtree(_hash);
+        }
+    });
+
     if (!g_chainstate.ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true))
```
_method CChainState::LoadGenesisBlock_
```diff             return error("%s: writing genesis block to disk failed", __func__);
         CBlockIndex *pindex = AddToBlockIndex(block);
         CValidationState state;
+        if (!VeriBlock::acceptBlock(*pindex, state)) {
+            return false;
+        }
         if (!ReceivedBlockTransactions(block, state, pindex, blockPos, chainparams.GetConsensus()))
             return error("%s: genesis block not accepted (%s)", __func__, FormatStateMessage(state));
```

[<font style="color: red"> src/init.cpp </font>]

_method AppInitMain_
```diff
     g_wallet_init_interface.Start(scheduler);

+    {
+        auto& pop = VeriBlock::GetPop();
+        auto* tip = chainActive.Tip();
+        altintegration::ValidationState state;
+        LOCK(cs_main);
+        bool ret = VeriBlock::setState(tip->GetBlockHash(), state);
+        auto* alttip = pop.altTree->getBestChain().tip();
+        assert(ret && "bad state");
+        assert(tip->nHeight == alttip->getHeight());
+
+        LogPrintf("ALT tree best height = %d\n", pop.altTree->getBestChain().tip()->getHeight());
+        LogPrintf("VBK tree best height = %d\n", pop.altTree->vbk().getBestChain().tip()->getHeight());
+        LogPrintf("BTC tree best height = %d\n", pop.altTree->btc().getBestChain().tip()->getHeight());
+    }
+
     return true;
```

## Add unit tests

Now we will test the functionality we have added before.

### First let's add some util files: consts.hpp, e2e_fixture.hpp.

[<font style="color: red"> src/vbk/test/util/consts.hpp </font>]
```
#ifndef BITCASH_SRC_VBK_TEST_UTIL_CONSTS_HPP
#define BITCASH_SRC_VBK_TEST_UTIL_CONSTS_HPP

namespace VeriBlockTest {

static const std::string defaultAtvEncoded =
    "000000010189bb01011667b55493722b4807bea7bb8ed2835d990885f3fe51c30203e80001"
    "070167010001500000002036cff5b91ed5d135be14654ca6c89f9da04043720696bd70c79b"
    "0a77b4c286ea000000205f1d18e6824ee01817e9432f8d926353f7d7a0a5d2c6534b6a30dd"
    "9ab019b70f000000050000000501050102030405010a0102030405060708090a4630440220"
    "6d1927c66b9a5f56f085fab309f756e11621e510b51736ca2d9c42eb8de6a97c0220111a2a"
    "9b8d4f480495ed9e5e0cc72aea1824008ba20446019566ddf3099ad17f583056301006072a"
    "8648ce3d020106052b8104000a034200042fca63a20cb5208c2a55ff5099ca1966b7f52e68"
    "7600784d1de062c1dd9c8a5fe55b2ba5d906c703d37cbd02ecd9c97a806110fa05d9014a10"
    "2a0513dd354ec50400000000040000000020a2e63f9eade6b9ff6899e094e29329a7225f23"
    "766afd8d5cd65bd4c0b406084c040000000041000000430002efeafedd566efa5d34395974"
    "b0d80c07c61cb745b3e7ed364ef191b08de0a2e63f9eade6b9ff6899e094e29329a75c9b94"
    "94010100000000000000";

static const std::string defaultVtbEncoded =
    "00000001020dbfbb02011667b55493722b4807bea7bb8ed2835d990885f3fe51c341000000"
    "0500026edd7a83dfbd4b56cad65ed577a1d330ec8c16fd6900000000000000000070e93ea1"
    "41e1fc673e017e97eadc6b965c9b949401010000000000000001510000000500026edd7a83"
    "dfbd4b56cad65ed577a1d330ec8c16fd6900000000000000000070e93ea141e1fc673e017e"
    "97eadc6b965c9b94940101000000000000008b334de3af7d2ba37c2efc1334e5b4fe011304"
    "0000000004000000000400000004000000205001000000eb5a665201d3e458eee75b74493f"
    "a91a7557a7f4375bd349c0ecb59691762a50842b620dbba278308a18de01ce6ae1fff526b6"
    "512a4f0c662ee22b9cb35b085e94949b5cffff7f202f0000000128500100000006226e4611"
    "1a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910ff57d9bba19226fbb5c15"
    "474850e3cd333baf101bf2acd4aadc099e112464703b94949b5cffff7f2002000000500100"
    "0000dca5bf5226bcc95c07d027441cb1e7d79796d1e4ab5e721a02b4b519df4cb33e056ccb"
    "fa774e5fbc343d4d79e0383298e84ecab5131ba4f829f8237f1c1ae10b94949b5cffff7f20"
    "000000005001000000bfaeff443812368985c2d1100d4eee8f8af09f0146ceefc5ec8bc94d"
    "9328332da94e82fd4915324f9ee4f0e2afb39436d35c043b73b570bea2551aaa2b2186ac94"
    "949b5cffff7f2000000000500100000006b1cfe9bac72c2d4159d3bf19c8210667c1d9540c"
    "3e9ee70dcedecae2762f24cdaf33c406e542099b2dd74c8ef35bac44a8180ed5bc0a9a4854"
    "298ab2d4700894949b5cffff7f200000000050010000006674f70816611fcb69e476fdc7ff"
    "7b670f885c352ac0e3a51579db8d383b8357c386ba20b90becf40407b2fb6c852320f630c4"
    "4aec1c32de4776d4ad2d7f84a394949b5cffff7f2003000000500100000007526cf73af2f9"
    "5cc4d359af0614a9dc4ddba2bd446d72849d14cfd4289fe82dfa7844bcb4be019405f6a810"
    "f2a05ef734d9d314e3a35099b73367d9ecf1053e94949b5cffff7f20050000005001000000"
    "fd40204242ab400ca343d2c0ac3da57bee07942179d32dda7b83ab5619bbef56e5e9bc9bee"
    "445732909931fb943a538448b325517e4c7e6a69da1ad023e6694994949b5cffff7f200700"
    "000050010000006c3357fc0ec3e59e07d1a3ad2c87fde9da78deecceef0d3a84103cdda226"
    "69638a5a70657587a8d998648266d4e835d854fa85d0b2d2aa60535ee2e9f508cf2594949b"
    "5cffff7f200b0000005001000000242b6cdb9eaf3378a83a361b23913f896286d6fd36c098"
    "fa05d352813bdc4d2cbb7cc07cf1660c8cf185e417ec809586acad51d359574e89a57cde44"
    "2980623f94949b5cffff7f200000000050010000005db28060551d0d7d279f98cca330119d"
    "2e5044da3ddd12896edcba1e0545fd154fef8d2d34116db81f07ac931627afff3a2f69b483"
    "bc62af630b61da66e4fc2294949b5cffff7f200d0000005001000000036b48e472f22d90eb"
    "1cb000a5f2daa5f7af8ed8b500b64cce741b4110394d031ff4c196a5d109779df80ae5d802"
    "3945ec1296edd8678324e4c7c13563b6d48994949b5cffff7f2013000000500100000013ad"
    "f99b975b3752f1b531ac9074e2cd0393fdedf0a07da0302970a17cd2db5e5e80c3c961cf08"
    "cb2a37c2b299caa8b4f2a67aacba6816cd90ae496cca82aa9594949b5cffff7f2015000000"
    "50010000007ad1645cd67ea0df1b0f67d80cf07dc761f0aa3b5e3962c4d6016f031381407d"
    "ff01c691a345cdd9e4fed118d49a5622008b794c99d3d2ed196ad74cda28036e94949b5cff"
    "ff7f20000000005001000000144078a90307ca1295b43c458be7520a4457d5fb39ca2035dc"
    "b01fc383551d193ace4b71cf49ab3ea66571cd8172fc699e62137c61870215ee2f430115d9"
    "2ac994949b5cffff7f20160000005001000000260576e4e6c25191ae1e72efcc12713f8874"
    "fd7d9361640153a28b10c26cf4613ca45bc76a8c7cf9bd324e7e8ce90dbf679bc3fefd61eb"
    "81ff647eea764fa77594949b5cffff7f2019000000500100000044ff5df22d0a816e855371"
    "6898cb9498affe5db0990338bceedb1acc1b55d966be0da7bcd103610a98d48e9f175b5099"
    "cf678b1000f04d01f3ec1672edb2f40294949b5cffff7f2000000000500100000040883ba4"
    "4e2f2c71eaaf636897045038e34247b0c057baebb8c7e86fe14e2e4f0cde97701f8ac963b9"
    "c602af2d2e218e16c53e7df6d6f2e5d60198d50eabbf9b94949b5cffff7f201b0000005001"
    "0000006a2d3f29d2e403b0d740a8e611f2afb61720d9f075cbb5530baf40303b77e833c2dd"
    "336cd155d561354b98d292d2cfe3a4a1c2168bfdd80d07011b212b1a895694949b5cffff7f"
    "201c00000050010000006dd3c8fa32c410953fae16c9f55e94cd1d813eef15b7f916070ff3"
    "8b30f2cd2b686afbaca81e793b4c2466ebee1a531c88814da4ddabe2c720e5ef13deedf7bc"
    "94949b5cffff7f201d0000005001000000763ec685ccab0db5480684e9f5bfe4acbb9655ab"
    "b30d26f4eff7dd5c51b2c33704db0811739e16c7f6f84ebaab2a54c03b3a6c1fb2ebd20d0e"
    "262b47064658f394949b5cffff7f201e0000005001000000a0253929a0b24d16ac1bc14ccd"
    "75d29f74e6f992685786eae8dcd60401aa7c7b539cebf2980fea869c4c70d55678879bcd5d"
    "470d220da0035bb5314da70a226094949b5cffff7f200000000050010000008006b4ca221c"
    "703f712ad12e0896d9390e7f08c884acbb1101973b0c3992ec345b76ce4e233263319a5447"
    "13b7fba3e2a52a5a095dfdc250dbb5b0d85afaa70d94949b5cffff7f200000000050010000"
    "00713c1d2f1f128cf6a25108e85ef264b0c7065599fa538c46834b5c9b6c370749c07be94a"
    "1f737cd14f4a6d1eb019d79c62dcf98037cf252e71286b214db6717594949b5cffff7f201f"
    "0000005001000000cb7038a95ea451e710076eb1df06a19514b555147898c8ca98b68cb7ff"
    "d92308dbd2308012b597c895244cc4d40257b6523ddeb5db02bc5bcaed369c7b0d315a9494"
    "9b5cffff7f2024000000500100000027d9eaf65e4be6a510ee79ae9cb674a01a57ee8e71cb"
    "260ec708e5721cc48a2b814902206e2ff0ee1d3b5755a63309e15e078aa8b54dcaff71c843"
    "16fd56e06194949b5cffff7f200000000050010000003bcb5dfe5825df24f4604add988eb4"
    "30a76c5251d1d51e21ae572142b2fef2592d96484b15fe49f4901a04a2fdc84ba822189f41"
    "b998b611e36947e3f87fa0e294949b5cffff7f2000000000500100000087dae66372419284"
    "26e5d6aa7acc41cf80cbc023c2d8ee5acbb682e36f6b584fea671502397fbaee6abca4752c"
    "8a718a8da93fe5862746456dae8f5ccb2515e894949b5cffff7f20000000005001000000b3"
    "90bbfbab98291a12947b7acb4e1cde5034976d64a33f1ee42c17afb458c96ca174db768a74"
    "60873be1cd4d7711a802e51e905b90e71cab61f5641b87b68c2b94949b5cffff7f20290000"
    "00500100000024afddffef180ef6fa667a98f9b707e35975882d088861631de4b61feecc80"
    "20d12fdd698e698d18df19b757ded68a915e79e85c94cacc393ae41d8f83282a6894949b5c"
    "ffff7f20000000005001000000921c6bcfd3a4aaa566b6aa8e7ae935ed091ed5d93789454e"
    "9d140b8d9ca3a140ccd322c402f3e699657d0c4d9ef3964715c0bc8461439b05aed1397597"
    "54570894949b5cffff7f20000000005001000000c154860be4151e92d3d7ca13e727db7f7b"
    "e62e1f56be34e260e6311d4640c72a6076d7e6aa03c4e601d000676b825b1de468879d53c7"
    "e0cf669d3461ef63287a94949b5cffff7f20000000005001000000630f5cb6dd49da9abee9"
    "6c3438bcc1546bedd0ffbcda626e21366882c546ad0b3679d83718626032b75d6ed15c9dd1"
    "f4324e99156a308dcdddc6ed0d604fd9ff94949b5cffff7f202a0000005001000000520a5a"
    "7190eb62b2fb393038b335202babf55cbe09cbef231f31f380180ff83c82e200d0ab87f774"
    "6f95133ddeb6cf0d5a313c66ffedcdea839c5cb5bf96c8b294949b5cffff7f200000000050"
    "01000000ccd2e9907adf9dcfc69f932ee11b0337750c64014e29e3da36ba75e376117e0ebb"
    "f537f27355f2a3a96aab35fb1622be386bef2b11beefabbf01ded57e4178c994949b5cffff"
    "7f2000000000500100000007c1358473941c714d172c9dd2ae9709535d362d659b44b00481"
    "ed3ae895964478b55ac9fa659207f23d154f93aba35eaf8d3cf155d0012abf433b14843a36"
    "af94949b5cffff7f20000000005001000000f4cee631258e04c5f5312785bd3eab5dfac2ac"
    "e997c25b0e42ec67ccac458c3f6c735adcfaa48231aa1d9fa32b628ddccfe2387133ab3542"
    "5564402ba5fdef9094949b5cffff7f20000000005001000000cd43104433d16acb475111c4"
    "ab812adb80b4d1057ed8603677ee5432ff8939362b9c8ce12f1987531ee3d1ed38b44d9589"
    "eb08ad1c2575abf2ca76b07411704994949b5cffff7f202c00000050010000006dd660d712"
    "3c108014e379a682f5c78b4b1f29b01d063c32e5f21e92e2aee975cf11bad3e61e4705ef2e"
    "7d9b109aca236215d5cc8ceac4dece9f6923ac9fadfc94949b5cffff7f202e000000500100"
    "0000b5f54cbefe1e7aa47e19db9b2d94ec630956a64cc3c31fe167d934d0030fe367306623"
    "c896110dc32bef7b26004da8643d0e9a1aac8544dff95a1b1a8b7cb16894949b5cffff7f20"
    "000000005001000000707ca69542d05336234b32301cf999270d67293a2ef021959bf77809"
    "e2f7a94a986039c430d3a1683c905a79656bfe3f6bb1960774886c5adce715fdeebbe2d494"
    "949b5cffff7f2000000000473045022100cadfa30349b4a3f76f55a8d6623d37c7c3d770f7"
    "4fd710a6f038af9091a5b6c1022048c9a2012815ef84a3e9fdb43246e26e34e6a8a36f26e7"
    "d1219500137da206c2583056301006072a8648ce3d020106052b8104000a034200042fca63"
    "a20cb5208c2a55ff5099ca1966b7f52e687600784d1de062c1dd9c8a5fe55b2ba5d906c703"
    "d37cbd02ecd9c97a806110fa05d9014a102a0513dd354ec504000000000400000000206bf3"
    "d41c8059c843d202fd75631d9ded1d9978dff61b9f21a8f6a3269867559604000000004100"
    "00000b0002f1606ebb9390033c3532bceb77a1d330ec8c16fd690000000000000000006bf3"
    "d41c8059c843d202fd75631d9ded5c9b9494010100000000000000";

} // namespace VeriBlockTest

#endif
```
[<font style="color: red"> src/vbk/test/util/e2e_fixture.hpp </font>]
```
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
#include <veriblock/mock_miner.hpp>
#include <veriblock/pop_context.hpp>
#include <consensus/merkle.h>

#include <vbk/pop_service.hpp>

using altintegration::ATV;
using altintegration::BtcBlock;
using altintegration::MockMiner;
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
    MockMiner popminer;
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
        auto atv = popminer.endorseAltBlock(publicationdata);
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

        return popminer.endorseVbkBlock(endorsed->getHeader());
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
```

### Update Pop logging support.

[<font style="color: red"> src/vbk/log.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef INTEGRATION_REFERENCE_BITC_LOG_HPP
#define INTEGRATION_REFERENCE_BITC_LOG_HPP

#include <logging.h>
#include <veriblock/logger.hpp>

namespace VeriBlock {

struct BITCLogger : public altintegration::Logger {
    ~BITCLogger() override = default;

    void log(altintegration::LogLevel l, const std::string& msg) override
    {
        LogPrint(BCLog::POP, "[alt-cpp] [%s] %s\n", altintegration::LevelToString(l), msg);
    }
};

} // namespace VeriBlock

#endif //INTEGRATION_REFERENCE_BITC_LOG_HPP
```
[<font style="color: red"> src/logging.h </font>]

_namespace BCLog_
```diff
         QT          = (1 << 19),
         LEVELDB     = (1 << 20),
+        POP         = (1 << 21),
         ALL         = ~(uint32_t)0,
     };
```

[<font style="color: red"> src/logging.cpp </font>]

_field LogCategories_
```diff
     {BCLog::COINDB, "coindb"},
     {BCLog::QT, "qt"},
     {BCLog::LEVELDB, "leveldb"},
+    {BCLog::POP, "pop"},
     {BCLog::ALL, "1"},
     {BCLog::ALL, "all"},
```
[<font style="color: red"> src/init.cpp </font>]
```diff
 #include <zmq/zmqnotificationinterface.h>
 #endif

+#include <vbk/log.hpp>
 #include <vbk/pop_service.hpp>

```
_method InitLogging_
```diff
     g_logger->m_log_timestamps = gArgs.GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
     g_logger->m_log_time_micros = gArgs.GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);

+    std::string poplogverbosity = gArgs.GetArg("-poplogverbosity", "warn");
+    altintegration::SetLogger<VeriBlock::BITCLogger>();
+    altintegration::GetLogger().level = altintegration::StringToLevel(poplogverbosity);
+
     fLogIPs = gArgs.GetBoolArg("-logips", DEFAULT_LOGIPS);
```

### Modify test_bitcash.cpp to perform the basic test setup.

[<font style="color: red"> src/test/test_bitcash.cpp </font>]

_method TestChain100Setup::TestChain100Setup_
```diff
         CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
         m_coinbase_txns.push_back(b.vtx[0]);
     }
+
+    auto& tree = *VeriBlock::GetPop().altTree;
+    assert(tree.getBestChain().tip()->getHeight() == chainActive.Tip()->nHeight);
 }
```

### Allow fast mining for Regtest.

[<font style="color: red"> src/pow.cpp </font>]

_method GetNextWorkRequiredBug_
```diff
     assert(pindexLast != nullptr);

-
     const arith_uint256 bnPowLimit = UintToArith256(params.powLimit.uHashLimit);
+    unsigned int nProofOfWorkLimit = bnPowLimit.GetCompact();
     int64_t nPastBlocks = 24;

     const CBlockIndex *pindex = pindexLast;
```
```diff
         return PoW{bnPowLimit.GetCompact(),pindexLast->nEdgeBits};
     }

+    if (params.fPowAllowMinDifficultyBlocks)
+    {
+        // Return the last non-special-min-difficulty-rules-block
+        while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
+            pindex = pindex->pprev;
+        return PoW{pindex->nBits,pindexLast->nEdgeBits};
+    }
+
     pindex = pindexLast;
     bool foundx16rv2 = false;
     bool foundx25x = false;
```
_method GetNextWorkRequired_
```diff
     int64_t nPastBlocks = 24;

     const arith_uint256 bnPowLimit = UintToArith256(params.powLimit.uHashLimit);
+    unsigned int nProofOfWorkLimit = bnPowLimit.GetCompact();

     // make sure we have at least (nPastBlocks + 1) blocks, otherwise just return powLimit
```
```diff
     if (!pindexLast || pindexLast->nHeight < nPastBlocks) {
         return PoW{bnPowLimit.GetCompact(),pindexLast->nEdgeBits};
     }

+    if (params.fPowAllowMinDifficultyBlocks)
+    {
+        // Return the last non-special-min-difficulty-rules-block
+        while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
+            pindex = pindex->pprev;
+        return PoW{pindex->nBits,pindexLast->nEdgeBits};
+    }
+
     pindex = pindexLast;
     bool foundx16rv2 = false;
     bool foundx25x = false;
```

### Now we can add a test case which tests the VeriBlock Pop behaviour: e2e_poptx_tests.cpp.

[<font style="color: red"> src/vbk/test/unit/e2e_poptx_tests.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <validation.h>
#include <vbk/test/util/e2e_fixture.hpp>
#include <vbk/util.hpp>
#include <veriblock/alt-util.hpp>

using altintegration::BtcBlock;
using altintegration::PublicationData;
using altintegration::VbkBlock;
using altintegration::VTB;

BOOST_AUTO_TEST_SUITE(e2e_poptx_tests)

BOOST_FIXTURE_TEST_CASE(ValidBlockIsAccepted, E2eFixture)
{
    // altintegration and popminer configured to use BTC/VBK/ALT regtest.
    auto tip = chainActive.Tip();
    BOOST_CHECK(tip != nullptr);

    // endorse tip
    CBlock block = endorseAltBlockAndMine(tip->GetBlockHash(), 10);
    BOOST_CHECK(block.popData.vtbs.size() == 10);
    BOOST_CHECK(block.popData.atvs.size() != 0);
    {
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());
        auto btc = VeriBlock::getLastKnownBTCBlocks(1)[0];
        BOOST_REQUIRE(btc == popminer.btc().getBestChain().tip()->getHash());
        auto vbk = VeriBlock::getLastKnownVBKBlocks(1)[0];
        BOOST_REQUIRE(vbk == popminer.vbk().getBestChain().tip()->getHash());
    }

    // endorse another tip
    block = endorseAltBlockAndMine(tip->GetBlockHash(), 1);
    BOOST_CHECK(block.popData.atvs.size() != 0);
    auto lastHash = chainActive.Tip()->GetBlockHash();
    {
        BOOST_REQUIRE(lastHash == block.GetHash());
        auto btc = VeriBlock::getLastKnownBTCBlocks(1)[0];
        BOOST_REQUIRE(btc == popminer.btc().getBestChain().tip()->getHash());
        auto vbk = VeriBlock::getLastKnownVBKBlocks(1)[0];
        BOOST_REQUIRE(vbk == popminer.vbk().getBestChain().tip()->getHash());
    }
}

BOOST_AUTO_TEST_SUITE_END()
```

### Update Makefile to enable new unit test.

[<font style="color: red"> src/Makefile.test.include </font>]
```diff
   test/test_bitcash.h \
   test/test_bitcash.cpp

+# VeriBlock
+VBK_TESTS =\
+  vbk/test/unit/e2e_poptx_tests.cpp
+
 # test_bitcash binary #
 BITCASH_TESTS =\
+  $(VBK_TESTS) \
   test/arith_uint256_tests.cpp \
   test/scriptnum10.h \
   test/addrman_tests.cpp \

```

## Update block merkle root, block size calculating.

For the VeriBlock Pop security we should add Pop related information to the merkle root. Root hash of the Pop data should be added to the original block merkle root calculation.

### VeriBlock merkle root related functions are implemented in the merkle.hpp and merkle.cpp

[<font style="color: red"> src/vbk/merkle.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_MERKLE_HPP
#define BITCASH_SRC_VBK_MERKLE_HPP

#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>

namespace VeriBlock {

uint256 TopLevelMerkleRoot(const CBlockIndex* prevIndex, const CBlock& block, bool* mutated = nullptr);

bool VerifyTopLevelMerkleRoot(const CBlock& block, const CBlockIndex* pprevIndex, CValidationState& state);

} // namespace VeriBlock

#endif //BITCASH_SRC_VBK_MERKLE_HPP
```
[<font style="color: red"> src/vbk/merkle.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "merkle.hpp"
#include <consensus/merkle.h>
#include <hash.h>
#include <vbk/pop_common.hpp>

namespace VeriBlock {

uint256 TopLevelMerkleRoot(const CBlockIndex* prevIndex, const CBlock& block, bool* mutated)
{
    using altintegration::CalculateTopLevelMerkleRoot;
    auto& altParams = *VeriBlock::GetPop().config->alt;

    // first, build regular merkle root from transactions
    auto txRoot = BlockMerkleRoot(block, mutated);

    // if POP is not enabled for 'block' , use original txRoot as merkle root
    const auto height = prevIndex == nullptr ? 0 : prevIndex->nHeight + 1;
    if (!Params().isPopActive(height)) {
        return txRoot;
    }

    // POP is enabled.

    // then, find BlockIndex in AltBlockTree.
    // if returns nullptr, 'prevIndex' is behind bootstrap block.
    auto* prev = VeriBlock::GetAltBlockIndex(prevIndex);
    auto tlmr = CalculateTopLevelMerkleRoot(txRoot.asVector(), block.popData, prev, altParams);
    return uint256(tlmr.asVector());
}

bool VerifyTopLevelMerkleRoot(const CBlock& block, const CBlockIndex* pprevIndex, CValidationState& state)
{
    bool mutated = false;
    uint256 hashMerkleRoot2 = VeriBlock::TopLevelMerkleRoot(pprevIndex, block, &mutated);

    if (block.hashMerkleRoot != hashMerkleRoot2) {
        return state.Invalid(false, REJECT_INVALID, "bad-txnmrklroot",
            strprintf("hashMerkleRoot mismatch. expected %s, got %s", hashMerkleRoot2.GetHex(), block.hashMerkleRoot.GetHex()));
    }

    // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
    // of transactions in a block without affecting the merkle root of a block,
    // while still invalidating it.
    if (mutated) {
        return state.Invalid(false, REJECT_INVALID, "bad-txns-duplicate", "duplicate transaction");
    }

    return true;
}

bool isKeystone(const CBlockIndex& block)
{
    auto keystoneInterval = VeriBlock::GetPop().config->alt->getKeystoneInterval();
    return (block.nHeight % keystoneInterval) == 0;
}

} // namespace VeriBlock
```

### Next step is to update the mining process and validation process with new merkle root calculation.

[<font style="color: red"> src/miner.cpp </font>]
```diff
 #include "RSJparser.tcc"
 #include <curl/curl.h>

+#include <vbk/merkle.hpp>
#include <vbk/pop_service.hpp>
```
_method IncrementExtraNonce_
```diff
     assert(txCoinbase.vin[0].scriptSig.size() <= 100);

     pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
-    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
+    // VeriBlock
+    pblock->hashMerkleRoot = VeriBlock::TopLevelMerkleRoot(pindexPrev, *pblock);
 }
```
[<font style="color: red"> src/stratum.cpp </font>]
```diff
 #include <chainparams.h>
 #include <validation.h>
 #include "rpc/blockchain.h"
+#include <vbk/merkle.hpp>

 #include "RSJparser.tcc"
```
_method stratum_
```diff
                         assert(txCoinbase.vin[0].scriptSig.size() <= 100);
                         pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
-                        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
+                        // VeriBlock
+                        CBlockIndex *tip = chainActive.Tip();
+                        assert(tip != nullptr);
+                        pblock->hashMerkleRoot = VeriBlock::TopLevelMerkleRoot(tip, *pblock);
+
                        if (ProcessBlockFound(pblock, Params())) {
```
[<font style="color: red"> src/validation.h </font>]
```diff
 /** Context-independent validity checks */
-bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true, bool fCheckMerkleRoot = true, bool checkdblnicknames = false);
+bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true, bool checkdblnicknames = false);
+
+/** Context-dependent validity checks */
+bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev, bool fCheckMerkleRoot = true);
```

### As VeriBlock Merkle root algorithm depends on the blockchain, we should move Merkle root validation from the CheckBlock() to the ContextualCheckBlock().

[<font style="color: red"> src/validation.cpp </font>]
```diff
 #include <boost/algorithm/string/join.hpp>
 #include <boost/thread.hpp>

+#include <vbk/merkle.hpp>
 #include <vbk/pop_service.hpp>

 #if defined(NDEBUG)
```
_method CChainState::ConnectBlock_
```diff
     // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
     // re-enforce that rule here (at least until we make it impossible for
     // GetAdjustedTime() to go backward).
-    if (!CheckBlock(block, state, chainparams.GetConsensus(), !fJustCheck, !fJustCheck)) {
+
+    //VeriBlock : added ContextualCheckBlock() here becuse merkleRoot calculation  moved from the CheckBlock() to the ContextualCheckBlock()
+    if (!CheckBlock(block, state, chainparams.GetConsensus(), !fJustCheck)  && !ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindex->pprev, true)) {
         LogPrintf("BlockHash for corrupt block: %s\n", block.GetHash().ToString());
         CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
```
```diff
-bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot, bool checkdblnicknames)
+bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool checkdblnicknames)
 {
     // These are checks that are independent of context.
```
_method CheckBlock_
```diff
         return false;
     }

-    // Check the merkle root.
-    if (fCheckMerkleRoot) {
-        bool mutated;
-        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
-        if (block.hashMerkleRoot != hashMerkleRoot2)
-            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");
-
-        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
-        // of transactions in a block without affecting the merkle root of a block,
-        // while still invalidating it.
-        if (mutated)
-            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
+    // VeriBlock: merkle root verification currently depends on a context, so it has been moved to ContextualCheckBlock
```
```diff
     if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
         return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

-    if (fCheckPOW && fCheckMerkleRoot)
+    if (fCheckPOW)
         block.fChecked = true;

     return true;
```
```diff
  *  in ConnectBlock().
  *  Note that -reindex-chainstate skips the validation that happens here!
  */
-static bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
+bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev, bool fCheckMerkleRoot)
 {
```
_method ContextualCheckBlock_
```diff
         nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
     }

+    // VeriBlock: merkle tree verification is moved from CheckBlock here, because it requires correct CBlockIndex
+    if (fCheckMerkleRoot && !VeriBlock::VerifyTopLevelMerkleRoot(block, pindexPrev, state)) {
+        // state is already set with error message
+        return false;
+    }
+
     int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                               ? pindexPrev->GetMedianTimePast()
                               : block.GetBlockTime();
```
_method TestBlockValidity_
```diff
     // NOTE: CheckBlockHeader is called by CheckBlock
     if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
         return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, FormatStateMessage(state));
-    if (!CheckBlock(block, state, chainparams.GetConsensus(), fCheckPOW, fCheckMerkleRoot))
+    if (!CheckBlock(block, state, chainparams.GetConsensus(), fCheckPOW))
         return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
-    if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindexPrev))
+    if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindexPrev, fCheckMerkleRoot))
         return error("%s: Consensus::ContextualCheckBlock: %s", __func__, FormatStateMessage(state));

```

### The next step is to update current tests and add new VeriBlock tests.

Add helper genesis_common.cpp file to allow the generating of the Genesis block.

[<font style="color: red"> src/vbk/genesis_common.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_GENESIS_COMMON_HPP
#define BITCASH_SRC_VBK_GENESIS_COMMON_HPP

#include <primitives/block.h>
#include <script/script.h>

namespace VeriBlock {

CScript ScriptWithPrefix(uint32_t nBits);

CBlock CreateGenesisBlock(
    std::string pszTimestamp,
    const CScript& genesisOutputScript,
    uint32_t nTime,
    uint32_t nNonce,
    uint32_t nBits,
    int32_t nVersion,
    const CAmount& genesisReward);

CBlock CreateGenesisBlock(
    uint32_t nTime,
    uint32_t nNonce,
    uint32_t nBits,
    int32_t nVersion,
    const CAmount& genesisReward,
    const std::string& initialPubkeyHex,
    const std::string& pszTimestamp);

} // namespace VeriBlock

#endif //BITCASH_SRC_VBK_GENESIS_COMMON_HPP
```
[<font style="color: red"> src/vbk/genesis_common.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "genesis_common.hpp"
#include <consensus/merkle.h>
#include <vbk/merkle.hpp>

namespace VeriBlock {

CScript ScriptWithPrefix(uint32_t nBits)
{
    CScript script;
    if (nBits <= 0xff)
        script << nBits << CScriptNum(1);
    else if (nBits <= 0xffff)
        script << nBits << CScriptNum(2);
    else if (nBits <= 0xffffff)
        script << nBits << CScriptNum(3);
    else
        script << nBits << CScriptNum(4);

    return script;
}

CBlock CreateGenesisBlock(
    std::string pszTimestamp,
    const CScript& genesisOutputScript,
    uint32_t nTime,
    uint32_t nNonce,
    uint32_t nBits,
    int32_t nVersion,
    const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = VeriBlock::ScriptWithPrefix(nBits) << std::vector<uint8_t>{pszTimestamp.begin(), pszTimestamp.end()};
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

CBlock CreateGenesisBlock(
    uint32_t nTime,
    uint32_t nNonce,
    uint32_t nBits,
    int32_t nVersion,
    const CAmount& genesisReward,
    const std::string& initialPubkeyHex,
    const std::string& pszTimestamp)
{
    const CScript genesisOutputScript = CScript() << altintegration::ParseHex(initialPubkeyHex) << OP_CHECKSIG;
    return VeriBlock::CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

} // namespace VeriBlock
```

### Add new tests: block_validation_tests.cpp, pop_util_tests.cpp, vbk_merkle_tests.cpp.

[<font style="color: red"> src/vbk/test/unit/block_validation_tests.cpp </font>]
```
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
#include <vbk/test/util/consts.hpp>
#include <vbk/test/util/e2e_fixture.hpp>

#include <string>

inline std::vector<uint8_t> operator""_v(const char* s, size_t size)
{
    return std::vector<uint8_t>{s, s + size};
}

BOOST_AUTO_TEST_SUITE(block_validation_tests)

static altintegration::PopData generateRandPopData()
{
    // add PopData
    altintegration::ATV atv = altintegration::AssertDeserializeFromHex<altintegration::ATV>(VeriBlockTest::defaultAtvEncoded);
    altintegration::VTB vtb = altintegration::AssertDeserializeFromHex<altintegration::VTB>(VeriBlockTest::defaultVtbEncoded);

    altintegration::PopData popData;
    popData.atvs = {atv};
    popData.vtbs = {vtb, vtb, vtb};

    return popData;
}

BOOST_AUTO_TEST_CASE(block_serialization_test)
{
    // Create random block
    CBlock block;
    block.hashMerkleRoot.SetNull();
    block.hashPrevBlock.SetNull();
    block.nBits = 10000;
    block.nNonce = 10000;
    block.nTime = 10000;
    block.nVersion = 1 | VeriBlock::POP_BLOCK_VERSION_BIT;

    altintegration::PopData popData = generateRandPopData();

    block.popData = popData;

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(stream.size() == 0);
    stream << block;
    BOOST_CHECK(stream.size() != 0);

    CBlock decoded_block;
    stream >> decoded_block;

    BOOST_CHECK(decoded_block.GetHash() == block.GetHash());
    BOOST_CHECK(decoded_block.popData == block.popData);
}

BOOST_AUTO_TEST_CASE(block_network_passing_test)
{
    // Create random block
    CBlock block;
    block.hashMerkleRoot.SetNull();
    block.hashPrevBlock.SetNull();
    block.nBits = 10000;
    block.nNonce = 10000;
    block.nTime = 10000;
    block.nVersion = 1 | VeriBlock::POP_BLOCK_VERSION_BIT;

    altintegration::PopData popData = generateRandPopData();

    block.popData = popData;

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
}

BOOST_FIXTURE_TEST_CASE(BlockPoPVersion_test, E2eFixture)
{
    for (size_t i = 0; i < 400; ++i) {
        CreateAndProcessBlock({}, cbKey);
    }

    auto block = CreateAndProcessBlock({}, cbKey);
}

BOOST_AUTO_TEST_SUITE_END()
```
[<font style="color: red"> src/vbk/test/unit/vbk_merkle_tests.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <boost/test/unit_test.hpp>

#include <algorithm>

#include <chain.h>
#include <test/test_bitcash.h>
#include <validation.h>
#include <wallet/wallet.h>

#include "vbk/genesis_common.hpp"
#include "vbk/merkle.hpp"

BOOST_AUTO_TEST_SUITE(vbk_merkle_tests)

struct MerkleFixture {
    // this inits veriblock services
    TestChain100Setup blockchain;
    CScript cbKey = CScript() << ToByteVector(blockchain.coinbaseKey.GetPubKey()) << OP_CHECKSIG;
};

BOOST_FIXTURE_TEST_CASE(genesis_block_hash_is_valid, MerkleFixture)
{
    CBlock block = VeriBlock::CreateGenesisBlock(
        1337, 36282504, 0x1d0fffff, 1, 50 * COIN,
        "047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488",
        "VeriBlock");
    CValidationState state;

    bool result = VeriBlock::VerifyTopLevelMerkleRoot(block, nullptr, state);
    BOOST_CHECK(result);
    BOOST_CHECK(state.IsValid());
}

BOOST_FIXTURE_TEST_CASE(TestChain100Setup_has_valid_merkle_roots, MerkleFixture)
{
    SelectParams("regtest");
    CValidationState state;
    CBlock block;

    int MAX = 1000;
    while(chainActive.Height() < MAX) {
        blockchain.CreateAndProcessBlock({}, cbKey);
    }

    for (int i = 0; i <= chainActive.Height(); i++) {
        CBlockIndex* index = chainActive[i];
        BOOST_REQUIRE_MESSAGE(index != nullptr, "can not find block at given height");
        BOOST_REQUIRE_MESSAGE(ReadBlockFromDisk(block, index, Params().GetConsensus()), "can not read block");
        BOOST_CHECK_MESSAGE(VeriBlock::VerifyTopLevelMerkleRoot(block, index->pprev, state), strprintf("merkle root of block %d is invalid", i));
    }
}

BOOST_AUTO_TEST_SUITE_END()
```

### Update makefile to run tests.

[<font style="color: red"> src/Makefile.test.include </font>]
```diff
   test/test_bitcash.cpp

+# VeriBlock
VBK_TESTS =\
   vbk/test/unit/e2e_poptx_tests.cpp \
+  vbk/test/unit/block_validation_tests.cpp \
+  vbk/test/unit/vbk_merkle_tests.cpp
+
 # test_bitcash binary #
```

## Add Pop rewards.

Modify reward algorithm. Tthe basic PoW rewards are extended with Pop rewards for the Pop miners. Corresponding functions are added to the pop_service.hpp, pop_service.cpp.

[<font style="color: red"> src/vbk/pop_service.hpp </font>]
```diff
 std::vector<BlockBytes> getLastKnownBTCBlocks(size_t blocks);

+PoPRewards getPopRewards(const CBlockIndex& pindexPrev, const CChainParams& params);
+void addPopPayoutsIntoCoinbaseTx(CMutableTransaction& coinbaseTx, const CBlockIndex& pindexPrev, const CChainParams& params);
+bool checkCoinbaseTxWithPopRewards(const CTransaction& tx, const CAmount& nFees, const CBlockIndex& pindexPrev, const CChainParams& params, CValidationState& state);
+CAmount getCoinbaseSubsidy(const CAmount& subsidy, int32_t height, const CChainParams& params);
+
```
[<font style="color: red"> src/vbk/pop_service.cpp </font>]
```diff

+#include <chainparams.h>
 #include <dbwrapper.h>
```
```diff
     return altintegration::getLastKnownBlocks(GetPop().altTree->btc(), blocks);
 }

+// PoP rewards are calculated for the current tip but are paid in the next block
+PoPRewards getPopRewards(const CBlockIndex& pindexPrev, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
+    AssertLockHeld(cs_main);
+    const auto& pop = GetPop();
+
+    if (!params.isPopActive(pindexPrev.nHeight)) {
+        return {};
+    }
+
+    auto& cfg = *pop.config;
+    if (pindexPrev.nHeight < (int)cfg.alt->getEndorsementSettlementInterval()) {
+        return {};
+    }
+    if (pindexPrev.nHeight < (int)cfg.alt->getPayoutParams().getPopPayoutDelay()) {
+        return {};
+    }
+
+    altintegration::ValidationState state;
+    auto prevHash = pindexPrev.GetBlockHash().asVector();
+    bool ret = pop.altTree->setState(prevHash, state);
+    (void)ret;
+    assert(ret);
+
+    auto rewards = pop.popRewardsCalculator->getPopPayout(prevHash);
+    int halvings = (pindexPrev.nHeight + 1 < params.GetConsensus().nSubsidyFirstInterval)?
+        0 :
+        (pindexPrev.nHeight + 1 - params.GetConsensus().nSubsidyFirstInterval) / params.GetConsensus().nSubsidyHalvingInterval;
+    PoPRewards result{};
+    // erase rewards, that pay 0 satoshis, then halve rewards
+    for (const auto& r : rewards) {
+        auto rewardValue = r.second;
+        rewardValue >>= halvings;
+        if ((rewardValue != 0) && (halvings < 64)) {
+            CScript key = CScript(r.first.begin(), r.first.end());
+            result[key] = params.PopRewardCoefficient() * rewardValue;
+        }
+    }
+
+    return result;
+}
+
+void addPopPayoutsIntoCoinbaseTx(CMutableTransaction& coinbaseTx, const CBlockIndex& pindexPrev, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
+    AssertLockHeld(cs_main);
+    PoPRewards rewards = getPopRewards(pindexPrev, params);
+    assert(coinbaseTx.vout.size() == 2 && "at this place we should have only PoW and DevFund payout here");
+    for (const auto& itr : rewards) {
+        CTxOut out;
+        out.scriptPubKey = itr.first;
+        out.nValue = itr.second;
+        out.nValueBitCash = itr.second;
+        out.currency = 0;
+        coinbaseTx.vout.push_back(out);
+    }
+}
+
+bool checkCoinbaseTxWithPopRewards(const CTransaction& tx, const CAmount& nFees, const CBlockIndex& pindex, const CChainParams& params, CValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
+{
+    AssertLockHeld(cs_main);
+    const CBlockIndex& pindexPrev = *pindex.pprev;
+    PoPRewards expectedRewards = getPopRewards(pindexPrev, params);
+    CAmount nTotalPopReward = 0;
+
+    if (tx.vout.size() < expectedRewards.size()) {
+        return state.Invalid(false, REJECT_INVALID, "bad-pop-vouts-size",
+            strprintf("checkCoinbaseTxWithPopRewards(): coinbase has incorrect size of pop vouts (actual vouts size=%d vs expected vouts=%d)", tx.vout.size(), expectedRewards.size()));
+    }
+    if (tx.vout.size() < 2) {
+        return state.Invalid(false, REJECT_INVALID, "bad-coinbase-vouts-size",
+            strprintf("checkCoinbaseTxWithPopRewards(): coinbase has incorrect size of vouts (actual vouts size=%d vs expected vouts=%d)", tx.vout.size(), 2));
+    }
+
+    std::map<CScript, CAmount> cbpayouts;
+    // skip first reward, as it is always PoW payout
+    // skip second reward as it pays to the DevFund
+    for (auto out = tx.vout.begin() + 2, end = tx.vout.end(); out != end; ++out) {
+        // pop payouts can not be null
+        if (out->IsNull()) {
+            continue;
+        }
+        cbpayouts[out->scriptPubKey] += out->nValue;
+    }
+
+    for (const auto& payout : expectedRewards) {
+        auto& script = payout.first;
+        auto& expectedAmount = payout.second;
+
+        auto p = cbpayouts.find(script);
+        // coinbase pays correct reward?
+        if (p == cbpayouts.end()) {
+            // we expected payout for that address
+            return state.Invalid(false, REJECT_INVALID, "bad-pop-missing-payout",
+                strprintf("[tx: %s] missing payout for scriptPubKey: '%s' with amount: '%d'",
+                    tx.GetHash().ToString(),
+                    HexStr(script),
+                    expectedAmount));
+        }
+
+        // payout found
+        auto& actualAmount = p->second;
+        // does it have correct amount?
+        if (actualAmount != expectedAmount) {
+            return state.Invalid(false, REJECT_INVALID, "bad-pop-wrong-payout",
+                strprintf("[tx: %s] wrong payout for scriptPubKey: '%s'. Expected %d, got %d.",
+                    tx.GetHash().ToString(),
+                    HexStr(script),
+                    expectedAmount, actualAmount));
+        }
+
+        nTotalPopReward += expectedAmount;
+    }
+
+    CAmount PoWBlockReward =
+        GetBlockSubsidy(pindex.nHeight, params);
+    CAmount DevFundBlockReward =
+        GetBlockSubsidyDevs(pindex.nHeight, params.GetConsensus());
+
+    if (tx.GetValueOut() > nTotalPopReward + PoWBlockReward + DevFundBlockReward + nFees) {
+        return state.Invalid(false, REJECT_INVALID,
+            "bad-cb-pop-amount",
+            strprintf("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)", tx.GetValueOut(), PoWBlockReward + DevFundBlockReward + nTotalPopReward));
+    }
+
+    return true;
+}
+
+CAmount getCoinbaseSubsidy(const CAmount& subsidy, int32_t height, const CChainParams& params)
+{
+    if (!params.isPopActive(height)) {
+        return subsidy;
+    }
+
+    int64_t powRewardPercentage = 100 - params.PopRewardPercentage();
+    CAmount newSubsidy = powRewardPercentage * subsidy;
+    return newSubsidy / 100;
+}
+
 } // namespace VeriBlock
```

### Modify CChainParams. Add two new VeriBlock parameters for the Pop rewards.

[<font style="color: red"> src/chainparams.h </font>]

_class CChainParams_
```diff
             return height >= (int)consensus.VeriBlockPopSecurityHeight;
     }

+    uint32_t PopRewardPercentage() const {return mPopRewardPercentage;}
+    int32_t PopRewardCoefficient() const {return mPopRewardCoefficient;}
+
 protected:
     CChainParams() {}
```
```diff
     CCheckpointData checkpointData;
     ChainTxData chainTxData;
     bool m_fallback_fee_enabled;
+
+    // VeriBlock:
+    // cut this % from coinbase subsidy
+    uint32_t mPopRewardPercentage = 40; // %
+    // every pop reward will be multiplied by this coefficient
+    int32_t mPopRewardCoefficient = 20;
 };
```

### Modify mining process in the CreateNewBlock, CreateNewBlockWithScriptPubKey functions. Insert VeriBlock PoPRewards into the conibase transaction, and some validation rules in the validation.cpp. Also modify GetBlockSubsidy() to accept CChainParams instead of consensus params.

[<font style="color: red"> src/validation.cpp </font>]
```diff
     return true;
 }

-CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
+CAmount GetBlockSubsidy(int nHeight, const CChainParams& params)
 {
+    const auto& consensusParams = params.GetConsensus();
     if (nHeight==1)
     {
         return 9700019350 * MILLICOIN; //9.7 millin coins premine
     } else
     if  (nHeight <= consensusParams.nSubsidyFirstInterval)
     {
-        return 19350 * MILLICOIN;
+        CAmount nSubsidy = 19350 * MILLICOIN;
+        nSubsidy = VeriBlock::getCoinbaseSubsidy(nSubsidy, nHeight, params);
+        return nSubsidy;
     } else
```
_method GetBlockSubsidy_
```diff
         CAmount nSubsidy = 7200 * MILLICOIN;
         // Subsidy is cut in half every 4.20.000 blocks which will occur approximately every 8 years.
         {
+            nSubsidy = VeriBlock::getCoinbaseSubsidy(nSubsidy, nHeight, params);
             nSubsidy >>= halvings;
         }
         return nSubsidy;
```
_method ConnectBlock_
```diff
     LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2), MILLI * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);

-    CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, chainparams.GetConsensus()) + GetBlockSubsidyDevs(pindex->nHeight, chainparams.GetConsensus());
-
-    if (block.vtx[0]->GetValueOutInCurrency(0, block.GetPriceinCurrency(0), block.GetPriceinCurrency(2)) > blockReward)//Get value in currency 0
-        return state.DoS(100,
-                         error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
-                               block.vtx[0]->GetValueOutInCurrency(0, block.GetPriceinCurrency(0), block.GetPriceinCurrency(2)), blockReward),
-                               REJECT_INVALID, "bad-cb-amount");
+    assert(pindex->pprev && "previous block ptr is nullptr");
+    if (!VeriBlock::checkCoinbaseTxWithPopRewards(*block.vtx[0], nFees, *pindex, chainparams, state)) {
+        return false;
+    }

     if (!control.Wait())
```

[<font style="color: red"> src/wallet/rpcwallet.cpp </font>]

_method createcoinbaseforaddress_
```diff
     coinbaseTx.vin.resize(1);
     coinbaseTx.vin[0].prevout.SetNull();
     coinbaseTx.vout.resize(2);
-    coinbaseTx.vout[0].nValue = GetBlockSubsidy(nHeight, Params().GetConsensus());
+    coinbaseTx.vout[0].nValue = GetBlockSubsidy(nHeight, Params());

```
_method createcoinbaseforaddresswithpoolfee_
```diff
     coinbaseTx.vin[0].prevout.SetNull();
     coinbaseTx.vout.resize(3);

-    CAmount amount=GetBlockSubsidy(nHeight, Params().GetConsensus());
+    CAmount amount=GetBlockSubsidy(nHeight, Params());
     CAmount poolfee=amount*poolfeepermille/1000;

```
[<font style="color: red"> src/miner.cpp </font>]

_method BlockAssembler::CreateNewBlockWithScriptPubKey_
```diff
     coinbaseTx.vin[0].prevout.SetNull();
     coinbaseTx.vout.resize(2);
     coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
-    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
+    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams);
     coinbaseTx.vout[0].nValueBitCash = coinbaseTx.vout[0].nValue;
```
```diff
     coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;

+    VeriBlock::addPopPayoutsIntoCoinbaseTx(coinbaseTx, *pindexPrev, chainparams);
+
     coinbaseTx.hashashinfo = true;
```
_method BlockAssembler::CreateNewBlock_
```diff
     coinbaseTx.vin[0].prevout.SetNull();
     coinbaseTx.vout.resize(2);

-    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
+    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams);
     coinbaseTx.vout[0].nValueBitCash = coinbaseTx.vout[0].nValue;
```
```diff
         coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
     }

+    VeriBlock::addPopPayoutsIntoCoinbaseTx(coinbaseTx, *pindexPrev, chainparams);
+
     coinbaseTx.hashashinfo = true;
```

### Add tests for the Pop rewards.

[<font style="color: red"> src/vbk/test/unit/pop_reward_tests.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <script/interpreter.h>
#include <vbk/test/util/e2e_fixture.hpp>

struct PopRewardsTestFixture : public E2eFixture {
};

BOOST_AUTO_TEST_SUITE(pop_reward_tests)

BOOST_FIXTURE_TEST_CASE(addPopPayoutsIntoCoinbaseTx_test, PopRewardsTestFixture)
{
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    auto tip = chainActive.Tip();
    BOOST_CHECK(tip != nullptr);
    std::vector<uint8_t> payoutInfo{scriptPubKey.begin(), scriptPubKey.end()};
    CBlock block = endorseAltBlockAndMine(tip->GetBlockHash(), tip->GetBlockHash(), payoutInfo, 0);
    {
        LOCK(cs_main);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
    }

    // Generate a chain whith rewardInterval of blocks
    int rewardInterval = (int)VeriBlock::GetPop().config->alt->getPayoutParams().getPopPayoutDelay();
    // do not add block with rewards
    // do not add block before block with rewards
    for (int i = 0; i < (rewardInterval - 3); i++) {
        CBlock b = CreateAndProcessBlock({}, scriptPubKey);
        m_coinbase_txns.push_back(b.vtx[0]);
    }

    CBlock beforePayoutBlock = CreateAndProcessBlock({}, scriptPubKey);

    int n = 0;
    for (const auto& out : beforePayoutBlock.vtx[0]->vout) {
        if (out.nValue > 0) n++;
    }
    BOOST_CHECK(n == 2);

    CBlock payoutBlock = CreateAndProcessBlock({}, scriptPubKey);
    n = 0;
    for (const auto& out : payoutBlock.vtx[0]->vout) {
        if (out.nValue > 0) n++;
    }

    // we've got additional coinbase out
    BOOST_CHECK(n > 2);

    // assume POP reward is the output after the POW and DevFund reward
    BOOST_CHECK(payoutBlock.vtx[0]->vout[2].scriptPubKey == scriptPubKey);
    BOOST_CHECK(payoutBlock.vtx[0]->vout[2].nValue > 0);

    CMutableTransaction spending;
    spending.nVersion = 6;
    spending.vin.resize(1);
    spending.vin[0].prevout.hash = payoutBlock.vtx[0]->GetHash();
    // use POP payout as an input
    spending.vin[0].prevout.n = 2;
    spending.vout.resize(1);
    spending.vout[0].nValue = 100;
    spending.vout[0].nValueBitCash = 100;
    spending.vout[0].scriptPubKey = scriptPubKey;

    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(scriptPubKey, spending, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
    vchSig.push_back((unsigned char)SIGHASH_ALL);
    spending.vin[0].scriptSig << vchSig;

    CBlock spendingBlock;
    // make sure we cannot spend till coinbase maturity
    spendingBlock = CreateAndProcessBlock({spending}, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() != spendingBlock.GetHash());
    }

    for (int i = 0; i < COINBASE_MATURITY; i++) {
        CBlock b = CreateAndProcessBlock({}, scriptPubKey);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == b.GetHash());
        m_coinbase_txns.push_back(b.vtx[0]);
    }

    spendingBlock = CreateAndProcessBlock({spending}, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == spendingBlock.GetHash());
    }
}

BOOST_AUTO_TEST_SUITE_END()
```

### Update makefile to run tests.

[<font style="color: red"> src/Makefile.test.include </font>]
```diff
 VBK_TESTS =\
   vbk/test/unit/e2e_poptx_tests.cpp \
   vbk/test/unit/block_validation_tests.cpp \
-  vbk/test/unit/vbk_merkle_tests.cpp
+  vbk/test/unit/vbk_merkle_tests.cpp \
+  vbk/test/unit/pop_reward_tests.cpp

 # test_bitcash binary #
```

## Add VeriBlock Pop fork resolution.

### Add some refactoring and fix block generation to avoid duplicates.

[<font style="color: red"> src/vbk/util.hpp </font>]
```diff
+//PopData weight
+inline int64_t GetPopDataWeight(const altintegration::PopData& pop_data)
+{
+    return ::GetSerializeSize(pop_data, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(pop_data, PROTOCOL_VERSION);
+}
+
 } // namespace VeriBlock
```
[<font style="color: red"> src/vbk/test/util/e2e_fixture.hpp </font>]

_struct E2eFixture_
```diff
     void InvalidateTestBlock(CBlockIndex* pblock)
     {
         CValidationState state;
-        InvalidateBlock(state, Params(), pblock);
+        {
+            LOCK(cs_main);
+            InvalidateBlock(state, Params(), pblock);
+        }
         ActivateBestChain(state, Params());
```
[<font style="color: red"> src/validation.cpp </font>]

_method CChainState::DisconnectBlock_
```diff
     // move best block pointer to prevout block
-    view.SetBestBlock(pindex->pprev->GetBlockHash());
+    view.SetBestBlock(prevHash);

     return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
```
_method CheckBlock_
```diff
     // checks that use witness data may be performed here.

     // Size limits
-    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
+    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || GetBlockWeight(block) > MAX_BLOCK_WEIGHT)
         return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");
```
[<font style="color: red"> src/test/test_bitcash.h </font>]

_struct TestChain100Setup_
```diff
     std::vector<CTransactionRef> m_coinbase_txns; // For convenience, coinbase transactions
     CKey coinbaseKey; // private/public key needed to spend coinbase transactions
+    // VeriBlock: make nonce global to avoid duplicate block hashes
+    unsigned int extraNonce = 0;
 };

```
[<font style="color: red"> src/test/test_bitcash.cpp </font>]
```diff
 #include <rpc/register.h>
 #include <script/sigcache.h>
+#include <vbk/merkle.hpp>
 #include <vbk/params.hpp>
 #include <vbk/pop_service.hpp>
```
```diff
+static void IncrementExtraNonceTest(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
+{
+    ++nExtraNonce;
+    unsigned int nHeight = pindexPrev->nHeight + 1; // Height first in coinbase required for block.version=2
+    CMutableTransaction txCoinbase(*pblock->vtx[0]);
+    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
+    assert(txCoinbase.vin[0].scriptSig.size() <= 100);
+
+    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
+    pblock->hashMerkleRoot = VeriBlock::TopLevelMerkleRoot(pindexPrev, *pblock);
+}
+
 //
```
_method TestChain100Setup::CreateAndProcessBlock_
```diff
     // IncrementExtraNonce creates a valid coinbase and merkleRoot
     {
         LOCK(cs_main);
-        unsigned int extraNonce = 0;
-        IncrementExtraNonce(&block, pPrev, extraNonce);
+        IncrementExtraNonceTest(&block, pPrev, extraNonce);
     }
     while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())) ++block.nNonce;
```
[<font style="color: red"> src/consensus/validation.h </font>]
```diff
 #include <primitives/transaction.h>
 #include <primitives/block.h>
+#include <vbk/util.hpp>

 /** "reject" message codes */
```
```diff
 static inline int64_t GetBlockWeight(const CBlock& block)
 {
-    return ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
+    int64_t popDataSize = 0;
+    popDataSize += VeriBlock::GetPopDataWeight(block.popData);
+    return ::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, PROTOCOL_VERSION) - popDataSize;
 }
 static inline int64_t GetTransactionInputWeight(const CTxIn& txin)
```

### Add fork resolution unit test. Parts of the test are commented out due to the block revalidation bug and not implemented POP fork resolution.

[<font style="color: red"> src/vbk/test/unit/forkresolution_tests.cpp </font>]
```
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

//TODO: uncomment when block revalidation is fixed
/*BOOST_FIXTURE_TEST_CASE(crossing_keystone_case_2_test, E2eFixture)
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
}*/

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

//TODO: uncomment when POP fork resolution is done
/*BOOST_FIXTURE_TEST_CASE(crossing_keystone_with_pop_1_test, E2eFixture)
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
}*/

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
```

### Update makefile to run tests.

[<font style="color: red"> src/Makefile.test.include </font>]
```diff
VBK_TESTS =\
   vbk/test/unit/e2e_poptx_tests.cpp \
   vbk/test/unit/block_validation_tests.cpp \
   vbk/test/unit/vbk_merkle_tests.cpp \
-  vbk/test/unit/pop_reward_tests.cpp
+  vbk/test/unit/pop_reward_tests.cpp \
+  vbk/test/unit/forkresolution_tests.cpp
```

## Update P2P protocol.

### Small refactoring for better validation result management.

[<font style="color: red"> src/consensus/validation.h </font>]
```diff
     std::string GetRejectReason() const { return strRejectReason; }
     std::string GetDebugMessage() const { return strDebugMessage; }
+
+    // VeriBlock: helpers
+    std::string ToString() const {return strRejectReason + ": " + strDebugMessage; }
+
+    operator altintegration::ValidationState() {
+        altintegration::ValidationState v;
+        if(IsInvalid()) {
+            v.Invalid(strRejectReason, strDebugMessage);
+            return v;
+        }
+
+        if(IsError()) {
+            v.Invalid(strRejectReason);
+            return v;
+        }
+
+        return v;
+    }
 };
```

### Add P2P service files: p2p_sync.hpp, p2p_sync.cpp.

[<font style="color: red"> src/vbk/p2p_sync.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_P2P_SYNC_HPP
#define BITCASH_SRC_VBK_P2P_SYNC_HPP

#include <chainparams.h>
#include <map>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <rpc/blockchain.h>
#include <validation.h>
#include <vbk/pop_common.hpp>
#include <veriblock/mempool.hpp>

namespace VeriBlock {

namespace p2p {

struct PopP2PState {
    uint32_t known_pop_data{0};
    uint32_t offered_pop_data{0};
    uint32_t requested_pop_data{0};
};

// The state of the Node that stores already known Pop Data
struct PopDataNodeState {
    // we use map to store DDoS prevention counter as a value in the map
    std::map<altintegration::ATV::id_t, PopP2PState> atv_state{};
    std::map<altintegration::VTB::id_t, PopP2PState> vtb_state{};
    std::map<altintegration::VbkBlock::id_t, PopP2PState> vbk_blocks_state{};

    template <typename T>
    std::map<typename T::id_t, PopP2PState>& getMap();
};

PopDataNodeState& getPopDataNodeState(const NodeId& id);

void erasePopDataNodeState(const NodeId& id);

} // namespace p2p

} // namespace VeriBlock


namespace VeriBlock {

namespace p2p {

const static std::string get_prefix = "g";
const static std::string offer_prefix = "of";

const static uint32_t MAX_POP_DATA_SENDING_AMOUNT = 100;
const static uint32_t MAX_POP_MESSAGE_SENDING_COUNT = 30;

template <typename pop_t>
void offerPopDataToAllNodes(const pop_t& p)
{
    std::vector<std::vector<uint8_t>> p_id = {p.getId().asVector()};
    CConnman* connman = g_connman.get();
    const CNetMsgMaker msgMaker(PROTOCOL_VERSION);

    connman->ForEachNode([&connman, &msgMaker, &p_id](CNode* node) {
        LOCK(cs_main);

        auto& pop_state_map = getPopDataNodeState(node->GetId()).getMap<pop_t>();
        PopP2PState& pop_state = pop_state_map[p_id[0]];
        if (pop_state.offered_pop_data == 0) {
            ++pop_state.offered_pop_data;
            connman->PushMessage(node, msgMaker.Make(offer_prefix + pop_t::name(), p_id));
        }
    });
}


template <typename PopDataType>
void offerPopData(CNode* node, CConnman* connman, const CNetMsgMaker& msgMaker) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    auto& pop_state_map = getPopDataNodeState(node->GetId()).getMap<PopDataType>();
    auto& pop_mempool = *VeriBlock::GetPop().mempool;
    std::vector<std::vector<uint8_t>> hashes;

    auto addhashes = [&](const std::unordered_map<typename PopDataType::id_t, std::shared_ptr<PopDataType>>& map) {
        for (const auto& el : map) {
            PopP2PState& pop_state = pop_state_map[el.first];
            if (pop_state.offered_pop_data == 0 && pop_state.known_pop_data == 0) {
                ++pop_state.offered_pop_data;
                hashes.push_back(el.first.asVector());
            }

            if (hashes.size() == MAX_POP_DATA_SENDING_AMOUNT) {
                connman->PushMessage(node, msgMaker.Make(offer_prefix + PopDataType::name(), hashes));
                hashes.clear();
            }
        }
    };

    addhashes(pop_mempool.getMap<PopDataType>());
    addhashes(pop_mempool.getInFlightMap<PopDataType>());

    if (!hashes.empty()) {
        connman->PushMessage(node, msgMaker.Make(offer_prefix + PopDataType::name(), hashes));
    }
}

int processPopData(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman);

} // namespace p2p
} // namespace VeriBlock


#endif
```
[<font style="color: red"> src/vbk/p2p_sync.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "vbk/p2p_sync.hpp"
#include "validation.h"
#include <veriblock/entities/atv.hpp>
#include <veriblock/entities/vbkblock.hpp>
#include <veriblock/entities/vtb.hpp>

namespace VeriBlock {
namespace p2p {

static std::map<NodeId, std::shared_ptr<PopDataNodeState>> mapPopDataNodeState;

template <>
std::map<altintegration::ATV::id_t, PopP2PState>& PopDataNodeState::getMap<altintegration::ATV>()
{
    return atv_state;
}

template <>
std::map<altintegration::VTB::id_t, PopP2PState>& PopDataNodeState::getMap<altintegration::VTB>()
{
    return vtb_state;
}

template <>
std::map<altintegration::VbkBlock::id_t, PopP2PState>& PopDataNodeState::getMap<altintegration::VbkBlock>()
{
    return vbk_blocks_state;
}

PopDataNodeState& getPopDataNodeState(const NodeId& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    std::shared_ptr<PopDataNodeState>& val = mapPopDataNodeState[id];
    if (val == nullptr) {
        mapPopDataNodeState[id] = std::make_shared<PopDataNodeState>();
        val = mapPopDataNodeState[id];
    }
    return *val;
}

void erasePopDataNodeState(const NodeId& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    mapPopDataNodeState.erase(id);
}

template <typename pop_t>
bool processGetPopData(CNode* node, CConnman* connman, CDataStream& vRecv, altintegration::MemPool& pop_mempool) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    std::vector<std::vector<uint8_t>> requested_data;
    vRecv >> requested_data;

    if (requested_data.size() > MAX_POP_DATA_SENDING_AMOUNT) {
        LogPrint(BCLog::NET, "peer %d send oversized message getdata size() = %u \n", node->GetId(), requested_data.size());
        Misbehaving(node->GetId(), 20, strprintf("message getdata size() = %u", requested_data.size()));
        return false;
    }

    auto& pop_state_map = getPopDataNodeState(node->GetId()).getMap<pop_t>();

    const CNetMsgMaker msgMaker(PROTOCOL_VERSION);
    for (const auto& data_hash : requested_data) {
        PopP2PState& pop_state = pop_state_map[data_hash];
        uint32_t ddosPreventionCounter = pop_state.known_pop_data++;

        if (ddosPreventionCounter > MAX_POP_MESSAGE_SENDING_COUNT) {
            LogPrint(BCLog::NET, "peer %d is spamming pop data %s \n", node->GetId(), pop_t::name());
            Misbehaving(node->GetId(), 20, strprintf("peer %d is spamming pop data %s", node->GetId(), pop_t::name()));
            return false;
        }

        const auto* data = pop_mempool.get<pop_t>(data_hash);
        if (data != nullptr) {
            connman->PushMessage(node, msgMaker.Make(pop_t::name(), *data));
        }
    }

    return true;
}

template <typename pop_t>
bool processOfferPopData(CNode* node, CConnman* connman, CDataStream& vRecv, altintegration::MemPool& pop_mempool) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    LogPrint(BCLog::NET, "received offered pop data: %s, bytes size: %d\n", pop_t::name(), vRecv.size());

    // do not process 'offers' during initial block download
    if (IsInitialBlockDownload()) {
        // TODO: may want to keep a list of offered payloads, then filter all existing (on-chain) payloadsm and 'GET' others
        return true;
    }

    std::vector<std::vector<uint8_t>> offered_data;
    vRecv >> offered_data;

    if (offered_data.size() > MAX_POP_DATA_SENDING_AMOUNT) {
        LogPrint(BCLog::NET, "peer %d sent oversized message getdata size() = %u \n", node->GetId(), offered_data.size());
        Misbehaving(node->GetId(), 20, strprintf("message getdata size() = %u", offered_data.size()));
        return false;
    }

    auto& pop_state_map = getPopDataNodeState(node->GetId()).getMap<pop_t>();

    std::vector<std::vector<uint8_t>> requested_data;
    const CNetMsgMaker msgMaker(PROTOCOL_VERSION);
    for (const auto& data_hash : offered_data) {
        PopP2PState& pop_state = pop_state_map[data_hash];
        uint32_t ddosPreventionCounter = pop_state.requested_pop_data++;

        if (!pop_mempool.get<pop_t>(data_hash)) {
            requested_data.push_back(data_hash);
        } else if (ddosPreventionCounter > MAX_POP_MESSAGE_SENDING_COUNT) {
            LogPrint(BCLog::NET, "peer %d is spamming pop data %s \n", node->GetId(), pop_t::name());
            Misbehaving(node->GetId(), 20, strprintf("peer %d is spamming pop data %s", node->GetId(), pop_t::name()));
            return false;
        }
    }

    if (!requested_data.empty()) {
        connman->PushMessage(node, msgMaker.Make(get_prefix + pop_t::name(), requested_data));
    }

    return true;
}

template <typename pop_t>
bool processPopData(CNode* node, CDataStream& vRecv, altintegration::MemPool& pop_mempool) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    LogPrint(BCLog::NET, "received pop data: %s, bytes size: %d\n", pop_t::name(), vRecv.size());
    pop_t data;
    vRecv >> data;

    auto& pop_state_map = getPopDataNodeState(node->GetId()).getMap<pop_t>();
    PopP2PState& pop_state = pop_state_map[data.getId()];

    if (pop_state.requested_pop_data == 0) {
        LogPrint(BCLog::NET, "peer %d send pop data %s that has not been requested \n", node->GetId(), pop_t::name());
        Misbehaving(node->GetId(), 20, strprintf("peer %d send pop data %s that has not been requested", node->GetId(), pop_t::name()));
        return false;
    }

    uint32_t ddosPreventionCounter = pop_state.requested_pop_data++;

    if (ddosPreventionCounter > MAX_POP_MESSAGE_SENDING_COUNT) {
        LogPrint(BCLog::NET, "peer %d is spaming pop data %s\n", node->GetId(), pop_t::name());
        Misbehaving(node->GetId(), 20, strprintf("peer %d is spamming pop data %s", node->GetId(), pop_t::name()));
        return false;
    }

    altintegration::ValidationState state;
    auto result = pop_mempool.submit(data, state);
    if (!result && result.status == altintegration::MemPool::FAILED_STATELESS) {
        LogPrint(BCLog::NET, "peer %d sent statelessly invalid pop data: %s\n", node->GetId(), state.toString());
        Misbehaving(node->GetId(), 20, strprintf("statelessly invalid pop data getdata, reason: %s", state.toString()));
        return false;
    }

    return true;
}

int processPopData(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman)
{
    auto& pop_mempool = *VeriBlock::GetPop().mempool;

    // process Pop Data
    if (strCommand == altintegration::ATV::name()) {
        LOCK(cs_main);
        return processPopData<altintegration::ATV>(pfrom, vRecv, pop_mempool);
    }

    if (strCommand == altintegration::VTB::name()) {
        LOCK(cs_main);
        return processPopData<altintegration::VTB>(pfrom, vRecv, pop_mempool);
    }

    if (strCommand == altintegration::VbkBlock::name()) {
        LOCK(cs_main);
        return processPopData<altintegration::VbkBlock>(pfrom, vRecv, pop_mempool);
    }
    //----------------------

    // offer Pop Data
    if (strCommand == offer_prefix + altintegration::ATV::name()) {
        LOCK(cs_main);
        return processOfferPopData<altintegration::ATV>(pfrom, connman, vRecv, pop_mempool);
    }

    if (strCommand == offer_prefix + altintegration::VTB::name()) {
        LOCK(cs_main);
        return processOfferPopData<altintegration::VTB>(pfrom, connman, vRecv, pop_mempool);
    }

    if (strCommand == offer_prefix + altintegration::VbkBlock::name()) {
        LOCK(cs_main);
        return processOfferPopData<altintegration::VbkBlock>(pfrom, connman, vRecv, pop_mempool);
    }
    //-----------------

    // get Pop Data
    if (strCommand == get_prefix + altintegration::ATV::name()) {
        LOCK(cs_main);
        return processGetPopData<altintegration::ATV>(pfrom, connman, vRecv, pop_mempool);
    }

    if (strCommand == get_prefix + altintegration::VTB::name()) {
        LOCK(cs_main);
        return processGetPopData<altintegration::VTB>(pfrom, connman, vRecv, pop_mempool);
    }

    if (strCommand == get_prefix + altintegration::VbkBlock::name()) {
        LOCK(cs_main);
        return processGetPopData<altintegration::VbkBlock>(pfrom, connman, vRecv, pop_mempool);
    }

    return -1;
}


} // namespace p2p

} // namespace VeriBlock
```

### Allow node to download chain with less chainWork.

[<font style="color: red"> src/version.h </font>]
```diff
  * network protocol versioning
  */

-static const int PROTOCOL_VERSION = 70015;
+static const int PROTOCOL_VERSION = 80000;
```
```diff
 static const int INVALID_CB_NO_BAN_VERSION = 70015;

+//! VeriBlock: ping p2p msg contains 'best chain'
+static const int PING_BESTCHAIN_VERSION = 80000;
+
```

[<font style="color: red"> src/net_processing.cpp </font>]
```diff
 #include <utilmoneystr.h>
 #include <utilstrencodings.h>
+#include <vbk/p2p_sync.hpp>
```
_struct CNodeState_
```diff
     bool fPreferHeaders;
     //! Whether this peer wants invs or cmpctblocks (when possible) for block announcements.
     bool fPreferHeaderAndIDs;
+
+    //! VeriBlock: The block this peer thinks is current tip.
+    const CBlockIndex *pindexLastAnnouncedBlock = nullptr;
+    //! VeriBlock: The last full block we both have from announced chain.
+    const CBlockIndex *pindexLastCommonAnnouncedBlock = nullptr;
+
```
```diff
+// VeriBlock
+/** Update tracking information about which a tip a peer is assumed to have. */
+static void UpdateBestChainTip(NodeId nodeid, const uint256 &tip) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
+    CNodeState *state = State(nodeid);
+    assert(state != nullptr);
+
+    const CBlockIndex* pindex = LookupBlockIndex(tip);
+    if (pindex && pindex->nChainWork > 0) {
+        state->pindexLastAnnouncedBlock = pindex;
+        LogPrint(BCLog::NET, "peer=%s: announced best chain %s\n", nodeid, tip.GetHex());
+
+        // announced block is better by chainwork. update pindexBestKnownBlock
+        if(state->pindexBestKnownBlock == nullptr || pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork) {
+            state->pindexBestKnownBlock = pindex;
+        }
+    }
+
+    ProcessBlockAvailability(nodeid);
+}
+
```
```diff
 /** Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks, until it has
  *  at most count entries. */
-static void FindNextBlocksToDownload(NodeId nodeid, unsigned int count, std::vector<const CBlockIndex*>& vBlocks, NodeId& nodeStaller, const Consensus::Params& consensusParams) {
+static void FindNextBlocksToDownload(NodeId nodeid, unsigned int count, std::vector<const CBlockIndex*>& vBlocks, NodeId& nodeStaller, const Consensus::Params& consensusParams,
+    // either pindexBestBlock or pindexLastAnouncedBlock
+    const CBlockIndex* bestBlock,
+    // out parameter: sets last common block
+    const CBlockIndex** lastCommonBlockOut) {
     if (count == 0)
         return;

     vBlocks.reserve(vBlocks.size() + count);
-    CNodeState *state = State(nodeid);
-    assert(state != nullptr);
-
-    // Make sure pindexBestKnownBlock is up to date, we'll need it.
-    ProcessBlockAvailability(nodeid);

-    if (state->pindexBestKnownBlock == nullptr || state->pindexBestKnownBlock->nChainWork < chainActive.Tip()->nChainWork || state->pindexBestKnownBlock->nChainWork < nMinimumChainWork) {
+    if (bestBlock == nullptr || bestBlock->nChainWork < nMinimumChainWork) {
         // This peer has nothing interesting.
         return;
     }

-    if (state->pindexLastCommonBlock == nullptr) {
+    assert(lastCommonBlockOut);
+
+    if (*lastCommonBlockOut == nullptr) {
         // Bootstrap quickly by guessing a parent of our best tip is the forking point.
         // Guessing wrong in either direction is not a problem.
-        state->pindexLastCommonBlock = chainActive[std::min(state->pindexBestKnownBlock->nHeight, chainActive.Height())];
+        *lastCommonBlockOut = chainActive[std::min(bestBlock->nHeight, chainActive.Height())];
     }

     // If the peer reorganized, our previous pindexLastCommonBlock may not be an ancestor
     // of its current tip anymore. Go back enough to fix that.
-    state->pindexLastCommonBlock = LastCommonAncestor(state->pindexLastCommonBlock, state->pindexBestKnownBlock);
-    if (state->pindexLastCommonBlock == state->pindexBestKnownBlock)
+    *lastCommonBlockOut = LastCommonAncestor(*lastCommonBlockOut, bestBlock);
+    if (*lastCommonBlockOut == bestBlock)
         return;

     std::vector<const CBlockIndex*> vToFetch;
-    const CBlockIndex *pindexWalk = state->pindexLastCommonBlock;
+    const CBlockIndex *pindexWalk = *lastCommonBlockOut;
     // Never fetch further than the best block we know the peer has, or more than BLOCK_DOWNLOAD_WINDOW + 1 beyond the last
     // linked block we have in common with this peer. The +1 is so we can detect stalling, namely if we would be able to
     // download that next block if the window were 1 larger.
-    int nWindowEnd = state->pindexLastCommonBlock->nHeight + BLOCK_DOWNLOAD_WINDOW;
-    int nMaxHeight = std::min<int>(state->pindexBestKnownBlock->nHeight, nWindowEnd + 1);
+    int nWindowEnd = (*lastCommonBlockOut)->nHeight + BLOCK_DOWNLOAD_WINDOW;
+    int nMaxHeight = std::min<int>(bestBlock->nHeight, nWindowEnd + 1);
     NodeId waitingfor = -1;
     while (pindexWalk->nHeight < nMaxHeight) {
```
_method FindNextBlocksToDownload_
```diff
         int nToFetch = std::min(nMaxHeight - pindexWalk->nHeight, std::max<int>(count - vBlocks.size(), 128));
         vToFetch.resize(nToFetch);
-        pindexWalk = state->pindexBestKnownBlock->GetAncestor(pindexWalk->nHeight + nToFetch);
+        pindexWalk = bestBlock->GetAncestor(pindexWalk->nHeight + nToFetch);
         vToFetch[nToFetch - 1] = pindexWalk;
```
```diff
             if (pindex->nStatus & BLOCK_HAVE_DATA || chainActive.Contains(pindex)) {
                 if (pindex->nChainTx)
-                    state->pindexLastCommonBlock = pindex;
+                    *lastCommonBlockOut = pindex;
             } else if (mapBlocksInFlight.count(pindex->GetBlockHash()) == 0) {
```
_method PeerLogicValidation::FinalizeNode_
```diff
     assert(g_outbound_peers_with_protect_from_disconnect >= 0);

     mapNodeState.erase(nodeid);
+    // VeriBlock
+    VeriBlock::p2p::erasePopDataNodeState(nodeid);

     if (mapNodeState.empty()) {
```
_method ProcessHeadersMessage_
```diff
         // If this set of headers is valid and ends in a block with at least as
         // much work as our tip, download as much as possible.
-        if (fCanDirectFetch && pindexLast->IsValid(BLOCK_VALID_TREE) && chainActive.Tip()->nChainWork <= pindexLast->nChainWork) {
+        if (fCanDirectFetch && pindexLast->IsValid(BLOCK_VALID_TREE)
+            // VeriBlock: download the chain suggested by the peer
+            /*&& chainActive.Tip()->nChainWork <= pindexLast->nChainWork*/) {
             std::vector<const CBlockIndex*> vToFetch;
             const CBlockIndex *pindexWalk = pindexLast;
```
_method ProcessMessage_
```diff
     }

+    // VeriBlock: if POP is not enabled, ignore POP-related P2P calls
+    int tipHeight = chainActive.Height();
+    if (Params().isPopActive(tipHeight)) {
+        int pop_res = VeriBlock::p2p::processPopData(pfrom, strCommand, vRecv, connman);
+        if (pop_res >= 0) {
+            return pop_res;
+        }
+    }
+

     if (!(pfrom->GetLocalServices() & NODE_BLOOM) &&
```
```diff
             uint64_t nonce = 0;
             vRecv >> nonce;
+
+            if(pfrom->nVersion > PING_BESTCHAIN_VERSION) {
+                // VeriBlock: immediately after nonce, receive best block hash
+                LOCK(cs_main);
+                uint256 bestHash;
+                vRecv >> bestHash;
+                UpdateBestChainTip(pfrom->GetId(), bestHash);
+
+                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::PONG, nonce, chainActive.Tip()->GetBlockHash()));
+                return true;
+            }
+
             // Echo the message back with the nonce. This allows for two useful features:
```
```diff
                     }
                 }
+                // VeriBlock
+                if(pfrom->nVersion > PING_BESTCHAIN_VERSION) {
+                    LOCK(cs_main);
+                    uint256 bestHash;
+                    vRecv >> bestHash;
+                    UpdateBestChainTip(pfrom->GetId(), bestHash);
+                }
             } else {
                 sProblem = "Unsolicited pong without ping";
             }
```
_method PeerLogicValidation::SendMessages_
```diff
             if (pto->nVersion > BIP0031_VERSION) {
                 pto->nPingNonceSent = nonce;
-                connman->PushMessage(pto, msgMaker.Make(NetMsgType::PING, nonce));
+                if(pto->nVersion > PING_BESTCHAIN_VERSION) {
+                    connman->PushMessage(pto, msgMaker.Make(NetMsgType::PING, nonce, chainActive.Tip()->GetBlockHash()));
+                } else {
+                    connman->PushMessage(pto, msgMaker.Make(NetMsgType::PING, nonce));
+                }
             } else {
                 // Peer is too old to support ping command with nonce, pong will never arrive.
                 pto->nPingNonceSent = 0;
```
```diff
         if (!vInv.empty())
             connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));

+        // VeriBlock offer Pop Data
+        {
+            VeriBlock::p2p::offerPopData<altintegration::ATV>(pto, connman, msgMaker);
+            VeriBlock::p2p::offerPopData<altintegration::VTB>(pto, connman, msgMaker);
+            VeriBlock::p2p::offerPopData<altintegration::VbkBlock>(pto, connman, msgMaker);
+        }
+
         // Detect whether we're stalling
         nNow = GetTimeMicros();
```
```diff
             std::vector<const CBlockIndex*> vToDownload;
             NodeId staller = -1;
-            FindNextBlocksToDownload(pto->GetId(), MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.nBlocksInFlight, vToDownload, staller, consensusParams);
+            // VeriBlock: find "blocks to download" in 2 chains: one that has "best chainwork", and second that is reported by peer as best.
+            ProcessBlockAvailability(pto->GetId());
+            // always download chain with higher chainwork
+            if(state.pindexBestKnownBlock) {
+                FindNextBlocksToDownload(pto->GetId(), MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.nBlocksInFlight, vToDownload, staller, consensusParams, state.pindexBestKnownBlock, &state.pindexLastCommonBlock);
+            }
+            // should we fetch announced chain?
+            if(state.pindexLastAnnouncedBlock && state.pindexBestKnownBlock) {
+                // last announced block is by definition always <= chainwork than best known block by chainwork
+                assert(state.pindexLastAnnouncedBlock->nChainWork <= state.pindexBestKnownBlock->nChainWork);
+
+                // are they in the same chain?
+                if (state.pindexBestKnownBlock->GetAncestor(state.pindexLastAnnouncedBlock->nHeight) != state.pindexLastAnnouncedBlock) {
+                    // no, additionally sync 'announced' chain
+                    LogPrint(BCLog::NET, "Requesting announced best chain %d:%s from peer=%d\n", state.pindexLastAnnouncedBlock->GetBlockHash().ToString(),
+                        state.pindexLastAnnouncedBlock->nHeight, pto->GetId());
+                    FindNextBlocksToDownload(pto->GetId(), MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.nBlocksInFlight, vToDownload, staller, consensusParams, state.pindexLastAnnouncedBlock, &state.pindexLastCommonAnnouncedBlock);
+                }
+            }
             for (const CBlockIndex *pindex : vToDownload) {
                 uint32_t nFetchFlags = GetFetchFlags(pto);
```

### Subscribe the library to the mempool events.

[<font style="color: red"> src/vbk/pop_service.cpp </font>]
```diff
 #include <vbk/adaptors/block_provider.hpp>
+#include <vbk/p2p_sync.hpp>
 #include <vbk/pop_common.hpp>
 #include <vbk/pop_service.hpp>
```
_method InitPopContext_
```diff
     SetPop(payloads_provider);
+
+    auto& app = GetPop();
+    app.mempool->onAccepted<altintegration::ATV>(VeriBlock::p2p::offerPopDataToAllNodes<altintegration::ATV>);
+    app.mempool->onAccepted<altintegration::VTB>(VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VTB>);
+    app.mempool->onAccepted<altintegration::VbkBlock>(VeriBlock::p2p::offerPopDataToAllNodes<altintegration::VbkBlock>);
 }
```

### Add P2P service to the makefile.

[<font style="color: red"> src/Makefile.am </font>]
```diff
libbitcash_server_a_SOURCES = \
   vbk/params.cpp \
   rest.cpp \
   stratum.cpp \
+  vbk/p2p_sync.hpp \
+  vbk/p2p_sync.cpp \
   rpc/blockchain.cpp \
```

## Add VeriBlock specific RPC methods.

Main parts of the POP protocol have been implemented. We'll provide POP related interaction with the BitCash node. We'll add new functions to the RPC.

### Add new rpc_registry.hpp/cpp source files.

[<font style="color: red"> src/vbk/rpc_register.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCASH_SRC_VBK_RPC_REGISTER_HPP
#define BITCASH_SRC_VBK_RPC_REGISTER_HPP

class CRPCTable;

namespace VeriBlock {

void RegisterPOPMiningRPCCommands(CRPCTable& t);

} // namespace VeriBlock

#endif //BITCASH_SRC_VBK_RPC_REGISTER_HPP
```
[<font style="color: red"> src/vbk/rpc_register.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <validation.h>
#include <vbk/p2p_sync.hpp>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h> // for CWallet

#include <fstream>
#include <set>

#include "rpc_register.hpp"
#include <vbk/merkle.hpp>
#include <vbk/pop_service.hpp>
#include <veriblock/mempool_result.hpp>

namespace VeriBlock {

namespace {

void EnsurePopEnabled()
{
    auto tipheight = chainActive.Height();
    if (!Params().isPopActive(tipheight)) {
        throw JSONRPCError(RPC_MISC_ERROR,
            strprintf("POP protocol is not active. Current=%d, activation height=%d",
                tipheight,
                Params().GetConsensus().VeriBlockPopSecurityHeight)

        );
    }
}

CBlock GetBlockChecked(const CBlockIndex* pblockindex)
{
    CBlock block;
    if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
    {
        throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");
    }

    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
        // Block not found on disk. This could be because we have the block
        // header in our index but don't have the block (for example if a
        // non-whitelisted node sends us an unrequested long chain of valid
        // blocks, we add the headers to our index, but don't accept the
        // block).
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return block;
}

} // namespace

// getpopdata
namespace {

UniValue getpopdata(const CBlockIndex* index)
{
    if (!index) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    UniValue result(UniValue::VOBJ);

    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
    ssBlock << index->GetBlockHeader();
    result.pushKV("block_header", HexStr(ssBlock));

    auto block = GetBlockChecked(index);

    auto txRoot = BlockMerkleRoot(block).asVector();
    using altintegration::AuthenticatedContextInfoContainer;
    auto authctx = AuthenticatedContextInfoContainer::createFromPrevious(
        txRoot,
        block.popData.getMerkleRoot(),
        // we build authctx based on previous block
        VeriBlock::GetAltBlockIndex(index->pprev),
        VeriBlock::GetPop().config->getAltParams());
    result.pushKV("authenticated_context", altintegration::ToJSON<UniValue>(authctx));

    auto lastVBKBlocks = VeriBlock::getLastKnownVBKBlocks(16);
    UniValue univalueLastVBKBlocks(UniValue::VARR);
    for (const auto& b : lastVBKBlocks) {
        univalueLastVBKBlocks.push_back(HexStr(b));
    }
    result.pushKV("last_known_veriblock_blocks", univalueLastVBKBlocks);

    auto lastBTCBlocks = VeriBlock::getLastKnownBTCBlocks(16);
    UniValue univalueLastBTCBlocks(UniValue::VARR);
    for (const auto& b : lastBTCBlocks) {
        univalueLastBTCBlocks.push_back(HexStr(b));
    }
    result.pushKV("last_known_bitcoin_blocks", univalueLastBTCBlocks);

    return result;
}

UniValue getpopdatabyheight(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getpopdatabyheight block_height\n"
            "\nFetches the data relevant to PoP-mining the given block.\n"
            "\nArguments:\n"
            "1. block_height         (numeric, required) Endorsed block height from active chain\n"
            "\nResult:\n"
            "TODO: write docs\n"
            "\nExamples:\n" +
            HelpExampleCli("getpopdatabyheight", "1000") + HelpExampleRpc("getpopdatabyheight", "1000"));

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    int height = request.params[0].get_int();

    LOCK(cs_main);
    return getpopdata(chainActive[height]);
}

UniValue getpopdatabyhash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getpopdatabyhash block_height\n"
            "\nFetches the data relevant to PoP-mining the given block.\n"
            "\nArguments:\n"
            "1. hash         (string, required) Endorsed block hash.\n"
            "\nResult:\n"
            "TODO: write docs\n"
            "\nExamples:\n" +
            HelpExampleCli("getpopdatabyhash", "xxx") + HelpExampleRpc("getpopdatabyhash", "xxx"));

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::string hex = request.params[0].get_str();
    LOCK(cs_main);

    const auto hash = uint256S(hex);
    return getpopdata(LookupBlockIndex(hash));
}

} // namespace

template <typename pop_t>
bool parsePayloads(const UniValue& array, std::vector<pop_t>& out, altintegration::ValidationState& state)
{
    std::vector<pop_t> payloads;
    for (uint32_t idx = 0u, size = array.size(); idx < size; ++idx) {
        auto& payloads_hex = array[idx];

        auto payloads_bytes = ParseHexV(payloads_hex, strprintf("%s[%d]", pop_t::name(), idx));

        pop_t data;
        altintegration::ReadStream stream(payloads_bytes);
        if (!altintegration::DeserializeFromVbkEncoding(stream, data, state)) {
            return state.Invalid("bad-payloads");
        }
        payloads.push_back(data);
    }

    out = payloads;
    return true;
}

template <typename T>
static void logSubmitResult(const std::string idhex, const altintegration::MemPool::SubmitResult& result, const altintegration::ValidationState& state)
{
    if (!result.isAccepted()) {
        LogPrintf("rejected to add %s=%s to POP mempool: %s\n", T::name(), idhex, state.toString());
    } else {
        auto s = strprintf("(state: %s)", state.toString());
        LogPrintf("accepted %s=%s to POP mempool %s\n", T::name(), idhex, (state.IsValid() ? "" : s));
    }
}

using VbkTree = altintegration::VbkBlockTree;
using BtcTree = altintegration::VbkBlockTree::BtcTree;

static VbkTree& vbk()
{
    return VeriBlock::GetPop().altTree->vbk();
}

static BtcTree& btc()
{
    return VeriBlock::GetPop().altTree->btc();
}

// submitpop
namespace {
void check_submitpop(const JSONRPCRequest& request, const std::string& popdata)
{
    auto cmdname = strprintf("submitpop%s", popdata);
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            cmdname + "\n"
            "\nSubmit " + popdata + "\n"
            "\nArguments:\n"
            "1. data         (string, required) hex serialized " + popdata + ".\n"
            "\nResult:\n"
            "TODO: write docs\n"
            "\nExamples:\n" +
            HelpExampleCli(cmdname, "\"<hex>\"") + HelpExampleRpc(cmdname, "\"<hex>\""));
}

template <typename Pop>
UniValue submitpopIt(const JSONRPCRequest& request)
{
    check_submitpop(request, Pop::name());

    EnsurePopEnabled();

    auto payloads_bytes = ParseHexV(request.params[0].get_str(), Pop::name());

    Pop data;
    altintegration::ReadStream stream(payloads_bytes);
    altintegration::ValidationState state;
    if (!altintegration::DeserializeFromVbkEncoding(stream, data, state)) {
        return state.Invalid("bad-data");
    }

    LOCK(cs_main);
    auto& mp = *VeriBlock::GetPop().mempool;
    auto idhex = data.getId().toHex();
    auto result = mp.submit<Pop>(data, state);
    logSubmitResult<Pop>(idhex, result, state);

    bool accepted = result.isAccepted();
    return altintegration::ToJSON<UniValue>(state, &accepted);
}

UniValue submitpopatv(const JSONRPCRequest& request)
{
    return submitpopIt<altintegration::ATV>(request);
}
UniValue submitpopvtb(const JSONRPCRequest& request)
{
    return submitpopIt<altintegration::VTB>(request);
}
UniValue submitpopvbk(const JSONRPCRequest& request)
{
    return submitpopIt<altintegration::VbkBlock>(request);
}

} // namespace

// getblock
namespace {

void check_getblock(const JSONRPCRequest& request, const std::string& chain)
{
    auto cmdname = strprintf("get%sblock", chain);
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            cmdname + "\n"
            "\nGet block data identified by block hash\n"
            "\nArguments:\n"
            "1. blockhash         (string, required) hex block hash.\n"
            "\nResult:\n"
            "TODO: write docs\n"
            "\nExamples:\n" +
            HelpExampleCli(cmdname, "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"") +
            HelpExampleRpc(cmdname, "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\""));
}

template <typename Tree>
typename Tree::index_t* GetBlockIndex(Tree& tree, std::string hex)
{
    auto data = ParseHex(hex);
    using hash_t = typename Tree::hash_t;
    hash_t hash = data;
    return tree.getBlockIndex(hash);
}

template <>
typename altintegration::VbkBlockTree::index_t* GetBlockIndex(altintegration::VbkBlockTree& tree, std::string hex)
{
    auto data = ParseHex(hex);
    using block_t = altintegration::VbkBlock;
    using hash_t = block_t::hash_t;
    using prev_hash_t = block_t::prev_hash_t;
    if (data.size() == hash_t::size()) {
        // it is a full hash
        hash_t h = data;
        return tree.getBlockIndex(h);
    }
    if (data.size() == prev_hash_t::size()) {
        // it is an id
        prev_hash_t h = data;
        return tree.getBlockIndex(h);
    }

    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Wrong hash size");
    return nullptr;
}

template <typename Tree>
UniValue getblock(const JSONRPCRequest& req, Tree& tree, const std::string& chain)
{
    check_getblock(req, chain);
    LOCK(cs_main);

    std::string strhash = req.params[0].get_str();
    auto* index = GetBlockIndex<Tree>(tree, strhash);
    if (!index) {
        // no block found
        return UniValue(UniValue::VNULL);
    }

    return altintegration::ToJSON<UniValue>(*index);
}

UniValue getvbkblock(const JSONRPCRequest& req)
{
    return getblock(req, vbk(), "vbk");
}
UniValue getbtcblock(const JSONRPCRequest& req)
{
    return getblock(req, btc(), "btc");
}

} // namespace

// getbestblockhash
namespace {
void check_getbestblockhash(const JSONRPCRequest& request, const std::string& chain)
{
    auto cmdname = strprintf("get%sbestblockhash", chain);
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            cmdname + "\n"
            "\nReturns the hash of the best (tip) block in the most-work fully-validated chain.\n"
            "\nResult:\n"
            "\"hex\"      (string) the block hash, hex-encoded\n"
            "\nExamples:\n" +
            HelpExampleCli(cmdname, "") + HelpExampleRpc(cmdname, ""));
}

template <typename Tree>
UniValue getbestblockhash(const JSONRPCRequest& request, Tree& tree, const std::string& chain)
{
    check_getbestblockhash(request, chain);

    LOCK(cs_main);
    auto* tip = tree.getBestChain().tip();
    if (!tip) {
        // tree is not bootstrapped
        return UniValue(UniValue::VNULL);
    }

    return UniValue(tip->getHash().toHex());
}

UniValue getvbkbestblockhash(const JSONRPCRequest& request)
{
    return getbestblockhash(request, vbk(), "vbk");
}

UniValue getbtcbestblockhash(const JSONRPCRequest& request)
{
    return getbestblockhash(request, btc(), "btc");
}
} // namespace

// getblockhash
namespace {

void check_getblockhash(const JSONRPCRequest& request, const std::string& chain)
{
    auto cmdname = strprintf("get%sblockhash", chain);
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            cmdname + "\n"
            "\nReturns hash of block in best-block-chain at height provided.\n"
            "\nArguments:\n"
            "1. height         (numeric, required) The block height.\n"
            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"
            "\nExamples:\n" +
            HelpExampleCli(cmdname, "1000") +
            HelpExampleRpc(cmdname, "1000"));
}

template <typename Tree>
UniValue getblockhash(const JSONRPCRequest& request, Tree& tree, const std::string& chain)
{
    check_getblockhash(request, chain);
    LOCK(cs_main);
    auto& best = tree.getBestChain();
    if (best.blocksCount() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Chain %s is not bootstrapped", chain));
    }

    int height = request.params[0].get_int();
    if (height < best.first()->getHeight()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Chain %s starts at %d, provided %d", chain, best.first()->getHeight(), height));
    }
    if (height > best.tip()->getHeight()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Chain %s tip is at %d, provided %d", chain, best.tip()->getHeight(), height));
    }

    auto* index = best[height];
    assert(index);
    return UniValue(index->getHash().toHex());
}

UniValue getvbkblockhash(const JSONRPCRequest& request)
{
    return getblockhash(request, vbk(), "vbk");
}
UniValue getbtcblockhash(const JSONRPCRequest& request)
{
    return getblockhash(request, btc(), "btc");
}

} // namespace

// getpoprawmempool
namespace {

UniValue getrawpopmempool(const JSONRPCRequest& request)
{
    std::string cmdname = "getrawpopmempool";
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            cmdname + "\n"
            "\nReturns the list of VBK blocks, ATVs and VTBs stored in POP mempool.\n"
            "\nResult:\n"
            "TODO: write docs\n"
            "\nExamples:\n" +
            HelpExampleCli(cmdname, "") +
            HelpExampleRpc(cmdname, ""));

    auto& mp = *VeriBlock::GetPop().mempool;
    return altintegration::ToJSON<UniValue>(mp);
}

} // namespace

// getrawatv
// getrawvtb
// getrawvbkblock
namespace {

template <typename T>
bool GetPayload(
    const typename T::id_t& pid,
    T& out,
    const Consensus::Params& consensusParams,
    const CBlockIndex* const block_index,
    std::vector<uint256>& containingBlocks)
{
    LOCK(cs_main);

    if (block_index) {
        CBlock block;
        if (!ReadBlockFromDisk(block, block_index, consensusParams)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                strprintf("Can not read block %s from disk", block_index->GetBlockHash().GetHex()));
        }
        if (!VeriBlock::FindPayloadInBlock<T>(block, pid, out)) {
            return false;
        }
        containingBlocks.push_back(block_index->GetBlockHash());
        return true;
    }

    auto& pop = VeriBlock::GetPop();

    auto& mp = *pop.mempool;
    auto* pl = mp.get<T>(pid);
    if (pl) {
        out = *pl;
        return true;
    }

    // search in the alttree storage
    const auto& containing = pop.altTree->getPayloadsIndex().getContainingAltBlocks(pid.asVector());
    if (containing.size() == 0) return false;

    // fill containing blocks
    containingBlocks.reserve(containing.size());
    std::transform(
        containing.begin(), containing.end(), std::back_inserter(containingBlocks), [](const decltype(*containing.begin())& blockHash) {
            return uint256(blockHash);
        });

    for (const auto& blockHash : containing) {
        auto* index = LookupBlockIndex(uint256(blockHash));
        assert(index && "state and index mismatch");

        CBlock block;
        if (!ReadBlockFromDisk(block, index, consensusParams)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Can not read block %s from disk", index->GetBlockHash().GetHex()));
        }

        if (!VeriBlock::FindPayloadInBlock<T>(block, pid, out)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Payload not found in the block data");
        }
    }

    return true;
}

template <typename T>
UniValue getrawpayload(const JSONRPCRequest& request, const std::string& name)
{
    auto cmdname = strprintf("getraw%s", name);

    // clang-format off
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            cmdname + "\n"
            "\nReturn the raw " + name + " data.\n"

            "\nWhen called with a blockhash argument, " + cmdname + " will return the " + name + "\n"
            "if the specified block is available and the " + name + " is found in that block.\n"
            "When called without a blockhash argument, " + cmdname + "will return the " + name + "\n"
            "if it is in the POP mempool, or in local payload repository.\n"

            "\nIf verbose is 'true', returns an Object with information about 'id'.\n"
            "If verbose is 'false' or omitted, returns a string that is serialized, hex-encoded data for 'id'.\n"

            "\nArguments:\n"
            "1. id         (string, required) The " + name + " id.\n"
            "2. verbose    (boolean, optional, default=false) If false, return a string, otherwise return a json object\n"
            "3. blockhash  (string, optional) The block in which to look for the " + name + "\n"
            "\nResult: (for verbose = false):\n"
            "\"data\"      (string) The serialized, hex-encoded data for 'id'\n"
            "\nExamples:\n" +
            HelpExampleCli(cmdname, "\"id\"") +
            HelpExampleCli(cmdname, "\"id\" true") +
            HelpExampleRpc(cmdname, "\"id\", true") +
            HelpExampleCli(cmdname, "\"id\" false \"myblockhash\"") +
            HelpExampleCli(cmdname, "\"id\" true \"myblockhash\""));
    // clang-format on

    using id_t = typename T::id_t;
    id_t pid;
    try {
        pid = id_t::fromHex(request.params[0].get_str());
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Bad id: %s", e.what()));
    }

    // Accept either a bool (true) or a num (>=1) to indicate verbose output.
    bool fVerbose = false;
    if (!request.params[1].isNull()) {
        fVerbose = request.params[1].isNum() ? (request.params[1].get_int() != 0) : request.params[1].get_bool();
    }

    CBlockIndex* blockindex = nullptr;
    if (!request.params[2].isNull()) {
        LOCK(cs_main);

        uint256 hash_block = ParseHashV(request.params[2], "parameter 3");
        blockindex = LookupBlockIndex(hash_block);
        if (!blockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found");
        }
    }

    T out;
    std::vector<uint256> containingBlocks{};
    if (!GetPayload<T>(pid, out, Params().GetConsensus(), blockindex, containingBlocks)) {
        std::string errmsg;
        if (blockindex) {
            if (!(blockindex->nStatus & BLOCK_HAVE_DATA)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Block not available");
            }
            errmsg = "No such " + name + " found in the provided block";
        } else {
            errmsg = "No such mempool or blockchain " + name;
        }
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg);
    }

    if (!fVerbose) {
        return altintegration::ToJSON<UniValue>(altintegration::SerializeToHex(out));
    }

    uint256 activeHashBlock{};
    CBlockIndex* verboseBlockIndex = nullptr;
    {
        LOCK(cs_main);
        for (const auto& b : containingBlocks) {
            auto* index = LookupBlockIndex(b);
            if (index == nullptr) continue;
            verboseBlockIndex = index;
            if (chainActive.Contains(index)) {
                activeHashBlock = b;
                break;
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    if (verboseBlockIndex) {
        bool in_active_chain = chainActive.Contains(verboseBlockIndex);
        result.pushKV("in_active_chain", in_active_chain);
        result.pushKV("blockheight", verboseBlockIndex->nHeight);
        if (in_active_chain) {
            result.pushKV("confirmations", 1 + chainActive.Height() - verboseBlockIndex->nHeight);
            result.pushKV("blocktime", verboseBlockIndex->GetBlockTime());
        } else {
            result.pushKV("confirmations", 0);
        }
    }

    result.pushKV(name, altintegration::ToJSON<UniValue>(out));
    UniValue univalueContainingBlocks(UniValue::VARR);
    for (const auto& b : containingBlocks) {
        univalueContainingBlocks.push_back(b.GetHex());
    }
    result.pushKV("containing_blocks", univalueContainingBlocks);
    result.pushKV("blockhash", activeHashBlock.GetHex());
    return result;
}

UniValue getrawatv(const JSONRPCRequest& req)
{
    return getrawpayload<altintegration::ATV>(req, "atv");
}
UniValue getrawvtb(const JSONRPCRequest& req)
{
    return getrawpayload<altintegration::VTB>(req, "vtb");
}
UniValue getrawvbkblock(const JSONRPCRequest& req)
{
    return getrawpayload<altintegration::VbkBlock>(req, "vbkblock");
}

} // namespace

UniValue getpopparams(const JSONRPCRequest& req)
{
    std::string cmdname = "getpopparams";
    // clang-format off
    if (req.fHelp || req.params.size() != 0)
        throw std::runtime_error(
            cmdname + "\n"
            "\nReturns POP-related parameters set for this altchain.\n"
            "\nResult:\n"
            "TODO: write docs\n"
            "\nExamples:\n"
            + HelpExampleCli(cmdname, "")
            + HelpExampleRpc(cmdname, "")
        );
    // clang-format on

    auto& config = *VeriBlock::GetPop().config;
    auto ret = altintegration::ToJSON<UniValue>(*config.alt);

    auto* vbkfirst = vbk().getBestChain().first();
    auto* btcfirst = btc().getBestChain().first();
    assert(vbkfirst);
    assert(btcfirst);

    auto _vbk = UniValue(UniValue::VOBJ);
    _vbk.pushKV("hash", vbkfirst->getHash().toHex());
    _vbk.pushKV("height", vbkfirst->getHeight());
    _vbk.pushKV("network", config.vbk.params->networkName());

    auto _btc = UniValue(UniValue::VOBJ);
    _btc.pushKV("hash", btcfirst->getHash().toHex());
    _btc.pushKV("height", btcfirst->getHeight());
    _btc.pushKV("network", config.btc.params->networkName());

    ret.pushKV("vbkBootstrapBlock", _vbk);
    ret.pushKV("btcBootstrapBlock", _btc);

    ret.pushKV("popActivationHeight", Params().GetConsensus().VeriBlockPopSecurityHeight);
    ret.pushKV("popRewardPercentage", (int64_t)Params().PopRewardPercentage());
    ret.pushKV("popRewardCoefficient", Params().PopRewardCoefficient());

    return ret;
}

const CRPCCommand commands[] = {
    {"pop_mining", "getpopparams", &getpopparams, {}},
    {"pop_mining", "submitpopatv", &submitpopatv, {"atv"}},
    {"pop_mining", "submitpopvtb", &submitpopvtb, {"vtb"}},
    {"pop_mining", "submitpopvbk", &submitpopvbk, {"vbkblock"}},
    {"pop_mining", "getpopdatabyheight", &getpopdatabyheight, {"blockheight"}},
    {"pop_mining", "getpopdatabyhash", &getpopdatabyhash, {"hash"}},
    {"pop_mining", "getvbkblock", &getvbkblock, {"hash"}},
    {"pop_mining", "getbtcblock", &getbtcblock, {"hash"}},
    {"pop_mining", "getvbkbestblockhash", &getvbkbestblockhash, {}},
    {"pop_mining", "getbtcbestblockhash", &getbtcbestblockhash, {}},
    {"pop_mining", "getvbkblockhash", &getvbkblockhash, {"height"}},
    {"pop_mining", "getbtcblockhash", &getbtcblockhash, {"height"}},
    {"pop_mining", "getrawatv", &getrawatv, {"id"}},
    {"pop_mining", "getrawvtb", &getrawvtb, {"id"}},
    {"pop_mining", "getrawvbkblock", &getrawvbkblock, {"id"}},
    {"pop_mining", "getrawpopmempool", &getrawpopmempool, {}}};

void RegisterPOPMiningRPCCommands(CRPCTable& t)
{
    for (const auto& command : VeriBlock::commands) {
        t.appendCommand(command.name, &command);
    }
}

} // namespace VeriBlock
```

### Add JSON adaptor for the library, to convert the MempoolResult from the library to the UniValue object.

[<font style="color: red"> src/vbk/adaptors/univalue_json.hpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef INTEGRATION_REFERENCE_BITC_JSON_HPP
#define INTEGRATION_REFERENCE_BITC_JSON_HPP

#include <univalue.h>
#include <veriblock/json.hpp>

/// contains partial specialization of ToJSON, which allows to write
/// UniValue v = ToJSON<UniValue>(vbk entity);

namespace altintegration {

template <>
inline UniValue ToJSON(const std::string& t)
{
    return UniValue(t);
}

template <>
inline UniValue ToJSON(const double& t)
{
    return UniValue(t);
}

template <>
inline UniValue ToJSON(const uint32_t& t)
{
    return UniValue((uint64_t)t);
}

template <>
inline UniValue ToJSON(const int& t)
{
    return UniValue((int64_t)t);
}

namespace json {

template <>
inline UniValue makeEmptyObject()
{
    return UniValue(UniValue::VOBJ);
}

template <>
inline UniValue makeEmptyArray()
{
    return UniValue(UniValue::VARR);
}

template <>
inline void putKV(UniValue& object,
    const std::string& key,
    const UniValue& val)
{
    object.pushKV(key, val);
}

template <>
inline void putStringKV(UniValue& object,
    const std::string& key,
    const std::string& value)
{
    object.pushKV(key, value);
}

template <>
inline void putIntKV(UniValue& object,
    const std::string& key,
    int64_t value)
{
    object.pushKV(key, value);
}

template <>
inline void putNullKV(UniValue& object, const std::string& key)
{
    object.pushKV(key, UniValue(UniValue::VNULL));
}

template <>
inline void arrayPushBack(UniValue& array, const UniValue& val)
{
    array.push_back(val);
}

template <>
inline void putBoolKV(UniValue& object,
    const std::string& key,
    bool value)
{
    object.pushKV(key, value);
}

} // namespace json
} // namespace altintegration

#endif //INTEGRATION_REFERENCE_BITC_JSON_HPP
```

### Update serialize.h to use new JSON convertor.

[<font style="color: red"> src/serialize.h </font>]
```diff
 #include <span.h>

+#include <vbk/adaptors/univalue_json.hpp>
+
 #include "veriblock/serde.hpp"
```

### Add all new RPC functions to the RPC server.

[<font style="color: red"> src/rpc/register.h </font>]
```diff
 #define BITCASH_RPC_REGISTER_H

+#include "vbk/rpc_register.hpp"
+
 /** These are in one header file to avoid creating tons of single-function
```
_method RegisterAllCoreRPCCommands_
```diff
     RegisterMiscRPCCommands(t);
     RegisterMiningRPCCommands(t);
     RegisterRawTransactionRPCCommands(t);
+    VeriBlock::RegisterPOPMiningRPCCommands(t);
 }
```

### Update original RPC calls to provide additional POP information.

[<font style="color: red"> src/rpc/blockchain.cpp </font>]
```diff
 #include <condition_variable>

+#include <vbk/adaptors/univalue_json.hpp>
+#include <vbk/pop_common.hpp>
+
 struct CUpdatedBlock
```
_method getblock_
```diff
     }

-    return blockToJSON(block, pblockindex, verbosity >= 2);
+    UniValue json = blockToJSON(block, pblockindex, verbosity >= 2);
+
+    {
+        auto& pop = VeriBlock::GetPop();
+        LOCK(cs_main);
+        auto index = pop.altTree->getBlockIndex(block.GetHash().asVector());
+        VBK_ASSERT(index);
+        UniValue obj(UniValue::VOBJ);
+
+        obj.pushKV("state", altintegration::ToJSON<UniValue>(*index));
+        obj.pushKV("data", altintegration::ToJSON<UniValue>(block.popData, verbosity >= 2));
+        json.pushKV("pop", obj);
+    }
+
+    return json;
 }
```
_method SoftForkMajorityDesc_
```diff
             activated = pindex->nHeight >= consensusParams.BIP65Height;
             break;
+        case 5:
+            activated = pindex->nHeight >= (int)consensusParams.VeriBlockPopSecurityHeight;
+            break;
     }
     rv.pushKV("status", activated);
```
_method getblockchaininfo_
```diff
     softforks.push_back(SoftForkDesc("bip66", 3, tip, consensusParams));
     softforks.push_back(SoftForkDesc("bip65", 4, tip, consensusParams));
+    // VeriBlock
+    softforks.push_back(SoftForkDesc("pop_security", 5, tip, consensusParams));
     for (int pos = Consensus::DEPLOYMENT_CSV; pos != Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++pos) {
```
[<font style="color: red"> src/rpc/client.cpp </font>]
```diff
 static const CRPCConvertParam vRPCConvertParams[] =
 {
+    // VeriBlock
+    { "getbtcblockhash", 0, "height"},
+    { "getvbkblockhash", 0, "height"},
+    { "getrawatv", 1, "verbose"},
+    { "getrawvtb", 1, "verbose"},
+    { "getrawvbkblock", 1, "verbose"},
+    { "getpopdatabyheight", 0, "block_height"},
+    // end VeriBlock
     { "setmocktime", 0, "timestamp" },
     { "generate", 0, "nblocks" },
```
[<font style="color: red"> src/rpc/mining.cpp </font>]
```diff
 #include <chainparams.h>
 #include <consensus/consensus.h>
+#include <consensus/merkle.h>
 #include <consensus/params.h>
```
```diff
 #include <stdint.h>

+#include <vbk/pop_service.hpp>
+
```
_method getmininginfo_
```diff
             "  \"bits\" : \"xxxxxxxx\",              (string) compressed target of next block\n"
             "  \"height\" : n                      (numeric) The height of the next block\n"
+            "  \"default_witness_commitment\" : \"xxxx\" (string) coinbase witness commitment \n"
+            "  \"pop_context\" : {\n"
+            "    \"serialized\": \"xxx\"     (string) serialized version of AuthenticatedContextInfoContainer\n"
+            "    \"stateRoot\" : \"xxx\"     (string) Hex-encoded StateRoot=sha256d(txRoot, popDataRoot)\n"
+            "    \"context\"   : {\n"
+            "      \"height\"    : 123       (numeric) Current block height.\n"
+            "      \"firstPreviousKeystone\": \"xxx\"  (string) First previous keystone of current block.\n"
+            "      \"secondPreviousKeystone\": \"xxx\" (string) Second previous keystone of current block.\n"
+            "    }\n"
+            "  }\n"
+            "  \"pop_data_root\" : \"xxxx\"   (string) Merkle Root of PopData\n"
+            "  \"pop_data\" : { \"atvs\": [], \"vtbs\": [], \"vbkblocks\": [] }   (object) Valid POP data that must be included in next block in order they appear here (vbkblocks, vtbs, atvs).\n"
+            "  \"pop_payout\" : [                 (array) List of POP payouts that must be addedd to next coinbase in order they appear in array.\n"
+            "    \"payout_info\": \"...\",\n"
+            "    \"amount\": xxx\n"
+            "   ]\n"
             "}\n"
```
_method getblocktemplate__
```diff
         result.pushKV("default_witness_commitment", HexStr(pblocktemplate->vchCoinbaseCommitment.begin(), pblocktemplate->vchCoinbaseCommitment.end()));
     }

+    //VeriBlock Data
+    auto& popctx = VeriBlock::GetPop();
+    pblock->popData = popctx.mempool->getPop();
+    const auto popDataRoot = pblock->popData.getMerkleRoot();
+    result.pushKV("pop_data_root", HexStr(popDataRoot.begin(), popDataRoot.end()));
+    auto txRoot = BlockMerkleRoot(*pblock, nullptr);
+    result.pushKV("tx_root", HexStr(txRoot));
+    result.pushKV("pop_data", altintegration::ToJSON<UniValue>(pblock->popData));
+    using altintegration::AuthenticatedContextInfoContainer;
+    auto authctx = AuthenticatedContextInfoContainer::createFromPrevious(txRoot.asVector(), popDataRoot, VeriBlock::GetAltBlockIndex(pindexPrev), VeriBlock::GetPop().config->getAltParams());
+    result.pushKV("pop_context", altintegration::ToJSON<UniValue>(authctx));
+
+    // pop rewards
+    UniValue popRewardsArray(UniValue::VARR);
+    VeriBlock::PoPRewards popRewards = VeriBlock::getPopRewards(*pindexPrev, Params());
+    for (const auto& itr : popRewards) {
+        UniValue popRewardValue(UniValue::VOBJ);
+        popRewardValue.pushKV("payout_info", HexStr(itr.first.begin(), itr.first.end()));
+        popRewardValue.pushKV("amount", itr.second);
+        popRewardsArray.push_back(popRewardValue);
+    }
+    result.pushKV("pop_rewards", popRewardsArray);
+
     return result;
```

### Add RPC unit test.

[<font style="color: red"> src/vbk/test/unit/rpc_service_tests.cpp </font>]
```
// Copyright (c) 2019-2020 Xenios SEZC
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <rpc/server.h>
#include <vbk/test/util/e2e_fixture.hpp>
#include <utility>

UniValue CallRPC(std::string args);

BOOST_AUTO_TEST_SUITE(rpc_service_tests)

BOOST_FIXTURE_TEST_CASE(submitpop_test, E2eFixture)
{
    auto makeRequest = [](std::string req, const std::string& arg){
      JSONRPCRequest request;
      request.strMethod = std::move(req);
      request.params = UniValue(UniValue::VARR);
      request.params.push_back(arg);
      request.fHelp = false;

      if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();

      UniValue result;
      BOOST_CHECK_NO_THROW(result = tableRPC.execute(request));

      return result;
    };

    JSONRPCRequest request;
    request.strMethod = "submitpop";
    request.params = UniValue(UniValue::VARR);
    request.fHelp = false;

    uint32_t generateVtbs = 20;
    std::vector<VTB> vtbs;
    vtbs.reserve(generateVtbs);
    std::generate_n(std::back_inserter(vtbs), generateVtbs, [&]() {
        return endorseVbkTip();
    });

    BOOST_CHECK_EQUAL(vtbs.size(), generateVtbs);

    std::vector<altintegration::VbkBlock> vbk_blocks;
    for (const auto& vtb : vtbs) {
        vbk_blocks.push_back(vtb.containingBlock);
    }

    BOOST_CHECK(!vbk_blocks.empty());

    UniValue vbk_blocks_params(UniValue::VARR);
    for (const auto& b : vbk_blocks) {
        auto res = makeRequest("submitpopvbk", altintegration::SerializeToHex(b));
    }

    UniValue vtb_params(UniValue::VARR);
    for (const auto& vtb : vtbs) {
        auto res = makeRequest("submitpopvtb", altintegration::SerializeToHex(vtb));
    }
}

BOOST_AUTO_TEST_SUITE_END()
```

### Add RPC service and test to the makefile.

[<font style="color: red"> src/Makefile.include </font>]
```diff
libbitcash_server_a_SOURCES = \
   vbk/params.cpp \
   rest.cpp \
   stratum.cpp \
+  vbk/rpc_register.hpp \
+  vbk/rpc_register.cpp \
   vbk/p2p_sync.hpp \
   vbk/p2p_sync.cpp \
```
[<font style="color: red"> src/Makefile.test.include </font>]
```diff
 VBK_TESTS =\
   vbk/test/unit/block_validation_tests.cpp \
   vbk/test/unit/vbk_merkle_tests.cpp \
   vbk/test/unit/pop_reward_tests.cpp \
-  vbk/test/unit/forkresolution_tests.cpp
+  vbk/test/unit/forkresolution_tests.cpp \
+  vbk/test/unit/rpc_service_tests.cpp
```