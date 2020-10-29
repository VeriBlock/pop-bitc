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
[<font style="color: red">configure.ac</font>]
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
[<font style="color: red">src/Makefile.am</font>]
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
[<font style="color: red">src/Makefile.bench.include</font>]
```diff
bench_bench_bitcash_LDADD = \
   $(LIBMEMENV) \
   $(LIBSECP256K1) \
   $(LIBUNIVALUE) \
-  $(DL_LIBS)
+  $(DL_LIBS) \
+  $(VERIBLOCK_POP_CPP_LIBS)
```
[<font style="color: red">src/Makefile.test.include</font>]
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
@@ -135,7 +131,7 @@ test_test_bitcash_fuzzy_LDADD = \
   $(LIBBITCASH_CRYPTO) \
   $(LIBSECP256K1)
 
-test_test_bitcash_fuzzy_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
+test_test_bitcash_fuzzy_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS) $(VERIBLOCK_POP_CPP_LIBS)
```

## Add PopData in the Block
We should add new PopData entity into the CBlock class in the block.h file and provide new nVersion flag. It is needed for storing VeriBlock specific information such as ATVs, VTBs, VBKs.
First we will add new POP_BLOCK_VERSION_BIT flag, that will help to distinguish original blocks that don't have any VeriBlock specific data, and blocks that contain such data.
Next, update serialization of the block, that will serialize/deserialize PopData if POP_BLOCK_VERSION_BIT is set. Finally extend serialization/deserialization for the PopData, so we can use the bitcoin native serialization/deserialization.

### Define POP_BLOCK_VERSION_BIT flag.
[<font style="color: red">src/vbk/vbk.hpp</font>]
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
```diff
public:
     // network and disk
     std::vector<CTransactionRef> vtx;
+    // VeriBlock  data network and disk
+    altintegration::PopData popData;
 
     // memory only
     mutable bool fChecked;
@@ -196,6 +201,9 @@ public:
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
[<font style="color: red">src/blockencodings.h</font>]
```diff
// A BlockTransactions message
     uint256 blockhash;
     std::vector<CTransactionRef> txn;
+    // VeriBlock data
+    altintegration::PopData popData;
 
     BlockTransactions() {}
     explicit BlockTransactions(const BlockTransactionsRequest& req) :
@@ -96,6 +98,9 @@ public:
             for (size_t i = 0; i < txn.size(); i++)
                 READWRITE(TransactionCompressor(txn[i]));
         }
+
+        // VeriBlock data
+        READWRITE(popData);
     }
```
```diff
public:
     CBlockHeader header;
+    // VeriBlock data
+    altintegration::PopData popData;
 
     // Dummy for deserialization
     CBlockHeaderAndShortTxIDs() {}
@@ -184,6 +191,11 @@ public:
             }
         }
 
+        if (this->header.nVersion & VeriBlock::POP_BLOCK_VERSION_BIT) {
+            READWRITE(popData);
+        }
+
+
         READWRITE(prefilledtxn);
```
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

### Update PartiallyDownloadedBlock object initializing, to fill popData field.
[<font style="color: red">src/blockencodings.cpp</font>]
```diff
-    LogPrint(BCLog::CMPCTBLOCK, "Initialized PartiallyDownloadedBlock for block %s using a cmpctblock of size %lu\n", cmpctblock.header.GetHash().ToString(), GetSerializeSize(cmpctblock, SER_NETWORK, PROTOCOL_VERSION));
+    // VeriBlock: set pop data
+    this->popData = cmpctblock.popData;
+
+    LogPrint(BCLog::CMPCTBLOCK, "Initialized PartiallyDownloadedBlock for block %s using a cmpctblock of size %lu with %d VBK %d VTB %d ATV\n", cmpctblock.header.GetHash().ToString(), GetSerializeSize(cmpctblock, PROTOCOL_VERSION), this->popData.context.size(), this->popData.vtbs.size(), this->popData.atvs.size());
 
     return READ_STATUS_OK;
 }
```
```diff
@@ -196,6 +199,9 @@ ReadStatus PartiallyDownloadedBlock::FillBlock(CBlock& block, const std::vector<
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

