// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/client.h>
#include <rpc/protocol.h>
#include <util.h>

#include <set>
#include <stdint.h>

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
    std::string paramName;  //!< parameter name
};

/**
 * Specify a (method, idx, name) here if the argument is a non-string RPC
 * argument and needs to be converted from JSON.
 *
 * @note Parameter indexes start from 0.
 */
static const CRPCConvertParam vRPCConvertParams[] =
{
    // VeriBlock
    { "getbtcblockhash", 0, "height"},
    { "getvbkblockhash", 0, "height"},
    { "getrawatv", 1, "verbose"},
    { "getrawvtb", 1, "verbose"},
    { "getrawvbkblock", 1, "verbose"},
    { "getpopdatabyheight", 0, "block_height"},
    // end VeriBlock
    { "setmocktime", 0, "timestamp" },
    { "generate", 0, "nblocks" },
    { "generate", 1, "maxtries" },
    { "setgenerate", 0, "mine" },
    { "setgenerate", 1, "gpumining" },
    { "setgenerate", 2, "gpuid" },
    { "setgenerate", 3, "minepowthreads" },
    { "setgenerate", 4, "minebucketthreads" },
    { "setgenerate", 5, "minebucketsize" },
    { "createcoinbaseforaddress", 1, "blockheight" },
    { "createcoinbaseforaddresswithpoolfee", 1, "blockheight" },
    { "createcoinbaseforaddresswithpoolfee", 3, "poolfeepermille" },
    { "getchildkeyforprivkey", 1, "childkeynumber" },
    { "generatetoaddress", 0, "nblocks" },
    { "generatetoaddress", 2, "maxtries" },
    { "generatetoaddress", 3, "nthreads" },
    { "getnetworkhashps", 0, "nblocks" },
    { "getnetworkhashps", 1, "height" },
    { "registernickname", 2, "nonprivate" },
    { "registernicknameandsignlater", 2, "nonprivate" },
    { "sendaslink", 4, "subtractfeefromamount" },
    { "sendaslink", 5 , "replaceable" },
    { "sendaslink", 6 , "conf_target" },
    { "sendaslinkfromcurrency", 1, "currency" },
    { "sendaslinkfromcurrency", 5, "subtractfeefromamount" },
    { "sendaslinkfromcurrency", 6 , "replaceable" },
    { "sendaslinkfromcurrency", 7 , "conf_target" },
    { "sendaslinkfromaddress", 5, "subtractfeefromamount" },
    { "sendaslinkfromaddress", 6 , "replaceable" },
    { "sendaslinkfromaddress", 7 , "conf_target" },
    { "sendaslinkfromcurrencyaddress", 2, "currency" },
    { "sendaslinkfromcurrencyaddress", 6, "subtractfeefromamount" },
    { "sendaslinkfromcurrencyaddress", 7 , "replaceable" },
    { "sendaslinkfromcurrencyaddress", 8 , "conf_target" },
    { "sendaslinkwithprivkey", 1, "withviewkey" },
    { "sendaslinkwithprivkey", 6, "subtractfeefromamount" },
    { "sendaslinkwithprivkey", 7 , "replaceable" },
    { "sendaslinkwithprivkey", 8 , "conf_target" },
    { "sendaslinkwithprivkeyfromcurrency", 1, "withviewkey" },
    { "sendaslinkwithprivkeyfromcurrency", 3, "currency" },
    { "sendaslinkwithprivkeyfromcurrency", 7, "subtractfeefromamount" },
    { "sendaslinkwithprivkeyfromcurrency", 8 , "replaceable" },
    { "sendaslinkwithprivkeyfromcurrency", 9 , "conf_target" },
    { "sendtoaddress", 1, "amount" },
    { "sendtoaddress", 5, "subtractfeefromamount" },
    { "sendtoaddress", 6 , "replaceable" },
    { "sendtoaddress", 7 , "conf_target" },
    { "sendtoaddressandsignlater", 0, "currency" },
    { "sendtoaddressandsignlater", 3, "amount" },
    { "sendtoaddressandsignlater", 7, "subtractfeefromamount" },
    { "sendtoaddressandsignlater", 8 , "replaceable" },
    { "sendtoaddressandsignlater", 9 , "conf_target" },
    { "sendtoaddressfromaddress", 0, "currency" },
    { "sendtoaddressfromaddress", 3, "amount" },
    { "sendtoaddressfromaddress", 7, "subtractfeefromamount" },
    { "sendtoaddressfromaddress", 8 , "replaceable" },
    { "sendtoaddressfromaddress", 9 , "conf_target" },
    { "sendtoaddressfromcurrency", 0, "currency" },
    { "sendtoaddressfromcurrency", 2, "amount" },
    { "sendtoaddressfromcurrency", 6, "subtractfeefromamount" },
    { "sendtoaddressfromcurrency", 7 , "replaceable" },
    { "sendtoaddressfromcurrency", 8 , "conf_target" },
    { "sendtoaddresswithprivkey", 1, "withviewkey" },
    { "sendtoaddresswithprivkey", 3, "amount" },
    { "sendtoaddresswithprivkey", 7, "subtractfeefromamount" },
    { "sendtoaddresswithprivkey", 8 , "replaceable" },
    { "sendtoaddresswithprivkey", 9 , "conf_target" },
    { "sendtoaddresswithprivkeyfromcurrency", 0, "currency" },
    { "sendtoaddresswithprivkeyfromcurrency", 2, "withviewkey" },
    { "sendtoaddresswithprivkeyfromcurrency", 4, "amount" },
    { "sendtoaddresswithprivkeyfromcurrency", 8, "subtractfeefromamount" },
    { "sendtoaddresswithprivkeyfromcurrency", 9 , "replaceable" },
    { "sendtoaddresswithprivkeyfromcurrency", 10 , "conf_target" },
    { "burncoins", 0, "currency" },
    { "burncoins", 1, "amount" },
    { "burncoins", 5, "subtractfeefromamount" },
    { "burncoins", 6 , "replaceable" },
    { "burncoins", 7 , "conf_target" },
    { "mintcoins", 1, "amount" },
    { "mintcoins", 5, "subtractfeefromamount" },
    { "mintcoins", 6 , "replaceable" },
    { "mintcoins", 7 , "conf_target" },
    { "settxfee", 0, "amount" },
    { "signpricewithprivkey", 2, "amount" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbyaddressforcurrency", 1, "currency" },
    { "getreceivedbyaddressforcurrency", 2, "minconf" },
    { "getreceivedbyaccount", 1, "minconf" },
    { "getreceivedbyaccountforcurrency", 1, "currency" },
    { "getreceivedbyaccountforcurrency", 2, "minconf" },
    { "getreceivedbylabel", 1, "minconf" },
    { "getreceivedbylabelforcurrency", 1, "currency" },
    { "getreceivedbylabelforcurrency", 2, "minconf" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "include_empty" },
    { "listreceivedbyaddress", 2, "include_watchonly" },
    { "listreceivedbyaddress", 3, "address_filter" },
    { "listreceivedbyaddressforcurrency", 0, "currency" },
    { "listreceivedbyaddressforcurrency", 1, "minconf" },
    { "listreceivedbyaddressforcurrency", 2, "include_empty" },
    { "listreceivedbyaddressforcurrency", 3, "include_watchonly" },
    { "listreceivedbyaddressforcurrency", 4, "address_filter" },
    { "listreceivedbyaccount", 0, "minconf" },
    { "listreceivedbyaccount", 1, "include_empty" },
    { "listreceivedbyaccount", 2, "include_watchonly" },
    { "listreceivedbyaccountforcurrency", 0, "currency" },
    { "listreceivedbyaccountforcurrency", 1, "minconf" },
    { "listreceivedbyaccountforcurrency", 2, "include_empty" },
    { "listreceivedbyaccountforcurrency", 3, "include_watchonly" },
    { "listreceivedbylabel", 0, "minconf" },
    { "listreceivedbylabel", 1, "include_empty" },
    { "listreceivedbylabel", 2, "include_watchonly" },
    { "listreceivedbylabelforcurrency", 0, "currency" },
    { "listreceivedbylabelforcurrency", 1, "minconf" },
    { "listreceivedbylabelforcurrency", 2, "include_empty" },
    { "listreceivedbylabelforcurrency", 3, "include_watchonly" },
    { "getlabeladdress", 1, "force" },
    { "getlabeladdress", 2, "nonprivate" },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "include_watchonly" },
    { "getbalanceforcurrency", 0, "currency" },
    { "getbalanceforcurrency", 2, "minconf" },
    { "getbalanceforcurrency", 3, "include_watchonly" },
    { "getbalanceforaddress", 1, "minconf" },
    { "getbalanceforaddress", 2, "include_watchonly" },
    { "getbalanceforaddress", 3, "currency" },
    { "getblockhash", 0, "height" },
    { "getunconfirmedbalanceforcurrency", 0, "currency" },
    { "waitforblockheight", 0, "height" },
    { "waitforblockheight", 1, "timeout" },
    { "waitforblock", 1, "timeout" },
    { "waitfornewblock", 0, "timeout" },
    { "move", 2, "amount" },
    { "move", 3, "minconf" },
    { "movecurrency", 0, "currency" },
    { "movecurrency", 3, "amount" },
    { "movecurrency", 4, "minconf" },
    { "sendfrom", 2, "amount" },
    { "sendfrom", 4, "minconf" },
    { "sendfrom", 7, "subtractfeefromamount" },
    { "sendfromcurrency", 2, "amount" },
    { "sendfromcurrency", 3, "currency" },
    { "sendfromcurrency", 5, "minconf" },
    { "sendfromcurrency", 8, "subtractfeefromamount" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "skip" },
    { "listtransactions", 3, "include_watchonly" },
    { "listtransactionsforcurrency", 0, "currency" },
    { "listtransactionsforcurrency", 2, "count" },
    { "listtransactionsforcurrency", 3, "skip" },
    { "listtransactionsforcurrency", 4, "include_watchonly" },
    { "listtransactionsforaddress", 1, "count" },
    { "listtransactionsforaddress", 2, "skip" },
    { "listtransactionsforcurrencyaddress", 1, "currency" },
    { "listtransactionsforcurrencyaddress", 2, "count" },
    { "listtransactionsforcurrencyaddress", 3, "skip" },
    { "listaccounts", 0, "minconf" },
    { "listaccounts", 1, "include_watchonly" },
    { "listaccounts", 2, "currency" },
    { "walletpassphrase", 1, "timeout" },
    { "getblocktemplate", 0, "template_request" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "listsinceblock", 3, "include_removed" },
    { "listsinceblockforcurrency", 0, "currency" },
    { "listsinceblockforcurrency", 2, "target_confirmations" },
    { "listsinceblockforcurrency", 3, "include_watchonly" },
    { "listsinceblockforcurrency", 4, "include_removed" },
    { "sendmany", 1, "amounts" },
    { "sendmany", 3, "minconf" },
    { "sendmany", 5, "subtractfeefrom" },
    { "sendmany", 6 , "replaceable" },
    { "sendmany", 7 , "conf_target" },
    { "sendmanyfromcurrency", 0, "currency" },
    { "sendmanyfromcurrency", 2, "amounts" },
    { "sendmanyfromcurrency", 4, "minconf" },
    { "sendmanyfromcurrency", 6, "subtractfeefrom" },
    { "sendmanyfromcurrency", 7 , "replaceable" },
    { "sendmanyfromcurrency", 8 , "conf_target" },
    { "addmultisigaddress", 0, "nrequired" },
    { "addmultisigaddress", 1, "keys" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "listunspent", 3, "include_unsafe" },
    { "listunspent", 4, "query_options" },
    { "listunspentforaddress", 1, "minconf" },
    { "listunspentforaddress", 2, "maxconf" },
    { "listunspentforaddress", 3, "addresses" },
    { "listunspentforaddress", 4, "include_unsafe" },
    { "listunspentforaddress", 5, "query_options" },
    { "getblock", 1, "verbosity" },
    { "getblock", 1, "verbose" },
    { "getblockheader", 1, "verbose" },
    { "getchaintxstats", 0, "nblocks" },
    { "gettransaction", 1, "include_watchonly" },
    { "getrawtransaction", 1, "verbose" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 3, "locktime" },
    { "createrawtransaction", 4, "replaceable" },
    { "decoderawtransaction", 1, "iswitness" },
    { "decoderawtransactionmk", 2, "iswitness" },
    { "decoderawtransactionvk", 2, "iswitness" },
    { "signrawtransaction", 1, "prevtxs" },
    { "signrawtransaction", 2, "privkeys" },
    { "signrawtransactionwithkey", 1, "privkeys" },
    { "signrawtransactionwithkey", 2, "prevtxs" },
    { "signrawtransactionwithwallet", 1, "prevtxs" },
    { "sendrawtransaction", 1, "allowhighfees" },
    { "testmempoolaccept", 0, "rawtxs" },
    { "testmempoolaccept", 1, "allowhighfees" },
    { "combinerawtransaction", 0, "txs" },
    { "fundrawtransaction", 1, "options" },
    { "fundrawtransaction", 2, "iswitness" },
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "gettxoutproof", 0, "txids" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "importprivkey", 2, "rescan" },
    { "importprivkey", 3, "importchildkeys" },
    { "importprivkey", 4, "settomainkey" },
    { "importprivkeysfromfile", 2, "rescan" },
    { "importaddress", 2, "rescan" },
    { "importaddress", 3, "p2sh" },
    { "importpubkey", 2, "rescan" },
    { "importmulti", 0, "requests" },
    { "importmulti", 1, "options" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "pruneblockchain", 0, "height" },
    { "keypoolrefill", 0, "newsize" },
    { "getrawmempool", 0, "verbose" },
    { "estimatesmartfee", 0, "conf_target" },
    { "estimaterawfee", 0, "conf_target" },
    { "estimaterawfee", 1, "threshold" },
    { "prioritisetransaction", 1, "dummy" },
    { "prioritisetransaction", 2, "fee_delta" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    { "setnetworkactive", 0, "state" },
    { "getmempoolancestors", 1, "verbose" },
    { "getmempooldescendants", 1, "verbose" },
    { "bumpfee", 1, "options" },
    { "logging", 0, "include" },
    { "logging", 1, "exclude" },
    { "disconnectnode", 1, "nodeid" },
    { "addwitnessaddress", 1, "p2sh" },
    // Echo with conversion (For testing only)
    { "echojson", 0, "arg0" },
    { "echojson", 1, "arg1" },
    { "echojson", 2, "arg2" },
    { "echojson", 3, "arg3" },
    { "echojson", 4, "arg4" },
    { "echojson", 5, "arg5" },
    { "echojson", 6, "arg6" },
    { "echojson", 7, "arg7" },
    { "echojson", 8, "arg8" },
    { "echojson", 9, "arg9" },
    { "rescanblockchain", 0, "start_height"},
    { "rescanblockchain", 1, "stop_height"},
};

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int>> members;
    std::set<std::pair<std::string, std::string>> membersByName;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
    bool convert(const std::string& method, const std::string& name) {
        return (membersByName.count(std::make_pair(method, name)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
        membersByName.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                            vRPCConvertParams[i].paramName));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw std::runtime_error(std::string("Error parsing JSON:")+strVal);
    return jVal[0];
}

UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}

UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);

    for (const std::string &s: strParams) {
        size_t pos = s.find('=');
        if (pos == std::string::npos) {
            throw(std::runtime_error("No '=' in named argument '"+s+"', this needs to be present for every argument (even if it is empty)"));
        }

        std::string name = s.substr(0, pos);
        std::string value = s.substr(pos+1);

        if (!rpcCvtTable.convert(strMethod, name)) {
            // insert string value directly
            params.pushKV(name, value);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.pushKV(name, ParseNonRFCJSONValue(value));
        }
    }

    return params;
}
