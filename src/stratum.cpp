#ifndef MAC_OSX
// Copyright (c) 2018 The Bitcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>
#include <iostream>    
#include <string.h>   //strlen  
#include <stdlib.h>  
#include <errno.h>  
#include <unistd.h>   //close  
#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>    //close  
#include <sys/socket.h> 
#include <netinet/in.h>   
#endif
#include <sys/types.h>  
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros  
#include <thread>
#include <fstream>
#include <sstream>
#include <rpc/server.h>
#include <univalue.h>
#include <rpc/client.h>
#include <boost/algorithm/string.hpp>
#include "wallet/wallet.h"
#include "miner.h"
#include "consensus/merkle.h"
#include <chainparams.h>
#include <validation.h>
#include "rpc/blockchain.h"
#include <vbk/merkle.hpp>

#include "RSJparser.tcc"
using namespace std;

     
#define TRUE   1  
#define FALSE  0  
#define PORT 8888

static bool ProcessBlockFound(const CBlock* pblock, const CChainParams& chainparams)
{
    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("BitCashMiner: generated block is stale");
    }

    // Inform about the new block
//    GetMainSignals().BlockFound(pblock->GetHash());

    // Process this block the same as if we had received it from another node
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    if (!ProcessNewBlock(chainparams, shared_pblock, true, nullptr, false))
        return error("BitCashMiner: ProcessNewBlock, block not accepted");

    return true;
}

uint32_t getHex(string hexstr) {
    return strtoull(hexstr.c_str(), 0, 16);
}

#define HASHLEN_STR		65
#define HASHLEN_BIN		32

unsigned char binvalue(const char v)
{
	if(v >= '0' && v <= '9')
		return v-'0';

	if(v >= 'a' && v <= 'f')
		return v-'a'+10;

	return 0;
}

void binlify(unsigned char *bin, const char *hex)
{
	int len = strlen(hex);
	for(int i=0; i<len/2; i++)
		bin[i] = binvalue(hex[i*2])<<4 | binvalue(hex[i*2+1]);
}

void hexlify(char *hex, const unsigned char *bin, int len)
{
	hex[0] = 0;
	for(int i=0; i < len; i++)
		sprintf(hex+strlen(hex), "%02x", bin[i]);
}

void sha256_double_hash_hex(const unsigned char *input, char *output, unsigned int len)
{
	unsigned char output1[32];

//	sha256_double_hash(input, output1, len);
        CHash256().Write(input, len).Finalize(output1);
	hexlify(output, (unsigned char *)output1, 32);
}

vector<string> merkle_steps(vector<string> input)
{
	vector<string> L = input;
	vector<string> steps;
	vector<string> PreL;
	PreL.push_back("");

	int Ll = L.size();
	while(Ll > 1)
	{
		steps.push_back(L[1]);

		if(Ll % 2)
			L.push_back(L[L.size() - 1]);

		vector<string> Ld;
		for(int i = 1; i < L.size()/2; i++)
		{
			string s = L[i*2] + L[i*2+1];

			unsigned char bin[HASHLEN_BIN*2];
			char out[HASHLEN_STR];

			binlify((unsigned char *)bin, s.c_str());
			sha256_double_hash_hex(bin, out, HASHLEN_BIN*2);

			Ld.push_back(out);
		}

		L = PreL;
		L.insert(L.end(), Ld.begin(), Ld.end());

		Ll = L.size();
	}

	return steps;
}


std::string hexstring_be(std::string input)
{
                        std::string output;
                        output=input; 
                         for(int i=0; i<8; i++) {
                            for(int j=0; j<8; j++) {
                                output[(7-i)*8 + j]=input[i*8 + j];
                            }
                        }
                        return output;
}

std::string hexstring_be2(std::string input)
{
                        std::string output;
                        output=input; 
                         for(int i=0; i<32; i++) {
                            for(int j=0; j<2; j++) {
                                output[(31-i)*2 + j]=input[i*2 + j];
                            }
                        }
                        return output;
}

float diff=1;
std::string branchestr="";
std::string coinb1, coinb2;
int blockheight=0;
CBlock* pblock;
uint64_t jobid=0;  
CWallet* pwallet;
std::unique_ptr<CBlockTemplate> pblocktemplate;

void getnewjob()
{
    pblocktemplate=BlockAssembler(Params()).CreateNewBlock(NULL,pwallet,false,true,true);
    pblock = &pblocktemplate->block; // pointer for convenience    
    coinb1 = pblocktemplate->coinb1;
    coinb2 = pblocktemplate->coinb2;
    blockheight = pblocktemplate->blockheight;
                        std::vector<std::string> leaves;
                        leaves.resize(pblock->vtx.size());
                        for (size_t s = 0; s < pblock->vtx.size(); s++) {
                            leaves[s] = hexstring_be2(pblock->vtx[s]->GetHash().ToString());
                        }
                        std::vector<std::string> branches=merkle_steps(leaves);
			branchestr="";
			for (size_t i = 0, i_end = branches.size(); i < i_end; ++i) {
   				branchestr += (i ? ", " : "");  // main line in this blog-post
   				branchestr += "\""+branches[i]+"\"";
//   				branchestr += "\""+hexstring_be2(branches[i])+"\"";
			}
                        jobid++;
}

     
void stratum()
{   
    int64_t extranonce1i=8000002;
    pwallet = GetWallet("");
    if (!pwallet) return;

    int opt = TRUE;
    int client_socket_status[100];
    int master_socket , addrlen , new_socket , client_socket[100] ,  
          max_clients = 100 , activity, i , valread , sd;   
    int max_sd;   
    struct sockaddr_in address;   
         
    char buffer[1025];  //data buffer of 1K
    char message[20000];
         
    //set of socket descriptors  
    fd_set readfds;          
     
    //initialise all client_socket[] to 0 so not checked  
    for (i = 0; i < max_clients; i++)   
    {   
        client_socket[i] = 0;
        client_socket_status[i] = 0;      
    }   
         
    //create a master socket  
    if( (master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)   
    {   
        LogPrintf("Stratum Server: Error: socket failed\n");   
        return;
    }   
     
    //set master socket to allow multiple connections ,  
    //this is just a good habit, it will work without this  
    if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,  
          sizeof(opt)) < 0 )   
    {   
        LogPrintf("Stratum Server: Error: setsockopt \n");   
        return;
    }   
     
    //type of socket created  
    address.sin_family = AF_INET;   
    address.sin_addr.s_addr = INADDR_ANY;   
    address.sin_port = htons( PORT );   
         
    //bind the socket to localhost port 8888  
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)   
    {   
        LogPrintf("Stratum Server: Could not bind to port %i\n",PORT);   
        return;
    }   
    //try to specify maximum of 3 pending connections for the master socket  
    if (listen(master_socket, 3) < 0)   
    {   
        LogPrintf("Stratum Server: Error: listen \n");   
        return;
    }   
         
    //accept the incoming connection  
    addrlen = sizeof(address);   

    CBlockIndex* pindexPrev = chainActive.Tip();
    getnewjob();
    diff=GetNextDifficulty(pindexPrev);
    if (diff<1)diff=1;

    while(TRUE)   
    {   
        //clear the socket set  
        FD_ZERO(&readfds);   
     
        //add master socket to set  
        FD_SET(master_socket, &readfds);   
        max_sd = master_socket;   
             
        //add child sockets to set  
        for ( i = 0 ; i < max_clients ; i++)   
        {   
            //socket descriptor  
            sd = client_socket[i];   
                 
            //if valid socket descriptor then add to read list  
            if(sd > 0)   
                FD_SET( sd , &readfds);   
                 
            //highest file descriptor number, need it for the select function  
            if(sd > max_sd)   
                max_sd = sd;   
        }   
     
        //wait for an activity on one of the sockets , timeout is NULL ,  
        //so wait indefinitely  
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);   
       
        if ((activity < 0) && (errno!=EINTR))   
        {   
            LogPrintf("Statrum Server: select error");   
        }   
             
        //If something happened on the master socket ,  
        //then its an incoming connection  
        if (FD_ISSET(master_socket, &readfds))   
        {   
            if ((new_socket = accept(master_socket,  
                    (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)   
            {   
                LogPrintf("Stratum Server: Error: accept \n");   
                return;
            }   
                             
            //add new socket to array of sockets  
            for (i = 0; i < max_clients; i++)   
            {   
                //if position is empty  
                if( client_socket[i] == 0 )   
                {   
                    client_socket[i] = new_socket;   
                         
                    break;   
                }   
            }   
        }

        if (pindexPrev != chainActive.Tip()) {
            pindexPrev = chainActive.Tip();
            getnewjob();
            diff=GetNextDifficulty(pindexPrev);
            if (diff<1)diff=1;

            for (i = 0; i < max_clients; i++)   
            {   
                sd = client_socket[i];   
                if (client_socket_status[i]=1 && FD_ISSET( sd , &readfds)) {

			std::string extranonce1=strprintf("%08x", extranonce1i+i);
			std::stringstream ss;
			ss << "\n";

                        sprintf(message, "{ \"id\": null, \"method\": \"mining.set_difficulty\", \"params\": [%.0f]}\n",diff);
                        if( send(sd, message, strlen(message), 0) != strlen(message) )   
                        {   
                            LogPrintf("Stratum Server: Error: send %i\n",PORT);   
                        }  

                        sprintf(message, "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"%x\",\"%s\",\"%s\",\"%s\",[%s],\"%s\",\"%s\",\"%s\",true]}\n",
  		        jobid, hexstring_be(pblock->hashPrevBlock.GetHex()).c_str(), coinb1.c_str(), coinb2.c_str(), branchestr.c_str(),
                        strprintf("%08x", pblock->nVersion).c_str(), strprintf("%08x", pblock->nBits).c_str(), strprintf("%08x", pblock->GetBlockTime()).c_str());                        
                        if( send(sd, message, strlen(message), 0) != strlen(message) )   
                        {   
                            LogPrintf("Stratum Server: Error: send %i\n",PORT);   
                        }  
                }
            }

        }   
        //else its some IO operation on some other socket 
        for (i = 0; i < max_clients; i++)   
        {   
            sd = client_socket[i];   
                 
            if (FD_ISSET( sd , &readfds))   
            {   
                //Check if it was for closing , and also read the  
                //incoming message  
                valread = recv( sd , buffer, 1024,0);
                if (valread<0)   
                {   
                    //Somebody disconnected , get his details and print  
                    getpeername(sd , (struct sockaddr*)&address , (socklen_t*)&addrlen);   
                    LogPrintf("Stratum Server: Host disconnected , ip %s , port %d \n" ,  
                          inet_ntoa(address.sin_addr) , ntohs(address.sin_port));   
                         
                    //Close the socket and mark as 0 in list for reuse  
                    close( sd );   
                    client_socket[i] = 0;  
                    client_socket_status[i] = 0;       
                }   
                     
                //Echo back the message that came in  
                else if (strlen(buffer)>0)
                {   
                    //set the string terminating NULL byte on the end  
                    //of the data read  
                    //printf("Message: %s", buffer);
                    std::string jsonstr = buffer;
                    RSJresource  json (jsonstr);
                    int id=json["id"].as<int>(0);

                    if (json["method"].as<std::string>("")=="mining.subscribe")
                    {                        
			std::string extranonce1=strprintf("%08x", extranonce1i+i);

                        sprintf(message, "{\"id\": %i, \"result\": [ [ \"mining.set_difficulty\", \"%.0f\", \"mining.notify\", \"ae6812eb4cd7735a302a8a9dd95cf71f\"], \"%s\", 4], \"error\": null}\n",
                                id, diff,extranonce1.c_str());

                        if( send(sd, message, strlen(message), 0) != strlen(message) )   
                        {   
                            LogPrintf("Stratum Server: Error: send \n");   
                        }  

                    } else
                    if (json["method"].as<std::string>("")=="mining.authorize")
                    {                        
			std::stringstream ss;
			ss << "{\"error\": null, \"id\": "<< id<< ", \"result\": true}\n";
			std::string res=ss.str();
               
                        if( send(sd, res.c_str(), res.length(), 0) != res.length() )   
                        {   
                            LogPrintf("Stratum Server: Error: send \n");   
                        }   

                        sprintf(message, "{ \"id\": null, \"method\": \"mining.set_difficulty\", \"params\": [%.0f]}\n",diff);
                        if( send(sd, message, strlen(message), 0) != strlen(message) )   
                        {   
                            LogPrintf("Stratum Server: Error: send \n");   
                        }  
                        
                        sprintf(message, "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"%x\",\"%s\",\"%s\",\"%s\",[%s],\"%s\",\"%s\",\"%s\",true]}\n",
  		        jobid, hexstring_be(pblock->hashPrevBlock.GetHex()).c_str(), coinb1.c_str(), coinb2.c_str(), branchestr.c_str(),
                        strprintf("%08x", pblock->nVersion).c_str(), strprintf("%08x", pblock->nBits).c_str(), strprintf("%08x", pblock->GetBlockTime()).c_str());                        
                        if( send(sd, message, strlen(message), 0) != strlen(message) )   
                        {   
                            LogPrintf("Stratum Server: Error: send \n");   
                        }  
                        client_socket_status[i] = 1;

                    } else
                    if (json["method"].as<std::string>("")=="mining.submit")
                    {
                        std::string extranonce2=json["params"][2].as<std::string>("");
			std::string ntime=json["params"][3].as<std::string>("");
                        std::string nonce=json["params"][4].as<std::string>("");
			std::string cyclestr=json["params"][5].as<std::string>("");
                        pblock->nNonce=getHex(nonce);
			pblock->nTime=getHex(ntime);
			pblock->sCycle.clear();
	                char cycs[2001];
                	char *pt;
                	char output[256];

                	if (cyclestr.length() < 2000)strcpy((char*)&cycs, cyclestr.c_str());
	                pt = strtok((char*)&cycs, ",");
                	std::vector<uint32_t> cycle;
                	uint32_t ui;
                	while (pt != NULL) {		
                         	if (strlen(pt) > 8) continue;
                                sprintf(output, "%.*d%s", (int)(8 - strlen(pt)), 0, pt);                
                		pblock->sCycle.insert(getHex(output));		
                		pt = strtok(NULL, ",");
                	}
                        CMutableTransaction txCoinbase(*pblock->vtx[0]);
                        std::string extranonce1=strprintf("%08x", extranonce1i+i);
                        txCoinbase.vin[0].scriptSig = CScript() << blockheight << ParseHex("FFBBAAEE003344BB"+extranonce1+extranonce2) << OP_0; 
                        assert(txCoinbase.vin[0].scriptSig.size() <= 100);
                        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
                        // VeriBlock
                        CBlockIndex *tip = chainActive.Tip();
                        assert(tip != nullptr);
                        pblock->hashMerkleRoot = VeriBlock::TopLevelMerkleRoot(tip, *pblock);

			if (ProcessBlockFound(pblock, Params())) {
                            LogPrintf("Stratum Server: Found block! \n");   
  			    std::stringstream ss;
			    ss << "{\"error\": null, \"id\": "<< id<< ", \"result\": true}\n";
			    std::string res=ss.str();
               
                            if( send(sd, res.c_str(), res.length(), 0) != res.length() )   
                            {   
                                LogPrintf("Stratum Server: Error: send \n");   
                            } 
                        }else {
                            LogPrintf("Stratum Server: Block was not accepted\n");   
  			    std::stringstream ss;
			    ss << "{\"error\": \"No block found\", \"id\": "<< id<< ", \"result\": false}\n";
			    std::string res=ss.str();
               
                            if( send(sd, res.c_str(), res.length(), 0) != res.length() )   
                            {   
                                LogPrintf("Stratum Server: Error: send \n");   
                            } 
                        }

                    }
                }   
            }               
        }   
    }            
}   

void startstratum()
{
    thread t1(stratum);
    t1.detach();
}
#endif
