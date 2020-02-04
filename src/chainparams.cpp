// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2018 The Cryptocurrency developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
        (0, uint256("0x00007b588772aef59019003155e307ee5ac974fbf285ed7bedb8cd5ea517bd85"))
        (10, uint256("0x00003e1386d0f92caee2a4693c592d9ce389ff1b15781ab8ec020e2c3259d78c"))
        (20, uint256("0x000015fbf543831cd2303616b3c2dc3c8fe94b36d1cc1a7ef261caef7e8163d3"))
	(98, uint256("0x000000929401443203afebe9f15f36e75c11ae9cc89c05db907dc7dbf19e6ab8"))
	(940, uint256("0xb2f2833f2de8cffeb143ec74d2296de27ccb28d859be28d1a3d74bc4b9e34abe"))
	(8300, uint256("0xd8ba3e36202132345659211d0c66af72cbb2058833b68c59f576f70a3ce277e6"))
	(10000, uint256("0x4d0ee19109347763f9ed8b23e9c36d5b9bfe3e4a2d42e7dbbad8f59c69e4c711"))
	(20000, uint256("0xe772536ce85e1bbd5114c3020735772f2a13c91f46c9dbbcb6d8b66c50ad1415"))
	(30000, uint256("0x6e776a05793febbc1a9fa52569be32cdc6b18d0f7dbe23df20542266e32b3d20"))
	(40000, uint256("0x94aabe01f562748abf11e67704fcd88af7478f029d9e2f0dd04f837a7d18215b"))
	(50000, uint256("0xed4f2f1f1f9839934f413d01e9e074e99c3d39b2fd5905047c72e50fe353d3f7"))
	(60000, uint256("0xda2189fe536ac55394dbf1f88c934e551437835be864399ad89a67b0e7e0be3d"))
	(70000, uint256("0xe308ce9c05d19f5eb702a541a57ea574d96ae11a3bd40a0354b226fdb9596ff1"))
	(77000, uint256("0x5ed464f2fa04f797be4f9580658c2d8ccfab89e4d2be7981838c48a34f129b85"))
	(78000, uint256("0x9898f9b7ca2260ec0bae1b59119596ef69756aeb249890a2d9ead77728e0d3d6"))
	(79000, uint256("0xfa63bebc42ea957bd8b0b5bab8edf7c4cd613327ddf9bb157383919e1ea5b72d"))
	(80000, uint256("0x7d003b0afe7c7a21256cf341b38f9a13f73beeada923b456636c40eed3711529"))
	(81000, uint256("0x7513add7a6b17f790e8d56d191ef6a2e7b92e08aab4b87346013c1be5e9d8ab9"))
	(82000, uint256("0x3d6e17de8f210b51994d62661af9f343af8ec1becb37a7cd73e5ed5ce0dbd363"))
	(83000, uint256("0x9a32d8114c2367c42d8832d44c85732bc518f4b4a2e320cfa4329d92e1980fc8"))
	;






static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1566342452, // * UNIX timestamp of last checkpoint block
    14638,          // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
        (0, uint256("0x001"));

static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1546854438,
    79227,
    5000};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1524873600,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        pchMessageStart[0] = 0x9a;
        pchMessageStart[1] = 0xec;
        pchMessageStart[2] = 0x8d;
        pchMessageStart[3] = 0xc6;
        vAlertPubKey = ParseHex("021a64803e42a0ba0588dacb197f2f9bad4d6a6aa508af9390b59ea5320642ae6b");
        nDefaultPort = 5535;
        bnProofOfWorkLimit = ~uint256(0) >> 18;
        nSubsidyHalvingInterval = 9999999;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 120;
        nTargetSpacing = 1 * 120;
        nLastPOWBlock = 5000;
        nMaturity = 6;
        nMasternodeCountDrift = 20;
        nModifierUpdateBlock = 906000;
        nMaxMoneyOut = 21000000 * COIN;
        const char* pszTimestamp = "When the Internet first came, I thought it was just the cryptocurrency of freedom - 2019";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 1 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("022c921f7b60cafde61bf786ae847c8776fb80dbea7f51b70ef2e9c549c1b3d968") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1567590279;
        genesis.nBits = 0x1e0fffff;
        genesis.nNonce = 0xc590;



        hashGenesisBlock = genesis.GetHash();



        assert(hashGenesisBlock == uint256("0x00007b588772aef59019003155e307ee5ac974fbf285ed7bedb8cd5ea517bd85"));
        assert(genesis.hashMerkleRoot == uint256("0x9a72655d4985c8521517fd45f7e59c2a9fac1d108bf0c2265c14abd030871850"));

        vSeeds.push_back(CDNSSeedData("seed1.ccy.cash", "seed1.ccy.cash"));
        vSeeds.push_back(CDNSSeedData("seed2.ccy.cash", "seed2.ccy.cash"));
        vSeeds.push_back(CDNSSeedData("seed3.ccy.cash", "seed3.ccy.cash"));
        vSeeds.push_back(CDNSSeedData("seed4.ccy.cash", "seed4.ccy.cash"));
        vSeeds.push_back(CDNSSeedData("seed5.ccy.cash", "seed5.ccy.cash"));
        vSeeds.push_back(CDNSSeedData("seed6.ccy.cash", "seed6.ccy.cash"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 28); 
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 33); 
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 28); 
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x77).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = true;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "044e3b0f3cf08859910c6d331c8c353f9c37f3f96efe5d9b73e8c7f44525e8d08fe336c42f57023ec4bdc37b52fea88c9a457602a644798aca8b9d4299dee7b558";
        strObfuscationPoolDummyAddress = "CcBbTGDeJQx9Y2G8gJixAQhSb3A5vRAMjH";
        nStartMasternodePayments = 1539514947;

    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0x41;
        pchMessageStart[1] = 0x4d;
        pchMessageStart[2] = 0x5e;
        pchMessageStart[3] = 0x78;
        vAlertPubKey = ParseHex("043e8760d1c9ef3af5a5e49796afe4389a5cb53c6028b54b9af0a152f34762e453615a1aab9260a31045b85f87d4de36bbe6fd04478fcc103fd47c8e1b813c3d3c");
        nDefaultPort = 39795;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // Cryptocurrency: 1 day
        nTargetSpacing = 1 * 60;  // Cryptocurrency: 1 minute
        nLastPOWBlock = 200;
        nMaturity = 15;
        nMasternodeCountDrift = 4;
        nMasternodeCollateralLimit = 10000;
        nModifierUpdateBlock = 500; // fake stake update on testnet
        nMaxMoneyOut = 43199500 * COIN;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1548384672;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 519;


        hashGenesisBlock = genesis.GetHash();

        //assert(hashGenesisBlock == uint256("0x0000fba7e26b7f3d40dc6d726dc87a3fd94bfc26e6c57fa5c000a47300675e25"));
        //assert(genesis.hashMerkleRoot == uint256("0x15e4c6108db65fcfe9a92603d445c9ed90062d3b213706e386d4808b9acc6710"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet cryptocurrency addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet cryptocurrency script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet cryptocurrency BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet cryptocurrency BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet cryptocurrency BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = true;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "04d32fcf0e8ca12ae8cbed1e8fba544b995901a7fb259acc545fec89d2f65a05b3d280fc7b4eb032f7e8618aba98d6ba56b02857ed322eb7d228f9d0450b278144";
        strObfuscationPoolDummyAddress = "xxVKdbxVogrXrPLMo2qEEyCm1GRv2KZCLy";
        nStartMasternodePayments = 1524873600; //Fri, 09 Jan 2015 21:05:58 GMT
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0x2d;
        pchMessageStart[1] = 0x53;
        pchMessageStart[2] = 0x6f;
        pchMessageStart[3] = 0x40;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Cryptocurrency: 1 day
        nTargetSpacing = 1 * 60;        // Cryptocurrency: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1524873600;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 906460;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 39793;
        // assert(hashGenesisBlock == uint256("00000d885e2813770fd59e71010b6b62a9b0609655109bf4e1b24c3bd524ae0c"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 39791;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}

