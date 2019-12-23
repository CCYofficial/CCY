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
	(22, uint256("0x00000a9dc7cba0815299a0783cb69d31d7a16db3680a9575f4b2382f87981a45"))
        (24, uint256("0x00003e7a8f1c366a011ac4bc617dc7c0a53f5775f8892adece76827506a1af89"))
        (26, uint256("0x00002b449c6e1e64c51499b3e6901a6525045a9892ec689744750466866a7bf5"))
	(30, uint256("0x00001abf15009207f0358c836cd5c32e74f4920a7c7ea26c43fdc7995e4d00ae"))
	(98, uint256("0x000000929401443203afebe9f15f36e75c11ae9cc89c05db907dc7dbf19e6ab8"))
	(940, uint256("0xb2f2833f2de8cffeb143ec74d2296de27ccb28d859be28d1a3d74bc4b9e34abe"))
	(8300, uint256("0xd8ba3e36202132345659211d0c66af72cbb2058833b68c59f576f70a3ce277e6"))
	(10000, uint256("0x4d0ee19109347763f9ed8b23e9c36d5b9bfe3e4a2d42e7dbbad8f59c69e4c711"))
	(11000, uint256("0x848dfbc8ae616d49fd398a9ddec270540702831e80d599cb9da034894f1e78b0"))
	(12000, uint256("0x170f1f30700b1f41a6831420f7c16813a714fb4d8c3932dec44367cc39ad6275"))
	(13000, uint256("0x01ec09b7ee0f34332a68d164b2d1f7a5d238d08ee7240079ed639c70c9b5d8b4"))
	(14000, uint256("0x7628edc5dfac22e62bf09ce2e4afbf0c28bc2b89e11856ac8488020c7938c9a2"))
	(15000, uint256("0x61c9f367641ded598580ae2d19466305a2d52d16d778617bc214551041b5a524"))
	(16000, uint256("0x6257dd8595b45ca55c1dfcb6d5a83b7b1b72fce1b3dcf3da13aa3a3faf82beca"))
	(17000, uint256("0x5911a13b3bf2091ae05c47bb09e9e8a0bfd2b13c2df69974c88700937375c50e"))
	(18000, uint256("0xaab501bf01678e9ab80939a5fb9010478575c7f5101b25cdf431da4fa474f743"))
	(19000, uint256("0x02a45f401e2b8dfb790a1a7ec28dcec2d87eff3e3f0634584a7b7ec31e1f3271"))
	(20000, uint256("0xe772536ce85e1bbd5114c3020735772f2a13c91f46c9dbbcb6d8b66c50ad1415"))
	(21000, uint256("0x866c79c3d41df96033f496db0871783dc1e225493286f9cbb7412edcc4dc2212"))
	(22000, uint256("0x7cbbdd6d145507899c91e4637e5680bc59bdb05adc401a41449ace79ab812a8f"))
	(23000, uint256("0xecbd9f6d2c454c9782e1f6a5e793a8784f63721db7cc29d8ac6cdd1cfe1a452d"))
	(24000, uint256("0xe924bd2e37480196c0009d4a6c1f8f315ccb8f41fa390f2fc26796a68c91d41b"))
	(25000, uint256("0x7129a7041908cc98c9dbde04d6f241ffadb7b3e7bae198a773a29c2e7f473d70"))
	(38000, uint256("0x6037966749c848149f1e6e115ff2bb5f23b724142cc1feca319b1f8cf6773d4e"))
	(40000, uint256("0x94aabe01f562748abf11e67704fcd88af7478f029d9e2f0dd04f837a7d18215b"))
	(43000, uint256("0x0282cec31ba51b47cb8877e617e9340d72fa3f3f249995219c807b5ff80e35c6"))
	(44000, uint256("0x089c18ead48356105a396118d036d532262ecff52f2f3d057bf723462ba936bf"))
	(47000, uint256("0x864c90f95fb0c7f5a112b56e3b6c7e9590ed80240a7fc7240241a7af41649aa0"))
	(48000, uint256("0x9aa13445370db56654c1b114f02522aa1831fbf6922be4ae3095f2f07bf315b0"))
	(49000, uint256("0x70db91cd327c8199fe745f760c7f0c9b2d1afba9d413689e4d2408254404011c"))
	(50000, uint256("0xed4f2f1f1f9839934f413d01e9e074e99c3d39b2fd5905047c72e50fe353d3f7"))
	(51000, uint256("0x3f079930daff23f7611df367ce9a76cfd974cbc564484bc278d34e2116c86208"))
	(52000, uint256("0xc136d6642a9f92116b0913657e10a435000a6e951710df98f9e23c0b793790dd"))
	(53000, uint256("0x3b9231aade9bf858c16ddce0ce1e8ce88ac58a0fe48e358249c77f4bf5726a8f"))
	(54000, uint256("0x392bdf2fef85e9df2788ef8d9bd14ecb17eb1495348730c9a86ab5b1f8110311"))
	(55000, uint256("0xae3c68f07a9613f34aad042db22a38489e4c11cc07abbdfd831fb128043e76b7"))
	(56000, uint256("0xb522c35de480959601095f3ce1eec24f9d88e8141476df54085d8224a625d7ce"))
	(57000, uint256("0x46cf945071f9da6701ff5ed8a342e56a820dc08ec87b966b07d3b2f004162a13"))
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
        nMasternodeCollateralLimit = 1000;
        nModifierUpdateBlock = 106000;
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
        strSporkKey = "03e3430d87d87a9354a9aefab06234d77b05eadc1b410d369fa2727af847823f77";
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
