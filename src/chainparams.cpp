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
	(84000, uint256("0x58db363153189331016e64e3071c6d2c748624504a12b0f74c6dba24dde5f082"))
	(85000, uint256("0xc5e3e3e98d4e1f3aa89e13885962684d9434e2de940a6788fa1b5c25ec11c893"))
	(86000, uint256("0x6e43a50e704f4bb207e672837ab1188ebae1da25be571377919392fbd5ed40d6"))
	(87000, uint256("0xa7e0099239b7a3a8082f6efb0537d44805ceed9c12d41b6623948086575fc7c7"))
	(88000, uint256("0x18401ddfb06876a4c248e39ddab3943a7536cceed73c67e742a327fbf5bbe8ca"))
	(89000, uint256("0xbbc86b70f1842b80f3313ebcf0a5554460306dad1e8a7e7e05cd2424de37a72b"))
	(90000, uint256("0x56a936b8a435a59c942444bc5c5d3942bc21667fac920c5bdc95ed86049580ea"))
	(91000, uint256("0xda864358ba6d5e07da9f3a646e85f81b6fa0fb9b9f556e96ebc005a8cff5c3a5"))
	(92000, uint256("0x0cca2b976b429aaebc025d6d6805d22352b78a0b1f3273dc08d4b98a40d9f421"))
	(93000, uint256("0xf3f68fdb44083e8aa182f55113990d5a2db561aea324e15ef7e957f94dc2ffeb"))
	(94000, uint256("0x8ad86073788273bf8c8337521d7b2af0188f05f9e5619168bb67bf40cac72a29"))
	(95000, uint256("0xa6d75a79b4332def8bc1752fb83dbc4b5c54367fd4150f2bc5f1f448c104ac74"))
	(96000, uint256("0x488cf2e430af4bfdfe1a4a3e36b1f578a10ddc887224641c36d693743d59f2a7"))
	(97000, uint256("0xbde2fd8ec74487bb1c1d135c70d73fbbef62e6689efd8de0e882b835600255bf"))
	(98000, uint256("0x010f6447ed808193a9a5d7ed8739c9f357d0aaf061f31b711ad8d1607ae80717"))
	(99000, uint256("0x0d275457fb50c8db6bf0b0f0ca368763bedd348c6f623e849464da0995424f89"))
	(100000, uint256("0x5270f837d0a2e3f8fbfe49d85b0b438dd52db75199c40379fee34877b5e8bbf1"))
	(101000, uint256("0x77a9b0b77ad42abe47501d9c8158fd056538d80e3eaaf3ced75b493ec0e7bf06"))
	(102000, uint256("0x4a654701dc14ce5fcd108809c33a0e1a14cf0e8384bf521adc46a0960cd3f2e0"))
	(103000, uint256("0xbde9d85896134ec67ee917ab76d8ad766c79b4538144cc843c17de57c1f79393"))
	(104000, uint256("0x4b3a3182890b01893b04ac97378ebd50384ca0000dee71ba2501aa43781942ef"))
	(105000, uint256("0xfeb072500541f8a285cc8f5dc2e1fec3e985af1cda1c4ec2f5ab51665e620c2a"))
	(106000, uint256("0x6cb6126377198481fa667d9adf178fd5ae1f10820974384e16285c647fdee1ac"))
	(107000, uint256("0x573c19a1407cb1b5c2d6a6dd65c7df80c516851136d35a3ab8ea3458d26330c6"))
	(108000, uint256("0x6deb888030e46a0c07ea9a70b0965120aff655197e78ba110a4c67688b002dcc"))
	(109000, uint256("0xd1a0e7f65c908805c976c5bff864a2f41aced24f9384899140899b026b88490b"))
	(110000, uint256("0xb875d6a7d01d4a025b0dce365ae6c794ce4300ec26d78c7963bb1b08fb265459"))
	(111000, uint256("0x4f1373162ab284b71d9800e73e37aea275f71a0be1f5d1e3931519efd417fd85"))
	(112000, uint256("0x31059d0d0895d282d7d1c8944a90f138c7e4553294d237bdb1dc0f7131193358"))
	(113000, uint256("0xe28c3b3eb3f85acfd373ed5682f6d95d81f1339ee8996979e86632e3a27a3cbf"))
	(114000, uint256("0x3528519cbe5aa66c46a4eb3684d9c429cb67c20278e5d3b14c7ad9f5e530c6b9"))
	(115000, uint256("0xadced74f2a18e33b90b4c41a33a54a39dc00b43355e8c4f837b111dc50219282"))
	(116000, uint256("0x14d4d13476febc9bf2941ee15add6efe3d0681dc655c2b67a092e2b45531e06e"))
	(117000, uint256("0xf3aa7b3f8d0b6625deda82a83d3a051128d645799a2071355181591d4a7c891b"))
	(118000, uint256("0x5c713073a3c0b9597cdc16c2c14ec7b89ce2b1dffc7856827a4138e3962a6ade"))
	(119000, uint256("0x57ee22740883abc01add273243664f93182b85d87a04eff3f4dfcb2133ac6bc0"))
	(120000, uint256("0xcbc5c65029cd18759a719c67859e4e440b0ad20ecee0df762a8d6ad4a661e8f4"))
	(121000, uint256("0x0a1167c6c3618dce1eae29f1252e48e274360e8561e6bd2372a0873477218929"))
	(122000, uint256("0x8f0a40722d5eb0cd8e358e21da06a7ac11cf6d8cb0742d25f0ffc55640b5df29"))
	(123000, uint256("0x8f2c8bc5db7322378bbb852053942d8086436adb075dce192c22cf878b84f060"))
	(124000, uint256("0x00fdbdb9a05b76a325f61fc59d9a49d7c9fa309b711c7dced25695b661abe26a"))
	(125000, uint256("0xadeb9b1fa3c90ce2c5b16143a12cf3a47d00b7bc64839d3492d63123c1b70744"))
	(126000, uint256("0xe8f207ffc7b19cb8a9bd69244e7774117a4899904222eaa647007c35669ad379"))
	(127000, uint256("0x03ec36cb3881eaa061d04ece4c6b2058908f259a5ec525bf07e94a5d54eeae96"))
	(128000, uint256("0x60fd8cb9088b22eb5d36cfb8133ef3754f4bdb8b1313c72aac58b8b0f33ae2d4"))
	(129000, uint256("0x5693ca114add9809333140c9cb968d80179f109fb39727d2821df40744d17357"))
	(130000, uint256("0xde7be469c360194a21d2298793b3b284e503b619288003db529d86f3ba0e9ee3"))
	(131000, uint256("0x5cd01a97be89e30c3667f98f3a5ed13eb2aaccf17ac50ed072db91ed4e4c6989"))
	(132000, uint256("0x7bb08b60dcf32191400551963b8571903db97bb2d59eaf0ce042e05e177dc63b"))
	(133000, uint256("0x6bda327dd2dacf3bced222c0d55fb4d4368db91ea1c33936664088206b33f25b"))
	(134000, uint256("0x94dab7524b81c43c77d69f0d72f709a2932aa8715f38571a8a5b11a13456d162"))
	(135000, uint256("0x64a7852447ce83a83d84be08e436732d95f8dfabac720553ac7c8f04b08e9f61"))
	(136000, uint256("0x4d3b284c1fbefe4529bf3bc658e52623a1273192893ae1015cf7380464264ac1"))
	(137000, uint256("0x4015a597c5f70721671dcb7bac8eaa38e04b3bbc646c3bc0e6ba7283b3d9dd0a"))
	(138000, uint256("0x590d140dc4e513ea16aa64daff68ac1edbb2c504185678879e77f717f74f103f"))
	(139000, uint256("0xcc65df6714c01736a74860e2c11e3d41502fa7d9a8c3fc06bab3dcbb702eff44"))
	(140000, uint256("0x0cea2a603895315e8e7fffdd77016abe9622258de14712e7b2575a633589f5fe"))
	(141000, uint256("0x2aa9f9e30a009f0273078a3fd721fa844d92d2337dbd5ade9331146831804dd5"))
	(142000, uint256("0x43994e7108b18e027d1ef00fe30e7e448532a921eb082a7d17448235b388e184"))
	(143000, uint256("0xc2c0d03f7b65685a11c37275eadc117e992a7fddfb1407ff6ba5dc3ebdc077d9"))
	(144000, uint256("0x283dc17e8f33454f16ba39475eea52f2775458fa03f08b7f0d9c908b9b477be9"))
	(145000, uint256("0xcf895a09f3cbc27e3cf61d23354b1c29daa28cebac404e4f7f066b3ef22801b7"))
	(146000, uint256("0x81df9c27f7c0893ac63c572c2c87c40764ec843658999a74aeee64f302f54b3a"))
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

