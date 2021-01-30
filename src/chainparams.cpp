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
	(90000, uint256("0x56a936b8a435a59c942444bc5c5d3942bc21667fac920c5bdc95ed86049580ea"))
	(91000, uint256("0xda864358ba6d5e07da9f3a646e85f81b6fa0fb9b9f556e96ebc005a8cff5c3a5"))
	(92000, uint256("0x0cca2b976b429aaebc025d6d6805d22352b78a0b1f3273dc08d4b98a40d9f421"))
	(93000, uint256("0xf3f68fdb44083e8aa182f55113990d5a2db561aea324e15ef7e957f94dc2ffeb"))
	(107000, uint256("0x573c19a1407cb1b5c2d6a6dd65c7df80c516851136d35a3ab8ea3458d26330c6"))
	(108000, uint256("0x6deb888030e46a0c07ea9a70b0965120aff655197e78ba110a4c67688b002dcc"))
	(109000, uint256("0xd1a0e7f65c908805c976c5bff864a2f41aced24f9384899140899b026b88490b"))
	(110000, uint256("0xb875d6a7d01d4a025b0dce365ae6c794ce4300ec26d78c7963bb1b08fb265459"))
	(111000, uint256("0x4f1373162ab284b71d9800e73e37aea275f71a0be1f5d1e3931519efd417fd85"))
	(112000, uint256("0x31059d0d0895d282d7d1c8944a90f138c7e4553294d237bdb1dc0f7131193358"))
	(113000, uint256("0xe28c3b3eb3f85acfd373ed5682f6d95d81f1339ee8996979e86632e3a27a3cbf"))
	(114000, uint256("0x3528519cbe5aa66c46a4eb3684d9c429cb67c20278e5d3b14c7ad9f5e530c6b9"))
	(130000, uint256("0xde7be469c360194a21d2298793b3b284e503b619288003db529d86f3ba0e9ee3"))
	(131000, uint256("0x5cd01a97be89e30c3667f98f3a5ed13eb2aaccf17ac50ed072db91ed4e4c6989"))
	(132000, uint256("0x7bb08b60dcf32191400551963b8571903db97bb2d59eaf0ce042e05e177dc63b"))
	(133000, uint256("0x6bda327dd2dacf3bced222c0d55fb4d4368db91ea1c33936664088206b33f25b"))
	(134000, uint256("0x94dab7524b81c43c77d69f0d72f709a2932aa8715f38571a8a5b11a13456d162"))
	(135000, uint256("0x64a7852447ce83a83d84be08e436732d95f8dfabac720553ac7c8f04b08e9f61"))
	(136000, uint256("0x4d3b284c1fbefe4529bf3bc658e52623a1273192893ae1015cf7380464264ac1"))
	(137000, uint256("0x4015a597c5f70721671dcb7bac8eaa38e04b3bbc646c3bc0e6ba7283b3d9dd0a"))
	(138000, uint256("0x590d140dc4e513ea16aa64daff68ac1edbb2c504185678879e77f717f74f103f"))
	(152000, uint256("0xef7a713afc18efd0dc730ed171db66969ae693a4c7b2e0e03a7dc372e46c92ca"))
	(153000, uint256("0xe373ab9d7b12017ce7b288905b463029598d24b4edfa53560c750a174c1b5e71"))
	(154000, uint256("0x69ed5e90749ad1e08603564d3ae54823a6b29cd430d119b3ff242b19613beaad"))
	(155000, uint256("0x3645cae2f64777cdf43b3d1f673bff3a9afd6e9ae0262ab3e3aa6d6b5219fa23"))
	(156000, uint256("0x193c0b7a8df64bc84788eb7b6692c9d45a3c8194cffae6335fcf23691d2d84c7"))
	(157000, uint256("0x9c79e75a835990aa0a5f9cac2eadd9a801d4c11aa4875707fb918726591a0c48"))
	(158000, uint256("0xedb53d9a536ba3b7e8616552c12f6055e3e58b6efcf0418adb9e2c8fb753f0b3"))
	(159000, uint256("0xb562c2a39abffc903a398e9bf1d6b4dce09e063cca2473fbeac875d30452b136"))
	(183000, uint256("0x4fdd5ce1e4ae9da73289105be8e76c95d8279b01a71520ed34c2ea516a2096c6"))
	(199000, uint256("0x62b0bb9c628f1e9b11d4c7768bf908f40fb2da17d477cda9dc6978eeb411013a"))
	(200000, uint256("0xba187e74db2910e69fec84f1971834ff514ac3693cca17ac5bf0b6e7e7dcd2eb"))
	(201000, uint256("0xea9e76840de94456d606cb4ed99e266def5983a7c964f3cbc112b6b05d39f318"))
	(202000, uint256("0x09a3e226216c7adf22eb8bad01397f2a17fa92c3da2217bae45a4a2557f78c1f"))
	(216400, uint256("0x17b30aa5b220b7eabc54a44f8e60ce63cb0a218f1cd72be54fbc14f0f7104256"))
	(218300, uint256("0x071a5d3fd81d33663b114dc193f28d7db46559ee5ad438ea20627c061a899190"))
	(219385, uint256("0x136e4b7a5e0fe0de65e00aa5782cef24c3cefa451e8de4f1446b3dce14b79744"))
	(230830, uint256("0x04470cdf4c72e3279ef720a6785a82e5c5d8265a951bf253b2a766b39d2d2a2f"))
	(230870, uint256("0xe7ac2131b22919d5db1c2587bc63b4bb88d5792fe667d9091e036eaba4024468"))
	(231460, uint256("0x2c88e090241fd5681c37c7988a2d069d1f318248f87128ebeaece674c628da7a"))
	(232000, uint256("0x0086d7b3e61a0c824d6b9165d5188b0af18989d342261ae12a8bfd8db9947bae"))
	(232020, uint256("0x84dff83a8ca7816319ff7d8f7ed283535ab2d5b3424c3791fc84aa05f63580cd"))
	(232050, uint256("0x2a9eeac7c36cc4a24b971c94c68cbc09145eba79674e30964b3b7d53d557f05c"))
	(232940, uint256("0x1264bf4731248ffe9e02d2b5597cadf2aa06ea1df390650f8a528d221d85a998"))
	(233370, uint256("0x4a20acffd7ff3c3e0a3a1ee47998c25091b1db01780cf24c9ba05c4626dbf83f"))
	(234980, uint256("0x51ca9a19eddbb267168871b5d442e472f53e9acbaf4377dd8108f9235588aa52"))
	(238490, uint256("0xf62f6fdd639dd9b84bbfefd342bb84e78bafc7298e066452209ff64c6571e9cd"))
	(240428, uint256("0x239601848b577ee7c78eabe080103a44cb1a4b2f725698b14b0d147ef52ed431"))	
	(244320, uint256("0xff2e6513bf9608b4746c7997fcee9db1cfe2c53dee2934a212455677894ed2d8"))	
	(246310, uint256("0xa1189be9c1d151408c22464fda611bfcd299b35e25c9a22485967a22e30d2ea6"))
	(250000, uint256("0x47dcf5af6663e73ef37835c13e549823ccfcac785dc2a93b09ec8b86f17459ff"))
	(251330, uint256("0xb9829efe534b7e41768b233365f96ad41eb295a9af536426ac86d43ebd7b0327"))
	(253360, uint256("0x69701cd2b66fb940302f14343aa5c4b63caec0c0d14731fbd1a1a9041b54323b"))
	(255000, uint256("0x070cc345cc22c00dfc575974d0023580c5e2c2100ccc13e4a2ab8a51427a0641"))
	(256850, uint256("0xc5681f8ca247e70386ca5e82f2ec799ce94834f5831e436e2b7a11070666de17"))
	(258000, uint256("0x61d003cd2b35d56f9b14eb246b631f2c4a6ae99a0ea9a066caeb875a01d7942b"))
	(260000, uint256("0xbf853e15ac3124c191c331dd8c89970ef617f0980daeb68d3a836d660e936a7f"))
	(262000, uint256("0x1c5ac7b79da6f210069943a51da80628eacc4549bd70126bbe025eaddcc1089b"))
	(263000, uint256("0x5a176aa9af4829a7ba65a2de00695c03ad7a306991a2c737edc65d7a718b9943"))
	(264000, uint256("0xa48f17b5440964f161446187d17f1b212f81340b116d1796691f2dc8ba399332"))
	(265000, uint256("0x4d7315d2fcba70a68a17723b5c25c770028d72fd67324cd05b48286140ed9187"))
	(266000, uint256("0xfef0b941b9722c80c69b2efb4aef775aa82ecc06556200e16a10155431e42b1c"))
	(267000, uint256("0x794554b179af4493e1384a0bad084c86670f5bfbf7ddab4d0e872f4fe22d29a9"))
	(268000, uint256("0x0e1c1ee480bcad255288aa970c295b9a7bc52c5484a7a3a30746279b7d44ea74"))
	(269000, uint256("0x2a7ca863e474e088e79d5f9351d740d1b06f7ef357cfd665916b4f4040215142"))
	(270000, uint256("0xa2f08e6680e0597308b31eb1bdb6a7c99dafa81398bc149c340e3e668d53bf27"))
	(271000, uint256("0x66dd65a76c121e09fa695176172c952e659b5ea00efbeb53e1ca845db149871a"))
	(272000, uint256("0x92fd8c3668cf4fc85bf9142a8f2fdd94d305d9bc3e782e4f87d77dde1429e416"))
	(273000, uint256("0x8de21759c002477f0b9dfc6f95878c59b44db34c1a78f08c985efaa6e93bc570"))
	(274000, uint256("0x625aa4f11a7e94dd7ec919fc110bf42db4039cd5d548b7599b75d49324463187"))
	(275000, uint256("0x11d44967c01a8e265ebe0f9652ceea65b1c66ebad437310827b7e5dd5f5065d6"))
	(276000, uint256("0x60716493329c2e9a5e0cbb277abd8e431ad62c0a06a3469b77778ae3957eb2f8"))
	(277000, uint256("0xaba51575fb764c091632b40e604bcce89e34091cd7e8c4d654a908ae098e1cfe"))
	(278000, uint256("0x12e16f638f0c19d6395497416d397db4d04fc0e4ecac8e4d7d310c1846fe36a7"))
	(279000, uint256("0x30cda75fe7b202ea41bf00641251974f67ff42c2468a4391c3aff971bef00433"))
	(280000, uint256("0x45b85307668b24d6c93e5fdbe9067fb7f8250e889a2a79bb9f034982dd020ec6"))
	(281000, uint256("0xc7fe48923d484b67ea8599c201d5c3436e3086691e075d2d98dba13f2c9fbf91"))
	(282000, uint256("0x9ad2a46ae93fdf23be42117f562a765dbfe7d491b9f618792da55442000b7464"))
	(283000, uint256("0xd9cc1c2d87f118183f792b9159e9947e40bf0691e3965b31b2e13355a1a17862"))
	(284000, uint256("0x0029c6a80012d2c3371836023c16e105d4c8810729c8e726f6c6f43bb82d6942"))
	(285000, uint256("0x20603e61721a3fefe57cce42ad6aa3443db09e9f367a24b40a32c8e28dee6717"))
	(286000, uint256("0x595bc423788f53c29afa04d55024066f4092064e5c8973da0eb23206774ece56"))
	(287000, uint256("0xf45b46202795dad6559915f6c47752b9db0a7168f0c841c20d4335215bd12b28"))
	(288000, uint256("0x6271c5f482ae8500367e89e4a89f8dc79eb285c5409b5a759a324d294700cf83"))
	(289000, uint256("0x7bc1f607419cf44d9cde644fbd332585a632379384bc3f917f11627798445daa"))
	(290000, uint256("0x203012324066ec0a9842f2d858a9bba08299d89a4a08a6961f65a9b8d2b9d94b"))
	(291000, uint256("0x79b22445022e3d00157943a3ef56d32958770fb2d064961a0061b947fa52b9d2"))
	(292000, uint256("0xe263af15a1a7dfeba5b70e3696bc029ad7b02ad6addad83074c6bf8d70af35c5"))
	(293000, uint256("0x5bcc6db219f0cf375923fcfc16fb6d7602022039bae2e0c1e02bba80e021ba6e"))
	(294000, uint256("0xf0f7e72c568ec764412bd517334286c27103a9f4dc6e4941ac022cdaa969d453"))
	(295000, uint256("0x523683bb0462998c0bf053111bba7d031e90079bf72f14e18a8faa1f649def5e"))
	(296000, uint256("0x0a7f31fb08b219af6b33890bb180503c88461dea656a5579dfc91bb4adec2e31"))
	(297000, uint256("0x7817a95aa710978e81bf471f91bbb864324eb0fb8af0c3a1ed43d267446e1070"))
	(298000, uint256("0xd0649dfb1d9fd1b790dfc3440aeb6b52b8d313fbd02e3a1753665c0f7b6b8c07"))
	(299000, uint256("0x98120d4ce168794e59e7887ca4ae85ec7fb1b520f114fb804a81fda0de510118"))
	(300000, uint256("0x0ad460bbd9bedd15008c17eaf0b1b71dd3a024cb90ad9a2f94a289c246107630"))
	(301000, uint256("0xb70167e3daf0be2efbdfc723a8b4db5a7384d644937dc1e598a869cc751db4e5"))
	(302000, uint256("0x0d82714748c82f371a0dba531175d03c5244748cb1b6465328312e72c2d43389"))
	(303000, uint256("0x41c78d22ebc42b9b191a49e29212c022f3f11b2962c3a7d2c09efb4e601cd1bd"))
	(304000, uint256("0x1a7358a971657472597a6f9fc4a7a871de6ae3faff9ec362e7b1f6ac79f4d334"))
	(305000, uint256("0xac9d7d14b34988fc8d7435348b0372e40dd13954dce95be9e2b8d80e9a145d3b"))
	(306000, uint256("0x68e02fc2408a70bf8e8c3a311b6e2ca6d7fea98dd3a9621aaa428a9d9260a305"))
	(307000, uint256("0x2e6161e3c8078390f2c76939fc0f0b23a40ecfaa3e19f986a1b58740ff9f845d"))
	(308000, uint256("0x52c214105b80d1c7ebf44236b244c412192a4cd30ef343cf76737b3f53e9427f"))
	(309000, uint256("0xf987c42cc78ccc5aebb6c688db1c7b4066a70545cb0ff87c77c6b4df65a46d0e"))
	(310000, uint256("0x501371505233c402bf2cfd6be54b5ad6903cc60368cd651511d5995f1e3c3416"))
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

        vSeeds.push_back(CDNSSeedData("seed1.ccy.network", "seed1.ccy.network"));
        vSeeds.push_back(CDNSSeedData("seed2.ccy.network", "seed2.ccy.network"));
        vSeeds.push_back(CDNSSeedData("seed3.ccy.network", "seed3.ccy.network"));
        vSeeds.push_back(CDNSSeedData("seed4.ccy.network", "seed4.ccy.network"));
        vSeeds.push_back(CDNSSeedData("seed5", "77.55.194.185"));
        vSeeds.push_back(CDNSSeedData("seed6", "167.86.84.123"));
	vSeeds.push_back(CDNSSeedData("seed7", "167.86.111.103"));

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


