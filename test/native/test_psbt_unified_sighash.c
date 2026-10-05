#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "psbt.h"
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_transaction.h>

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

#define MAX_SPENT 3

typedef struct {
    uint64_t amount;
    const char *script;
} spent_hex_t;

typedef struct {
    const char *tx;
    size_t input_idx;
    uint8_t hash_type;
    size_t num_spent;
    spent_hex_t spent[MAX_SPENT];
    const char *sighash;
} unified_vector_t;

/* Script type 2 rows of src/test/data/unified_sighash.json in Bitcoin Knots
 * v29.4.2.knots20260508, specified in doc/unified-sighash.md. */
static const unified_vector_t VECTORS[] = {
    {"0100000001c912714ed02bfbe45aa3b7c1f92b3bfc59e94ddb7ea263a3648dbb9c897bd2b40300000000000000000"
     "2e39d6002000000001514b1a1b9552e930d457b46ee4e0a54a8033d8da9cd69a36c050000000015142d72d2372c84"
     "25e95b93dfd296ad9fc276e104cd00000000",
     0,
     0x21,
     1,
     {{62739988ULL, "512096e0394492f9208afc6f8249db5a85c7c4b303f0eb4babb53c2a4c60b717fd1f"}},
     "973f75abf22f12402d185957809b0f29c3912d8359a5cff14c0f6709ec4ac88c"},
    {"0100000003d9d06499a5e20188a0896bb9e9f2b7af354d5810e876257a86161d9e934f013b020000000000000000c"
     "9cb65767352ef69f5780098b2e9c826ffb509a2fc78f05bc116d654400b1f200200000000ffffffff128c3d8bf349"
     "cf03e0cd01bb70bb8fab1bbe4be333d52994bc82e1cb93294af100000000000000000003908d78010000000015148"
     "01c17897609048ce6916f33e1a2960e5e1cbebd55df94000000000015145e4eb9cb533b05f2a0cb52d273e439aa5f"
     "09b5cb492c81010000000015145831ed6de553b2edea918937d64a71a854b4119620a10700",
     0,
     0x21,
     3,
     {{13520714ULL, "5120b8421ee8b865a1f71e130d25631a5aba852226e0c3834ffc5f0315f7502d0dc2"},
      {58184495ULL, "5120b8421ee8b865a1f71e130d25631a5aba852226e0c3834ffc5f0315f7502d0dc2"},
      {50718789ULL, "5120b8421ee8b865a1f71e130d25631a5aba852226e0c3834ffc5f0315f7502d0dc2"}},
     "95b0384e42d04a91170afbf5e5cd2433396e036ef4b9573b60d1a24ab4004a07"},
    {"020000000169311c8eee61185c20f4a14407dfa76adee0a641758a10a280f24a58f1afb0f70200000000ffffffff0"
     "23075f2030000000015147e290521bc345acc5d7e0728bd1e445171cbb76efe82ce00000000001514fae73c7a5992"
     "3ff6cfb7de7b9b48331ee7f45d9600000000",
     0,
     0xa1,
     1,
     {{22876442ULL, "5120548576bb76cbb2166296291188f9559831eb3aeda43d0ad7b9bd0937674090fc"}},
     "2ed17c56cd762bf56ab95022edf0fff86016335b436f8597a128167b1eb225fa"},
    {"020000000395c687717fce3e77bf2f6f0dd49941d18c6b05e02a151ac48dc3ccc9e89bb9eb0200000000fefffffff"
     "673d4d8475da382b47f3c3a5b5374e3e07309cd56e4a5bb5e61289cbed73ad50000000000ffffffff69719566c7ec"
     "f726b06a997fea4e26db4158dc9478f9f9e9010716b10aad09780000000000ffffffff03af8610030000000015147"
     "e55291e93281962eb83e5800f5326726c8c3922bcb76200000000001514c8254f8fe97690982258cbc1d380a8153b"
     "1b342321e8fb00000000001514a9a5d4ced4545d91f105f3a6ce4ba37887c4c21620a10700",
     0,
     0xa1,
     3,
     {{61074777ULL, "5120f2a3cf194eb894997c7ffcada558fe79d3988613cda32878de6dcd79ccd11123"},
      {89470188ULL, "5120f2a3cf194eb894997c7ffcada558fe79d3988613cda32878de6dcd79ccd11123"},
      {98421892ULL, "5120f2a3cf194eb894997c7ffcada558fe79d3988613cda32878de6dcd79ccd11123"}},
     "dd4be52e0a82db8f13d8cbccded9aa8cd2268f06cc57bdd3f31ae085a5d36fec"},
    {"0200000001dcd3fe4ab86e8a382a4c6c65704e6e4616f02dd02e1847df4018f55f00c742df0300000000feffffff0"
     "27d44160000000000151413fc98dbefd14ea516489e3c808c3894e1a153ac531ca401000000001514fccec46f3fc0"
     "92d39628b8e5feb1936d9f1ab37400000000",
     0,
     0x22,
     1,
     {{21058498ULL, "5120598bdf4e0170fda199c2029e49e4ec6e0bb9cd33588d45089f03921481405d4e"}},
     "7e206a8ae1bc2ddca7971f3d513acb932e1b6c198c5fbce075d1092224991b8d"},
    {"02000000033a3a37b73343d17e9489dc50bbb115e7b2ae3058004f6b29b55f0d56cc46b396030000000000000000c"
     "ca24f6b4cf148c03adf6b4d9f24209839c787c6318450a3a806f32091f7c5070000000000ffffffff8c3e757bbda3"
     "37f5b34a4b3d3948294c8519615de2f3b853aac96a22df2a30930000000000ffffffff03781532020000000015147"
     "76947a4c26cdd82b83f38bfa3c4250b4efeb0c6816bf300000000001514b021b1f29cb02d3d629b630f8b878cfc48"
     "85694eeea8f60300000000151422e3097a04d83b5f3b85bb5d1f0614c7ad7aac1c00000000",
     0,
     0x22,
     3,
     {{22006403ULL, "5120d77e3a4f9a6b386816ac3854b808862bc0c2087c0c086a9c02f866607df735d0"},
      {75887238ULL, "5120d77e3a4f9a6b386816ac3854b808862bc0c2087c0c086a9c02f866607df735d0"},
      {34417848ULL, "5120d77e3a4f9a6b386816ac3854b808862bc0c2087c0c086a9c02f866607df735d0"}},
     "bc9eb934df69f98f3b6b249a0290fb642f62711c35c79b9f9c9700ab6c2b76d0"},
    {"0200000001f2f243d5f493a2272c2babbf92c5875e8c9ca96de7ef638263e4048d576b70b10000000000000000000"
     "28ebe3a05000000001514d338ce1e75c2ca8896cd82b57132ad944e3504d5fa5b2704000000001514d5063330a2f1"
     "ef8fd51305debc0276ea183afbbc20a10700",
     0,
     0xa2,
     1,
     {{43989297ULL, "5120a127b13e502eb8d4ccdea718fa7a6d9b12d4c61c4de590e82ef1538e51b67bcc"}},
     "9219d44c6046c9ec02a41c68ce1e7bef0d6f7a1fb95dc2533e2b729b6a47499d"},
    {"0100000003514c6eafda58ff2283c06aafc564d9f677d2ec86a5b6cede502a1818da7183080000000000feffffff8"
     "62514ab6e9e2d7d23dbc0405920f974e56ed475c356d0ee96bafaa0346763ff02000000000000000093a636575756"
     "f2cd86f00cbb72f7939a806adcc61b59711f5fb646101f90f7990000000000ffffffff035527b701000000001514a"
     "c16fcfcc05b2f837ec590c840006726aedc0eaa0fb5c605000000001514a091477fa31df3ebf46d60a22e2576cf87"
     "aee3cc74e5a700000000001514840bdd46d55a7f18350de0fce49a0e205e0f259800000000",
     0,
     0xa2,
     3,
     {{61567982ULL, "512092c84ed3c9a93fb2347b57388a5fc16fb6a3cec57cb614073056c18e30bc80e2"},
      {83278909ULL, "512092c84ed3c9a93fb2347b57388a5fc16fb6a3cec57cb614073056c18e30bc80e2"},
      {46276334ULL, "512092c84ed3c9a93fb2347b57388a5fc16fb6a3cec57cb614073056c18e30bc80e2"}},
     "0b2e3b6cd660fa269729c56f874b2b93c33d809c2cab14faf50e5ae7c8abd530"},
    {"02000000010ba3ffe5ce2fe0b27650f00a275981bcd1ca36cd6da7e3cc9fced353f445eab70300000000ffffffff0"
     "201665000000000001514bc5930018796b95b5d34d9b0023466a70541f799d20df9000000000015147ba381de279c"
     "23f784d09327158c2aae5ccfb6dd20a10700",
     0,
     0x23,
     1,
     {{80061498ULL, "512093b56ff9c06b16e39cab267044802f3b55a3cd5e07cfa6ee20b291c0ba0fb9b6"}},
     "54caff36b98a532cd8f42de93e32853eed6d2fa92d142aa3e405825ec3f7e641"},
    {"0200000003393fd515608cb3291481a606f74d571f50aa46260dea3be6a4c1516402790efc0300000000ffffffff0"
     "97c114c8e5d4252bc36a92cf752d832c6118a5f4f50b8ce002547a3dced366b0000000000feffffffb9de2f7bd33b"
     "96857ad3fa88ce2b67fd6b9339ac66d2ac4bcbf3014692c866490100000000feffffff03378ca503000000001514e"
     "b69cf2e1c385a203ca047335d99d0c2a61571d6726212050000000015147060d788fe0133881ef1a5a869f834bbc6"
     "8dfb8e4a3d59030000000015141a20dde74b4f72785a209bb7ff5c2dfb246b0f6120a10700",
     0,
     0x23,
     3,
     {{53579443ULL, "5120e9cebaaf1a7f4ff7d3ac8d862a62e5dfb30709dc6b74f360d19340e75c559e8a"},
      {69471874ULL, "5120e9cebaaf1a7f4ff7d3ac8d862a62e5dfb30709dc6b74f360d19340e75c559e8a"},
      {47458042ULL, "5120e9cebaaf1a7f4ff7d3ac8d862a62e5dfb30709dc6b74f360d19340e75c559e8a"}},
     "250379bde1e19cdcd15725b35b01ca1af602b8ed3b7f5a432950b51176e7c33b"},
    {"0200000001b2dd2b219b05bfd67542a21bf64a995b70c0698b0d2a66283cf875a7252c85720300000000000000000"
     "221f6e3040000000015144842b013cede9676c6519b9a447b58935cc12844931cdb00000000001514fd5ab544c975"
     "6698d4507d600a93dd2fb0701fc520a10700",
     0,
     0xa3,
     1,
     {{13234387ULL, "5120959e6ba5f72fa657941056a644f5d99f86e042312152a9d981ee3a228055d8d6"}},
     "3a22182ad7c2457c7fe1a9fb206349303df90003f3983dc7c14625142f597576"},
    {"01000000036c282f291c6d293c415cdd0bbcb2b50821afab2b875843415c1bb3a715f5e6150200000000ffffffff4"
     "cd42852e312fcaf1c5b23664152b19fac4492fdaf446fdcece8f16fa8b5080e0100000000feffffff483299ae107a"
     "5a65a8fe7e7f4cde8da058437edb73fc8b708a056b6e2115d4f20100000000feffffff038ca11803000000001514b"
     "2d89ff249c45890f4db822d490a44510ec24e02f77c8c0300000000151415a24a075100ec88a3050282ef175c3fcc"
     "b4262da7a5cd05000000001514fdaf4cbf977e926c0662a125a3be6be66d7800eb20a10700",
     0,
     0xa3,
     3,
     {{55011288ULL, "51205af5a28a31fb38c866a0dd83407cdb0a60381f85d74257f6ff5ab9ce25030ec2"},
      {69494961ULL, "51205af5a28a31fb38c866a0dd83407cdb0a60381f85d74257f6ff5ab9ce25030ec2"},
      {40733133ULL, "51205af5a28a31fb38c866a0dd83407cdb0a60381f85d74257f6ff5ab9ce25030ec2"}},
     "7e8a585934ca0ee2d129952ec14084338cb83ed53a9275a0569d1e0025ad4f96"},
};

#define NUM_VECTORS (sizeof(VECTORS) / sizeof(VECTORS[0]))

typedef struct {
    struct wally_tx *tx;
    struct wally_tx_output spent[MAX_SPENT];
    unsigned char scripts[MAX_SPENT][64];
    unsigned char expected[32];
} loaded_vector_t;

static int load_vector(const unified_vector_t *v, loaded_vector_t *out) {
    memset(out, 0, sizeof(*out));
    if (wally_tx_from_hex(v->tx, 0, &out->tx) != WALLY_OK || !out->tx ||
        out->tx->num_inputs != v->num_spent) {
        return -1;
    }
    for (size_t i = 0; i < v->num_spent; i++) {
        size_t written = 0;
        if (wally_hex_to_bytes(v->spent[i].script, out->scripts[i], sizeof(out->scripts[i]),
                               &written) != WALLY_OK) {
            return -1;
        }
        out->spent[i].satoshi = v->spent[i].amount;
        out->spent[i].script = out->scripts[i];
        out->spent[i].script_len = written;
    }
    size_t written = 0;
    if (wally_hex_to_bytes(v->sighash, out->expected, 32, &written) != WALLY_OK || written != 32) {
        return -1;
    }
    return 0;
}

static int test_vectors(void) {
    TEST("unified sighash matches every script type 2 vector");
    for (size_t i = 0; i < NUM_VECTORS; i++) {
        loaded_vector_t lv;
        if (load_vector(&VECTORS[i], &lv) != 0) {
            wally_tx_free(lv.tx);
            FAIL("could not load vector");
        }
        uint8_t got[32];
        int ret = psbt_unified_sighash_taproot(lv.tx, VECTORS[i].input_idx, lv.spent,
                                               VECTORS[i].hash_type, got);
        wally_tx_free(lv.tx);
        if (ret != 0 || memcmp(got, lv.expected, 32) != 0) {
            printf("    vector %zu (hash type 0x%02x)\n", i, VECTORS[i].hash_type);
            FAIL("sighash mismatch");
        }
    }
    PASS();
    return 0;
}

static int test_rejects_invalid_hash_types(void) {
    TEST("hash types outside the taproot set are refused");
    loaded_vector_t lv;
    if (load_vector(&VECTORS[0], &lv) != 0) {
        wally_tx_free(lv.tx);
        FAIL("could not load vector");
    }
    static const uint8_t bad[] = {0x00, 0x01, 0x20, 0x24, 0x61, 0x81, 0xa0, 0xe1, 0x3f};
    for (size_t i = 0; i < sizeof(bad); i++) {
        uint8_t got[32];
        if (psbt_unified_sighash_taproot(lv.tx, 0, lv.spent, bad[i], got) == 0) {
            wally_tx_free(lv.tx);
            printf("    hash type 0x%02x\n", bad[i]);
            FAIL("accepted an invalid hash type");
        }
    }
    uint8_t got[32];
    int idx_ret = psbt_unified_sighash_taproot(lv.tx, lv.tx->num_inputs, lv.spent, 0x21, got);
    wally_tx_free(lv.tx);
    if (idx_ret == 0) {
        FAIL("accepted an out of range input index");
    }
    PASS();
    return 0;
}

static int test_single_without_output(void) {
    TEST("SINGLE with no output at the input index is refused");
    loaded_vector_t lv;
    if (load_vector(&VECTORS[0], &lv) != 0) {
        wally_tx_free(lv.tx);
        FAIL("could not load vector");
    }
    while (lv.tx->num_outputs > 0) {
        if (wally_tx_remove_output(lv.tx, 0) != WALLY_OK) {
            wally_tx_free(lv.tx);
            FAIL("could not remove output");
        }
    }
    uint8_t got[32];
    int single = psbt_unified_sighash_taproot(lv.tx, 0, lv.spent, 0x23, got);
    int single_acp = psbt_unified_sighash_taproot(lv.tx, 0, lv.spent, 0xa3, got);
    int none = psbt_unified_sighash_taproot(lv.tx, 0, lv.spent, 0x22, got);
    wally_tx_free(lv.tx);
    if (single == 0 || single_acp == 0) {
        FAIL("signed SINGLE with no matching output");
    }
    if (none != 0) {
        FAIL("NONE should not need an output");
    }
    PASS();
    return 0;
}

static char *psbt_for_vector(const unified_vector_t *v, uint32_t sighash,
                             const char *override_script) {
    loaded_vector_t lv;
    struct wally_psbt *psbt = NULL;
    char *b64 = NULL;
    if (load_vector(v, &lv) != 0) {
        goto out;
    }
    if (wally_psbt_from_tx(lv.tx, 0, 0, &psbt) != WALLY_OK) {
        goto out;
    }
    for (size_t i = 0; i < v->num_spent; i++) {
        struct wally_tx_output *utxo = NULL;
        unsigned char script[64];
        size_t script_len = lv.spent[i].script_len;
        memcpy(script, lv.spent[i].script, script_len);
        if (override_script && i == v->input_idx) {
            wally_hex_to_bytes(override_script, script, sizeof(script), &script_len);
        }
        if (wally_tx_output_init_alloc(lv.spent[i].satoshi, script, script_len, &utxo) !=
            WALLY_OK) {
            goto out;
        }
        int ret = wally_psbt_input_set_witness_utxo(&psbt->inputs[i], utxo);
        wally_tx_output_free(utxo);
        if (ret != WALLY_OK) {
            goto out;
        }
    }
    if (sighash && wally_psbt_input_set_sighash(&psbt->inputs[v->input_idx], sighash) != WALLY_OK) {
        goto out;
    }
    wally_psbt_to_base64(psbt, 0, &b64);
out:
    wally_psbt_free(psbt);
    wally_tx_free(lv.tx);
    return b64;
}

static int test_psbt_unified_vectors(void) {
    TEST("psbt_get_sighash computes ALL|UNIFIED for the PSBT form of each 0x21 vector");
    size_t checked = 0;
    for (size_t i = 0; i < NUM_VECTORS; i++) {
        if (VECTORS[i].hash_type != PSBT_SIGHASH_ALL_UNIFIED) {
            continue;
        }
        char *b64 = psbt_for_vector(&VECTORS[i], PSBT_SIGHASH_ALL_UNIFIED, NULL);
        if (!b64) {
            FAIL("could not build PSBT");
        }
        uint8_t got[32], expected[32];
        uint8_t type = 0;
        size_t written;
        int ret = psbt_get_sighash(b64, VECTORS[i].input_idx, got, &type);
        wally_free_string(b64);
        wally_hex_to_bytes(VECTORS[i].sighash, expected, 32, &written);
        if (ret != 0 || type != PSBT_SIGHASH_ALL_UNIFIED || memcmp(got, expected, 32) != 0) {
            FAIL("PSBT sighash does not match the vector");
        }
        checked++;
    }
    if (checked == 0) {
        FAIL("no 0x21 vectors");
    }
    PASS();
    return 0;
}

static int test_psbt_sighash_allowlist(void) {
    TEST("psbt_get_sighash refuses every host-requested type except DEFAULT, ALL and ALL|UNIFIED");
    static const uint32_t refused[] = {0x02, 0x03, 0x81, 0x82, 0x83, 0x22, 0x23, 0xa1, 0x20, 0x41};
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        char *b64 = psbt_for_vector(&VECTORS[0], refused[i], NULL);
        if (!b64) {
            FAIL("could not build PSBT");
        }
        uint8_t got[32];
        uint8_t type = 0xff;
        int ret = psbt_get_sighash(b64, VECTORS[0].input_idx, got, &type);
        wally_free_string(b64);
        if (ret != PSBT_ERR_SIGHASH_TYPE) {
            printf("    sighash 0x%02x returned %d\n", (unsigned)refused[i], ret);
            FAIL("expected PSBT_ERR_SIGHASH_TYPE");
        }
    }
    static const uint32_t accepted[] = {0x00, 0x01};
    for (size_t i = 0; i < 2; i++) {
        char *b64 = psbt_for_vector(&VECTORS[0], accepted[i], NULL);
        if (!b64) {
            FAIL("could not build PSBT");
        }
        uint8_t got[32];
        uint8_t type = 0xff;
        int ret = psbt_get_sighash(b64, VECTORS[0].input_idx, got, &type);
        wally_free_string(b64);
        if (ret != 0 || type != accepted[i]) {
            printf("    sighash 0x%02x returned %d\n", (unsigned)accepted[i], ret);
            FAIL("legacy taproot sighash refused");
        }
    }
    PASS();
    return 0;
}

static int test_psbt_unified_requires_p2tr(void) {
    TEST("ALL|UNIFIED is refused for an input that is not P2TR");
    const char *p2wpkh = "0014751e76e8199196d454941c45d1b3a323f1433bd6";
    char *b64 = psbt_for_vector(&VECTORS[0], PSBT_SIGHASH_ALL_UNIFIED, p2wpkh);
    if (!b64) {
        FAIL("could not build PSBT");
    }
    uint8_t got[32];
    uint8_t type = 0xff;
    int ret = psbt_get_sighash(b64, VECTORS[0].input_idx, got, &type);
    wally_free_string(b64);
    if (ret == 0) {
        FAIL("signed a non-taproot input under ALL|UNIFIED");
    }
    PASS();
    return 0;
}

static int test_psbt_non_witness_utxo_vout(void) {
    TEST("a v0 PSBT input carrying only non_witness_utxo commits the output at its vout");
    static const unsigned char p2tr[34] = {0x51, 0x20, 1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                           11,   12,   13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                           23,   24,   25, 26, 27, 28, 29, 30, 31, 32};
    static const unsigned char decoy[22] = {0x00, 0x14, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    const uint64_t spent_amount = 500000, decoy_amount = 1000;
    struct wally_tx *prev = NULL, *tx = NULL;
    struct wally_psbt *psbt = NULL;
    char *b64 = NULL;
    int failed = 1;
    unsigned char prev_txid[32];
    static const unsigned char zero_hash[32] = {0};

    if (wally_tx_init_alloc(2, 0, 1, 2, &prev) != WALLY_OK ||
        wally_tx_add_raw_input(prev, zero_hash, 32, 0, 0xffffffff, NULL, 0, NULL, 0) != WALLY_OK ||
        wally_tx_add_raw_output(prev, decoy_amount, decoy, sizeof(decoy), 0) != WALLY_OK ||
        wally_tx_add_raw_output(prev, spent_amount, p2tr, sizeof(p2tr), 0) != WALLY_OK ||
        wally_tx_get_txid(prev, prev_txid, 32) != WALLY_OK ||
        wally_tx_init_alloc(2, 0, 1, 1, &tx) != WALLY_OK ||
        wally_tx_add_raw_input(tx, prev_txid, 32, 1, 0xfffffffd, NULL, 0, NULL, 0) != WALLY_OK ||
        wally_tx_add_raw_output(tx, 499000, p2tr, sizeof(p2tr), 0) != WALLY_OK ||
        wally_psbt_from_tx(tx, 0, 0, &psbt) != WALLY_OK ||
        wally_psbt_set_input_utxo(psbt, 0, prev) != WALLY_OK ||
        wally_psbt_input_set_sighash(&psbt->inputs[0], PSBT_SIGHASH_ALL_UNIFIED) != WALLY_OK ||
        wally_psbt_to_base64(psbt, 0, &b64) != WALLY_OK) {
        printf("    could not build PSBT\n");
        goto out;
    }

    struct wally_tx_output spent = {0};
    spent.satoshi = spent_amount;
    spent.script = (unsigned char *)p2tr;
    spent.script_len = sizeof(p2tr);
    uint8_t expected[32], got[32];
    uint8_t type = 0;
    if (psbt_unified_sighash_taproot(tx, 0, &spent, PSBT_SIGHASH_ALL_UNIFIED, expected) != 0) {
        printf("    reference sighash failed\n");
        goto out;
    }
    if (psbt_get_sighash(b64, 0, got, &type) != 0 || type != PSBT_SIGHASH_ALL_UNIFIED ||
        memcmp(got, expected, 32) != 0) {
        printf("    sighash does not commit the output at vout 1\n");
        goto out;
    }
    psbt_summary_t summary;
    if (psbt_parse(b64, &summary) != 0 || summary.total_in_sats != spent_amount) {
        printf("    psbt_parse summed the wrong input amount\n");
        goto out;
    }
    failed = 0;
out:
    wally_free_string(b64);
    wally_psbt_free(psbt);
    wally_tx_free(tx);
    wally_tx_free(prev);
    if (failed) {
        FAIL("non_witness_utxo lookup");
    }
    PASS();
    return 0;
}

int main(void) {
    printf("\n=== Unified Sighash Tests ===\n\n");
    if (wally_init(0) != WALLY_OK) {
        printf("FATAL: wally_init failed\n");
        return 1;
    }
    int failures = 0;
    failures += test_vectors();
    failures += test_rejects_invalid_hash_types();
    failures += test_single_without_output();
    failures += test_psbt_unified_vectors();
    failures += test_psbt_sighash_allowlist();
    failures += test_psbt_unified_requires_p2tr();
    failures += test_psbt_non_witness_utxo_vout();
    wally_cleanup(0);
    printf("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
