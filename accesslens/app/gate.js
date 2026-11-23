var ALGate = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // src/gate.mjs
  var gate_exports = {};
  __export(gate_exports, {
    FREE_MAX_ROWS: () => FREE_MAX_ROWS,
    FREE_MAX_TABLES: () => FREE_MAX_TABLES,
    GATED_ACTIONS: () => GATED_ACTIONS,
    KEY_EMPTY_REASON: () => KEY_EMPTY_REASON,
    KEY_NOT_FOUND_REASON: () => KEY_NOT_FOUND_REASON,
    PRO_KEY: () => PRO_KEY,
    checkLicenseKey: () => checkLicenseKey,
    clearPro: () => clearPro,
    dbSize: () => dbSize,
    evaluate: () => evaluate,
    isGatedAction: () => isGatedAction,
    keyHashCount: () => keyHashCount,
    proMessage: () => proMessage,
    rate: () => rate_exports,
    readPro: () => readPro,
    wallMessage: () => wallMessage,
    withinFreeLimits: () => withinFreeLimits,
    writePro: () => writePro
  });

  // src/keycrypto.mjs
  var KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  var KEY_GROUPS = 5;
  var KEY_GROUP_LEN = 5;
  var KEY_LENGTH = KEY_GROUPS * KEY_GROUP_LEN;
  var HASH_HEX_LEN = 32;
  var HASH_DOMAIN = "accesslens-pro-key-v1:";
  function normalizeKey(raw) {
    return String(raw == null ? "" : raw).toUpperCase().replace(/[^A-Z2-9]/g, "");
  }
  function isWellFormedKey(normalized) {
    if (typeof normalized !== "string" || normalized.length !== KEY_LENGTH) return false;
    for (const ch of normalized) if (!KEY_ALPHABET.includes(ch)) return false;
    return true;
  }
  function formatKey(normalized) {
    const groups = [];
    for (let i = 0; i < normalized.length; i += KEY_GROUP_LEN) groups.push(normalized.slice(i, i + KEY_GROUP_LEN));
    return groups.join("-");
  }
  async function hashKey(normalized) {
    const bytes = new TextEncoder().encode(HASH_DOMAIN + normalized);
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("").slice(0, HASH_HEX_LEN);
  }

  // src/keyhashes.mjs
  var KEY_HASHES = [
    "015c049e12ed2a10be4060e1b3b6768c",
    "01ce9ac1d168fac365a1ff97de77fedb",
    "0284e99b56f2ec8093440597327745c8",
    "0411dceada7a45db747de2b79894a233",
    "050d08fbc8e46357397b05fae0a73972",
    "05dd01284b3ca637577e1bd93472b8df",
    "06b6291bafc2147b1e72b44ffe96cf47",
    "07200fb63419d2c0d7202d1a731a4bf6",
    "08abf98d791efa526b3283c30bbc0567",
    "0b581c5184b24a79ccba0e98a6034167",
    "0baaa694b22d15929c9c6ef5ffb461d1",
    "0c4302686769534f4fb67b1d3ebfebbc",
    "0c5f178d0da4474ded3518840e3e22b9",
    "0cd45810f5fe5a6c4849951b640665d8",
    "0cd9c556b41e527be7a9e0149337d7b6",
    "0dd00e407a203cddd78f6bb059d8863f",
    "0ddf23af3532529e5faaf7111092c731",
    "0e4e33c23123f177dffab6fe361d806d",
    "11587e5ca54464004e1d97630e2437b3",
    "12b2d441c82f31a6135404260e39cbdc",
    "12cb9aa55c00041f400f7a75244ab807",
    "12ea76106c824e1d6f7b3e012e4de354",
    "135fbb10738567d51d5bde9787d1620d",
    "13afcbdb7d313e46ee0d1a7039be8c6e",
    "13dd5166a5341b4aa2c2508abb589463",
    "13e248927febcf70409eb2c40edc0af0",
    "146a719853697783600e6ee75040a619",
    "1490c7315de895c5cd4d5a704a368eca",
    "14c11fdf37bad566b57c405fcad2ae98",
    "15f9d20621202da79759165b421a82a4",
    "164df4153075f462048da42ecb3daa98",
    "1680fa3387db4e5c5fd19fa1d8eda37b",
    "1763711377f1b4dc33e5b7651bae6948",
    "1770341ea773ae3ff699eb5da1e8b2c5",
    "178e202f77542f90fe6cc1ba66f27d3f",
    "17cb5fa724c03cceccd21828ea019cce",
    "17f60963e363ab7b2f546a6fe722e8c3",
    "18469a46362d85b3d1aa3c8e8fb02d1b",
    "1863c563079dc9359cfe62caea7cc648",
    "1913a2305eb19c56f5633444e8ad6bcd",
    "194088d2709ccb5e2ba361f247982ea9",
    "197d958f5b32ee8a0966db35ef7910c9",
    "1ad1681a68017007353f8cbf48e4f33b",
    "1bbd9a56a7a4d2e620d0552035416b5f",
    "1bda6dc93adab9f7aac6c7f827ff6a4d",
    "1bed564f1611c7bcc21929121aaed569",
    "1c34e25f895b9acc34f5d61fa0218c55",
    "1c450afdb2aefcf2b07ccf038207dbf8",
    "1c65c82ad035791c7d0a8e09ab12b0cd",
    "1ced6c8d726303634c99bb8e2b248a72",
    "1d7ea4e97916924793fbd9357512677e",
    "1ded1ecd8d15e9747cf6fa0f79602b5a",
    "1e10579249e0e060d83f9f5a8493517e",
    "1e9d3ec15a59f7adea2e90dcc3ac48d8",
    "1ecffd54435a74ccd8ac48d8305a3826",
    "1ed440bc4e32c2dcd120bf2303d80261",
    "1f55ef29d29dba6be9e11bbb5f26014e",
    "1f9e1a3d96d670ff05a9d5e697f283e7",
    "1fff525ca4e51ed81b67cf83e578cf0a",
    "2008d91e4823d68c350629374aa77930",
    "20411b8cab81715aa0bf9d750eb016e4",
    "205a2598e34cbe9efd7c07aa5446d3fa",
    "206d5ad21889ee8ac08388d485d12aeb",
    "2096f8fac4a308328d5983af811021de",
    "20bb2d1fca66805fac213e781b0fc9c7",
    "20fbdbd5bf56db7525e26b1d279c160d",
    "21c3ab5be2933194d3ca6185c528b058",
    "21f4ff0d6c07ab2c0b298b0e1eeb1d8a",
    "21f631bd8d550f61eccf7aeb68e0bc0f",
    "22c953b6828fda7e2a14e1df464e91d6",
    "22d63e61d7f950b5df383d1e9d44f1ad",
    "23092403f96bcbd97fdd4f6cc43ead81",
    "23c6fb2378dbf5ca66664fed86a0220c",
    "247cea8bb30fb6ccbee67ea19d241aac",
    "248638136bc731cdcbd5a6bd6f0f6f36",
    "253bd71454cf6b6ea14834cd2b526010",
    "253c32cc6b242cf749d3af33c148b28c",
    "260d5a33e846d98af030138573c5c62b",
    "26b99555d1316e26a62a5148063bc297",
    "27b173a00ebbea9fc612412fc8fa6751",
    "2855f1a5d0cb9d68b954f5f105630bb8",
    "28fefe4a8d8a0190dcb5bb5c072a7727",
    "299bf5e9dc2f80952b0bb5eb6c09cad4",
    "29dd6fa3c8f5eee6a63f8b78c9b0ac02",
    "2bef0c8f1ddd5c05e6addd097ef0d6f3",
    "2c42f671626bea35b5c72ef3d263c91d",
    "2d5c710a2215976361a7b8e4a266a644",
    "2ddf2a847c6e34debefecf0a7718ac48",
    "2ea30cf804f3a880c47fae56e41d0e26",
    "2f2cacc252c05917cde814677d3e6acc",
    "2fbd59f705b0658a24238d1a8c7d8d1a",
    "2fcadfdeae6d7ab13ff0d0675df07d96",
    "2ffdeeed6e6bcb96023e6847029768d3",
    "30697cf65cbacfafc9181f38841c3e87",
    "30c22de5bda5c4180f2664a19a86cc1d",
    "31f734e21e6872c2bf8f883866b85d91",
    "322938c4d6e21d935b4e9088519a6e42",
    "322f2c4ff54778b7d644ad7b08f598dd",
    "32e604838d7dce2e4af4f6c559516245",
    "335c06e2b25c88f01866e07ab215f88d",
    "338aa250c52571d7a2e8e771315ad8ee",
    "340a1afae6403e9cc70e5c2f13b272af",
    "3597a47e9f851259150c9cc4715e4b05",
    "35b8debef27c93a21edaf4bebae88ee4",
    "35c2cd82f102134142e8478213fe4645",
    "35ffeeed5c57aabfad895922ba214eb6",
    "36ab7f9c3c6b3220a44f52286b23ce7a",
    "36f57a143f89c25d75dcf9a674bb57ae",
    "373f66d8ae573c922602ebe8d87bcfce",
    "37ca16f8a5a8f1238bdb89fe83141c72",
    "3826c9977bf70bcb0fc99a0ce6c0db76",
    "38a9d6240bee71ea0ba56790857746a7",
    "38c279f992f2f87218b2ce435aec4a2e",
    "3906d9edc9c56ad861b1f8e62c50e53f",
    "39da4191ab29af3a1719454d061a5726",
    "3a5be9a5fef8a0984bf83873b0a9ac09",
    "3a79ef7a71be0910c9a007e34fb8264c",
    "3ace3265a0e0d2c3f14c2235a365deee",
    "3b0306b5e9f324ffdd172dbe028f405c",
    "3b0a4148354be8956c4383956dc8686d",
    "3b182e5fac6e9b578f8a249d0b7b8494",
    "3b1cd5ffcd6319f8be3e7424efd9d733",
    "3b366a2fa3f2b523499e17a127b6c149",
    "3b59f657d6665ebb02ff7d6f5be3f20c",
    "3c5191c5d0b600bd183fb6e29ca682b8",
    "3c63b31e3a6d146a791e619889be895c",
    "3c86ead937dedc8b5dbc892c7ef0e320",
    "3d3e7a67ba04ef0d129bda23cc86270a",
    "3d82d6d9cff02cda42ed5156ac2b3d5c",
    "3f13afe5b13cb1e1b98d0250fe62c780",
    "3f4371dbc72e23418b099a9ebf2f45e4",
    "413b04e4ef89ad3331fc7d94de04cd4f",
    "41bb2365890646e109dcbd67c2cbdb11",
    "42159b4d504eaf21fe7e0a114491e474",
    "4250d4d1759a6ee248bb3dc4595515a3",
    "4266dd1ce24d66775bc61ab2ac894fae",
    "42bd7ccdb472d4df53dc92a2f1af7df1",
    "43686e012a9c08add717a4ee6117bb66",
    "43c14f25c1244a78003bcde1251bdd67",
    "43e2b96cb8255805918763115e38c585",
    "443d4def6de0596d13ee3d9633e39180",
    "450d6914dcb3ff251f1c8087ed7f125b",
    "451232cca131ab110e8f1753c8ab88c7",
    "45765ff849d3a1ff898ec3c4febba7e6",
    "46d37c130dfacb055311d73a043804f0",
    "4b5e134cddd407edf92122fd617a6cc7",
    "4b8532a10bf94e9c984420c03d96ed80",
    "4bc5f4447988e4a6bd12d41ec1a00b82",
    "4c3bf210849f5a4fec61a1d05443a43d",
    "4c6a5393ec934168677201a78719a7ed",
    "4d9aa5d5c2f79cd8b54b9e602a78c374",
    "4dc904c1b1092889d69bca4eb8e2c411",
    "4e50277a82b7ba7ead5ce09d1933bce0",
    "4e6bf8b4af27a1f7736039dbe5c84604",
    "4f2bee2cf2e63bcfb22a5819b3f84388",
    "4f6877b20663be9158aea571ba859891",
    "4f806db432b05e532044d22bffaf3842",
    "501e4b7d98aea9f52244c18f833cabc3",
    "503449d3118a944cf8f4854f130d0eda",
    "50b279a18420b94c485f6ee9402d86ab",
    "50fc11b8e30d005989bdc73828f5e5cc",
    "5102e6a9a5d405ab86e31f41b9e0fca0",
    "5134be73305ab6b7303c1a10a20e6e65",
    "524f642a48e392143442278d8416653b",
    "525ee8f85fb38f14017956f312bcbead",
    "52b5c0b2b9b9fadf313c71626b163616",
    "52bcde376bd94c23e70069a3015c3c32",
    "52bd357ce5601de7539368cc3f9b8d93",
    "52d6c057c0ab779e98f079b8edee491e",
    "5319307586dc1d74d240187ae0353218",
    "534bf11a76b1aaec23f7de54aec21d50",
    "536f2b95f8d52d9c3f5aef7b2ebc48d8",
    "5372b7f1657a808567e3e3220a1638e8",
    "53a0e7e0e43695d15dc24e246594ad28",
    "54fff70c5c776e8d1ee58ff1f97b8aa6",
    "552cf1e17d3873a04d1067e23bce3aa0",
    "55b2bb636f3d36e02f5044ef40cb777a",
    "55eefa10b0a1b84985f619482ac17764",
    "565253b7e2d640e037c2c380c51cb57b",
    "56c005ea49d50325d810c72e830226ad",
    "56c8e2cf4d51f8e936cc23c8430ee5fe",
    "5778c63a1022ebfec1de5181014ead4d",
    "588d096ccfad960473749b120f704294",
    "58fcfdb25ff313bb8ef1186f0ed78b11",
    "591c39ddacdfb0af624d63ed6d2ec740",
    "59f2e20de3acd6315394c3927005761e",
    "59f875b2ade521d65b5a07a3ff41ef3e",
    "5a1677b411ecb12e1c36c39fc851a083",
    "5ad0f042606ab9ba6b4a58e55935c424",
    "5af13ec32b93b1381d6105b89c32e008",
    "5b54163ed6c5a58f717ae429c706e581",
    "5c4f8d50097847f34bf536bdf7f33cbb",
    "5cfccf861628e1c841ba5ad77cbd5a0a",
    "5d6c5ec6e7197acb0dc41b7095b74e2c",
    "5d78e289baa7cd9a9da334d59b6d7e6b",
    "5d88b6580d7e365dce48a1ea4d36794f",
    "5f031df4bde0766b8b70acdbe1effcdb",
    "5faab9904bbd8a0fa66b6d55eaaf43ae",
    "61606d0eee112516e0fe9425883555c6",
    "61698305f34eb66f99206de4787ef995",
    "6193cd1de56c337e4c0042363f7f6203",
    "6253f596d4e05101327a5b5e750258fd",
    "6262ef437922e3323b159f0a91850c7b",
    "62e895da2fdab67f7454888fa0fa4f46",
    "63675df9e3193523928b13e4f63e223b",
    "63d6327aa8224cfe1da8b21b2b47fe6f",
    "6418b7794c040227761140fcca91b1e5",
    "641b4e3fe03444c68224393441a5f3a5",
    "65c18b552d6221604c5408fa9390f645",
    "65cb95421d9a6ddd8ffbd15eea8bcdad",
    "65fc99229dea8fcfb0fc05225eacae42",
    "668c0daa875a9a1951f0c10748eb7520",
    "66a368b10be762e45d693e2cd6274105",
    "671004217878052cc32d7a7365a1e735",
    "67a6fb4ba9b0c9826733a7ef89fc7d9e",
    "67e19a9bd5875a40f24852911f826625",
    "682209810352877a1887a78e6aecaa9e",
    "684abc758698d5b9b700b1135279b039",
    "699560e2f9f6d9d9eb4f50c69909cfd8",
    "69d86cd953d8868347f2122d3d0ea96d",
    "6a16e2b243bd773aa02b413a13fd2f0b",
    "6a6e9d97aed697b153d685abbda034c0",
    "6af85e394c31f3de4318c07766e70b99",
    "6b9c39b6636f86393d9afa316cafc883",
    "6cded00f32446da1a9032f1dc9d3d6cd",
    "6d0c414b245a9201dce0926def2be3ac",
    "6d1c721c8ff66b3281fdc6181ae5e6a7",
    "6e971287e54c777988e07d32a9925b9b",
    "6ee1d60d630cdd3fa554f76b71b8e053",
    "6fb7140d2af0fbbbf7db8d0c79b08727",
    "7065f0799b2759f65ca4d539e7abc248",
    "708960b185087fb079001ac11bec4dfc",
    "708b5ec149f079c7aaa7071af44b9150",
    "711dc0379fc062f2983fd33dc4f018ba",
    "713093acfcc273405dcca30c712ddaec",
    "7173bdc276cb69268fade993b46e7a0f",
    "71a78d2221dca4e8cf6ec4c2733ed883",
    "722ec15d7206053ae577bc5518a613ce",
    "73d809b5571ceff4046278b8463968f9",
    "742b257aa9d4799119696a067566559a",
    "7519118d604e51a20c81c5ed173d4276",
    "754b8f435f2556a125499b5dd24b4ff7",
    "757d2232133f409bed3759fc2899f159",
    "76fc7cd962377d776ae1c11d3a290247",
    "77aa9a955dcc84d5e4cd22cd1645c000",
    "77c3e654a2df67ba3cbbbe9f5eea26fe",
    "797e512102364468339e57e7979043de",
    "79f7e6f9c9811317b43805a0bf838e38",
    "7a4b5b0a75f72c7c2c37e67cc7bb5ed4",
    "7ab9a78bed87ab00addbe0a8113a3f43",
    "7b2a57f3ed93e8ed2ab8772ff733117e",
    "7b469dabb2b7fba03ae9e5b825d1fe0d",
    "7b865c0e03807a886a66c776949e0cd8",
    "7c1be009c2da02062172c0b3a50fa68e",
    "7c32b3cea32004fb21459d2de2c0de98",
    "7c6fc43b80837489b278437cf52e0bcb",
    "7c9f5daefed17a34f8446e6d870a34d8",
    "7d7bf0917a17f8ad39aedb7005e4496c",
    "7d985ef2923f77e0e259527077d06c60",
    "7ec888360929eb4dca38c59d8e7a0653",
    "7f1a5c966d160d67336709a0447f9373",
    "7f7a3396c83c2bed769767b875db64f3",
    "7fd530ceabb47ed7a1558624f39f3729",
    "80c127a6f5dcc627915da65bb4307917",
    "80ef9ca9d293b4706bf338750753df4b",
    "8120d654e7f4dee1491bde67829443a9",
    "814a7f9ac1177163746de3f1bc61643a",
    "814b0818ee43c445b6baa2f886c67c68",
    "816f8de414e6ab0a400a762482e42366",
    "81edd6a8fc36d75e4a8f0d00b32158f1",
    "820bb8bad26d6149500a692f6047994b",
    "8210e7bfbaafdd6e78af9c8fa6d31cb7",
    "821a2d6b79b14b5918ceb61e40b8963a",
    "8249d8ccc07f02772f53e5d09b4a5ec6",
    "8376154f595af6896e515544356782b5",
    "84185d9b725613eb8e6841b5bd5c66a4",
    "84e96a01d6d01d59094141e3c4f6a543",
    "85476ef922efb0f48e8992a59f3d19d0",
    "8574845413777a1131f59c683b8a4bb7",
    "8604b99116ed1305c3fb0628c4987642",
    "86b9b7d51cccf425c172887902be8105",
    "87223731c7df54bd4034c63909532463",
    "896b66455e679297db0e3831a7c6199a",
    "89b301634d4457353fce936965aab436",
    "8ba7f726f1fc0be895b72122b1ce323b",
    "8bc8ede2c11e729d8a66f26b682a031b",
    "8ccba61a41c9d0d4f95846b50c5a726c",
    "8cf2179d4dc193591c177f8c9ef7fdef",
    "8d939bdcc4bb1f376007bc5a9d8c01ff",
    "8daeaa830c7d0556ac4d49a3de823461",
    "8e3932c312eb99f805d27d6288a93688",
    "8fce98a9f92dc1f7a317b8efce3a0245",
    "9032981b8423b8c88693974fec55d805",
    "91af87ab53170fe455b998f9cb611548",
    "92c5a636e1e3dd84914ac1da05ac3733",
    "931a7fdbbba35104c3351a32d2467649",
    "94144492de6f586ed0ef41c1b7743349",
    "9465efce7f7827a9ad2fb2dd48fcf05e",
    "94a28d28c7a502cd134a868fe038d8b5",
    "9510b9f818da3db76362925c5c19aa66",
    "967c9e83551986614e943d091f91488e",
    "96a237ad690f8a04ba3d3ee9cd7efeb5",
    "9795d24834708182a7e77864431334ca",
    "9847acced4c2ec8aed61b0b8a2ac0c2a",
    "98c55c368c91e97fa42ffd58b5d195df",
    "98c5f770adc8d9b28eb015a99f81f57c",
    "99422a5771d168f5c34b3db61a44b347",
    "9945d0ed1a4c3d36b9be78f2139adaf0",
    "9955e82843d59cacb73cdb791d7c08f3",
    "99c914b5b16403115061c8f06e77094d",
    "99de487794df7a97dfb92c2d75794be7",
    "9a1fceff660e82f1cd8a5f5d8cddd855",
    "9b5e3558ade678db56ef4665e31c36c9",
    "9b81eb7f0c9f57dbfb661fc7b03efca9",
    "9ca6438d628650665cfe7f6ea4a26cfd",
    "9cd26e1ce2781c4985e705ec7211694e",
    "9d76d20991fb4f76f08c4e4e960ef158",
    "9e43b0b6ef4e68f2fb3a455475229b7d",
    "9ef940d5f3a4f637b397d0ac78dbbe8c",
    "9fc99e5a5f2f2ff8bdc3c2822d452365",
    "a00341f5b891caa3f04248e713664ccc",
    "a02c6c91ed0a7b68931546bd9e72eece",
    "a0514ea410081c4a3feb01a82d62fa95",
    "a08cfc91fe133d2df6afec06bc232563",
    "a14ffe756c05871315000a96b42f07c8",
    "a17790335affc63ad5c9287dd434266c",
    "a214692a7f7db13d7ee46598cd6a8c55",
    "a4c4b0fb0ce3b17c751e57dd65e0fcd2",
    "a51049bf462f9fa418d5dd6df66a7740",
    "a7e5beea1bde16a43ea192c1e9164977",
    "a8f1b8db5917d002310b11853c58e330",
    "a926aea8bdd87b85331aa4d854906d00",
    "aa374ac3623b5132d4cac58154ec9873",
    "ab874149e86b5b60d7b81d13c2ed5e9a",
    "abfa6afa3d395edb63c2318104cd6f67",
    "ad358f6a3b0949f0af2eec875734f8b7",
    "ad4d304f04fdeb25508d7ec630053077",
    "adf4692a58a666ad87ee9b1ce7018add",
    "adfbf600784683e1e9ed5bd176249f69",
    "ae0c21f91ce12a23b428c3341d284d19",
    "ae2a9a6e01d842de5a26f7bbc87ed4a8",
    "aec17125144add48e2bf37a8db3f3eb5",
    "aefe206ae663d4294c1d87c9bce49c98",
    "af0d075d0afe565702eeed89c8c0ed0e",
    "af39b6d03ea895f739d1dac6f3c15644",
    "af3abfd878314863322a040b224e505b",
    "af89b5cb1f7f9967f3c2eb2775d78f18",
    "afb42ea60013bb3c5b81d4cf461760e3",
    "b017ff4517370f280fff5c25cc992d88",
    "b1dca672b92cd867c7484367016b7e2d",
    "b33748481f2c3d5dad2225bba2ec6bcd",
    "b39b04fad8e58571ce18bc40d54b4c42",
    "b415d8f0106cbcc2f121d2eee75b0663",
    "b43fef746336ae05fa2a5002002947b5",
    "b44f29991967bbdb2b2e8b9f07e8a9af",
    "b4fecfcd8a0f784840deaf17e3eb93ba",
    "b553234b26f0348ee594762e2701fea2",
    "b5ed406b272d691cebd5b7922d25ac75",
    "b60d5ebc72f0264a0adef9754b2a1f00",
    "b6cec2cf8552f630dd4fe7f486632dfa",
    "b6fcce33992ccc6f65bc51b38a442fde",
    "b788430f130d3918ca921ab1b082154a",
    "b821cd22fc5cf1e87d2135ad5b982818",
    "b86541ecfa8f7de2889ed8f429221d4f",
    "b86c9fbe45bf782b7fd27b205df7971c",
    "b897e6be0fc7932978732d3344a1737f",
    "b8a2c7752ce35d71e8310f758828dc89",
    "b8b76d973c8b1e41057c3c71c37bb692",
    "b91ddd39cbc94bcf8e24ca7d92405a8f",
    "b9daba1d2eee0663bcd5c082207ea164",
    "ba4e9618e941ed88737b4d22315934d4",
    "bb9b1a3fa54a25f142bcebbc3a7d37bf",
    "bbbb4801fc4f4061017772336e264474",
    "bbc0f53f14c66ddf72a642fa544f8f3d",
    "bc57eab9acf0efa4e153dba686e6ba74",
    "bc7d1f16967173e93288800c79b701a5",
    "bcc174bcf22901a557b8b7900b8d93c2",
    "bd70178334cdee6445eb17cef571a324",
    "bdbbb5c1736ecebf61b12693206f4a51",
    "bdd49da1ed92d4de7f8981841bd07e74",
    "bdd5cba40e8170361c9235047044b75b",
    "be462e649b960f58405802098a967370",
    "bf8bb73f2255f93b9323898bcf093330",
    "bf93ed2aad13654174b976d45bcbc7a7",
    "bfd625cce642f41bec14e2306b001d38",
    "bfd916cbce36fc3fd837fc6d48243661",
    "c05533ccd16a0175b820e0db48cf1612",
    "c07ba07dc03f7cbbd85faba455f7de44",
    "c300741ec5ef15ce31d67a8da11bd63b",
    "c30fb9c10d0dfb68a7b4965cc6cbbef0",
    "c31689e5f60833ed893515eda099bc63",
    "c34bec466a84313c0c477ab235810dd8",
    "c418328c7631836b59fd435c90c9e8fb",
    "c48b4a7295b0b1653577408091ea933b",
    "c5083598fed401f7a5e6660a78346483",
    "c5e699e85d4e9410a40831d62ab85d81",
    "c5f2d7a0022019cc2f613e9eeb0871c4",
    "c61f3faa32f2f34b7ee9f385769cf9fb",
    "c6f1b0248a45018a00f402b5a81cae00",
    "c7892e9e739b91d5883da03ddadfaa93",
    "c7fbb95fb6b6442a44590802e4cbca3c",
    "c82e06120cc3f850a01682318947dc3a",
    "c844a43e0ee640769789f88ac1f1632e",
    "c8549da1a54f4a96c3c5492c56cc3fd3",
    "c867d2a663088733e68864997d851bbe",
    "c92705477d9bd22ac99d58c0ee29184d",
    "c93d7a16b1b88df819133e0c0d165825",
    "ca178a60f17d91da180b8ac0a2a6d801",
    "cac60aff9bdb2c3851c115a0a382b1e9",
    "cae9627cdbaaa205f8706dbd37c21675",
    "ccba9c968917c3dc368d23327375345f",
    "cd5188395cd474d7d09a2e2fbaeebfde",
    "cd53c94a586447df558574208e271bcf",
    "cd79033bc76d63c8e7a063d87ef62412",
    "cee7faebf81e06334571a9c5c88e68cd",
    "cfb7c888f3116ea8eeb4c2daa1825c33",
    "cfbe50118c4c32c8ebb7d802662ada10",
    "d028b5bcb19d83f5b057111ceddfc32f",
    "d0c77e85e89902896581e0b914767f44",
    "d22c62ebd319832e0d8d0c9bda3236c7",
    "d3078ae191b8838a8c97f4b76b6db323",
    "d3a86be8f211359ce6b6bed4bc21bcf9",
    "d3e21fa4f1e229591e57a551fc0f4752",
    "d472e3386c442cb43216bce3feee6432",
    "d4bbbd61f06be78293ccf694a16effa1",
    "d5677223dc07c7bf920b3c4974bff614",
    "d65ce904a794606ae198f2d3d5b8e4a8",
    "d6ee2222b36238c27d4599f7d30e9ed9",
    "d773a36076823812bc4e7d18dfe179d4",
    "d7de6a7480f5daac1f64535db4af0239",
    "d80b0aca02e6426ca3bdb6c52d2b8b6a",
    "daca3efc0b7ca1c5d6d2a36c24a979e3",
    "dafc08191f0ca5e0718046f6889c54a9",
    "db076aadd7cfc3cb7363283eae684c3c",
    "dbbc68bac5f0aca07797937d34c39339",
    "dbd6f163ce2784cff31a51b076d7263c",
    "dcdfcf93315c5c8df951ff6156705ef1",
    "dceba7c0481272e2cca72cf6295bd6da",
    "dd2888a14ccec460127889956e5a7bee",
    "dda0fb99ecb57736e5f04e4748755a60",
    "de7587056a8b7efe34e425ddbe009d64",
    "de89a24ad90d11eef2795f754f41cb3f",
    "dea2de2768b2f6aee961f6058fb9fbe8",
    "deff9d89dfaa1997d0060fe8c271fae6",
    "e0b1e1f37dc0281d7d8a5a67aefd4b04",
    "e136b2c56eb273dd132a1b6cbc772186",
    "e178965d2af81d20f382965fc96b176b",
    "e18f337a450b3a5afdd64c68c5552da4",
    "e1ce723be5962098db252e4ee86012fc",
    "e23bd7b185199e679e1172ce7865e134",
    "e24ca3f2ab509ac9eb140523d41e4a4c",
    "e2ae89c5f81d422f385d794589934bde",
    "e2b327fb8367f9cf2137f1f34fbd8ea4",
    "e5fca42d81026d42798008e92f7b90f8",
    "e6264a4e5d3b12f77f4703892c18355d",
    "e715f289e8c95fe7cf14a2f108643834",
    "e7ef50228eb2ad57d1681faf5ce551ac",
    "e822d87be5c871e8a0d0cf7f5fd8f465",
    "e8451e3e12051e16fc06787c85d048cc",
    "e84904fa98b6e6ed16d36dfab4f2af32",
    "e8e88aacd12f41b91d2f0850c7b9a87e",
    "e94e3e4917a2c7eb710cbbbfc187b0d0",
    "ea03a08d3c2ef2b2f885c52c2fef875b",
    "ea76a3a3c1288db311da5509b395b0a3",
    "eb44569976666976c8e82651a6042db8",
    "ebd5aa7eaede1bd906cee7d8003471e3",
    "ebdfb25e3731cc5f795ab548825b3a9d",
    "ecd15d835d91ea9c91cad94ee6150f5e",
    "ecd711fb21b8bcc9f378b00e7dbf39f2",
    "ee00fe10dc3582d8747ffd904da0c9cb",
    "ee62930e57c68499138ac2e6ddc0ae9b",
    "ef8a6ff0729aa4abc2b39a72b64dbffd",
    "f1df7a8feaa9d052f3c8a7355087a4ac",
    "f2f6ae0a28471ddfbbe8046132df4dc4",
    "f311d9c1a35bb7f4bce2dc690c4c74be",
    "f323bb31da711394c55e49f70f53ef3b",
    "f3ba656611fc4ca9321fccd6cf28b80b",
    "f3eb51938d3a00b6e2a47c147b4ac56a",
    "f403f61da57abe7128576ad5a05ccbc5",
    "f465c89fd3ed2ed1e6056239362eea33",
    "f6e29eb709b3f903e11f3abfc95211d3",
    "f77ed6164abce07a3a3271b12de7cfe0",
    "f87c45e2e1b671a76cc3866e9f12785d",
    "f91cc262b5cddf1633c5b3b8e0dbe2ca",
    "f930afe26d4cb741aca5c1193a6d218d",
    "f97cb32af5768b2ce070c022fcac8af2",
    "f9a3e290a516fe2ad31085d18e004384",
    "f9bb487251106cec5b498af2ef129bb7",
    "f9ec3c8496c7649b3941b5144af888da",
    "fa2696993284dfd3ef6dfe64d11c1a5e",
    "fa968e5204948ca3f6e7f3b74f20eac5",
    "fb671657a94b0ad0f4daecbe5103fa08",
    "fbf7ad093a57c106818cb3755ab66bfd",
    "fc4825ae0dbe04c98402b4af7903ff2c",
    "fdfde476833486ac6841556305d4cb1c",
    "fe57907f37033308f4f65af1d5790c13",
    "fe7d7efdac7c96088f4cda8b4c207780",
    "fe9bf9ed4d8f33e28737cee68f40964c",
    "ff5e42625b80fcd5569f804edae55a5e"
  ];

  // src/rate.mjs
  var rate_exports = {};
  __export(rate_exports, {
    CWS_ID: () => CWS_ID,
    EDGE_ID: () => EDGE_ID,
    EDGE_LISTING_URL: () => EDGE_LISTING_URL,
    GECKO_ID: () => GECKO_ID,
    MAX_SHOWINGS: () => MAX_SHOWINGS,
    RATE_KEY: () => RATE_KEY,
    RETURNING_SESSIONS: () => RETURNING_SESSIONS,
    WEB_KEY: () => WEB_KEY,
    WEB_MAX_SHOWINGS: () => WEB_MAX_SHOWINGS,
    markAnswered: () => markAnswered,
    markShown: () => markShown,
    message: () => message,
    normalize: () => normalize,
    noteSession: () => noteSession,
    read: () => read,
    shouldAsk: () => shouldAsk,
    storeFor: () => storeFor,
    write: () => write
  });
  var CWS_ID = "ceilhkpcnofeomaibeldikllpgjolaml";
  var GECKO_ID = "accesslens@phakeoa.github.io";
  var EDGE_ID = "";
  var EDGE_LISTING_URL = "";
  var STORES = [
    {
      id: CWS_ID,
      name: "the Chrome Web Store",
      short: "Chrome Web Store",
      reviewUrl: `https://chromewebstore.google.com/detail/${CWS_ID}/reviews`
    },
    // AMO has no separate "write a review" URL: the rating widget sits on the listing page itself.
    {
      id: GECKO_ID,
      name: "Firefox Add-ons",
      short: "Firefox Add-ons",
      reviewUrl: "https://addons.mozilla.org/firefox/addon/accesslens/"
    }
  ];
  function storeFor(id) {
    if (!id || typeof id !== "string") return null;
    if (EDGE_ID && EDGE_LISTING_URL && id === EDGE_ID) {
      return { id, name: "Edge Add-ons", short: "Edge Add-ons", reviewUrl: EDGE_LISTING_URL };
    }
    return STORES.find((s) => s.id === id) || null;
  }
  var RATE_KEY = "al.rate";
  var WEB_KEY = "al.web";
  var MAX_SHOWINGS = 3;
  var WEB_MAX_SHOWINGS = 2;
  var RETURNING_SESSIONS = 2;
  var count = (v) => Number.isInteger(v) && v > 0 ? v : 0;
  function normalize(v) {
    const o = v && typeof v === "object" ? v : {};
    return { shown: count(o.shown), done: o.done === true, sessions: count(o.sessions) };
  }
  function read(storage, key = RATE_KEY) {
    try {
      return normalize(JSON.parse(storage.getItem(key)));
    } catch {
      return normalize(null);
    }
  }
  function write(storage, key, state) {
    try {
      storage.setItem(key, JSON.stringify(normalize(state)));
      return true;
    } catch {
      return false;
    }
  }
  var noteSession = (s) => {
    const n = normalize(s);
    return { ...n, sessions: n.sessions + 1 };
  };
  var markShown = (s) => {
    const n = normalize(s);
    return { ...n, shown: n.shown + 1 };
  };
  var markAnswered = (s) => {
    const n = normalize(s);
    return { ...n, done: true };
  };
  function shouldAsk(state, trigger, { askedThisPage = false, max = MAX_SHOWINGS } = {}) {
    const s = normalize(state);
    if (s.done || s.shown >= max || askedThisPage) return false;
    if (trigger === "export") return true;
    if (trigger === "return") return s.sessions >= RETURNING_SESSIONS;
    return false;
  }
  function message(kind, trigger) {
    if (kind === "install") {
      return trigger === "export" ? "Need this again? The free extension opens Access files straight from your browser toolbar, so you never have to find this page." : "Back again? The free extension opens Access files straight from your browser toolbar, so you never have to find this page.";
    }
    return trigger === "export" ? "Did AccessLens get your data out? A rating helps the next person find it." : "Using AccessLens again? A quick rating helps the next person with an Access file find it.";
  }

  // src/gate.mjs
  var FREE_MAX_TABLES = 20;
  var FREE_MAX_ROWS = 5e4;
  var GATED_ACTIONS = ["zip", "xlsx", "sqlite", "sql", "searchAll"];
  var isGatedAction = (a) => GATED_ACTIONS.includes(a);
  function dbSize(tables) {
    const list = tables || [];
    return {
      tables: list.length,
      rows: list.reduce((a, t) => a + (Number(t.rowCount) || 0), 0)
    };
  }
  function withinFreeLimits(size, limits = {}) {
    const maxTables = limits.maxTables ?? FREE_MAX_TABLES;
    const maxRows = limits.maxRows ?? FREE_MAX_ROWS;
    return size.tables <= maxTables && size.rows <= maxRows;
  }
  function evaluate(tables, { isPro = false, limits = {} } = {}) {
    const size = dbSize(tables);
    const maxTables = limits.maxTables ?? FREE_MAX_TABLES;
    const maxRows = limits.maxRows ?? FREE_MAX_ROWS;
    const reasons = [];
    if (size.tables > maxTables) reasons.push(`${size.tables} tables (free covers up to ${maxTables})`);
    if (size.rows > maxRows) reasons.push(`${size.rows.toLocaleString()} rows (free covers up to ${maxRows.toLocaleString()})`);
    const withinFree = withinFreeLimits(size, limits);
    return { free: withinFree, size, reasons, needsPro: !withinFree && !isPro, isPro };
  }
  function proMessage(evaluation, price = "$5.99", limits = {}) {
    const maxTables = limits.maxTables ?? FREE_MAX_TABLES;
    const maxRows = limits.maxRows ?? FREE_MAX_ROWS;
    if (evaluation.isPro) {
      return `Pro is active on this browser. Every export and cross-table search is unlocked, at any database size.`;
    }
    if (!evaluation.reasons.length) {
      return `Everything is unlocked for this database \u2014 it is within the free limits (up to ${maxTables} tables and ${maxRows.toLocaleString()} rows). Pro (${price} once) removes those limits for larger databases. If you already bought it, you can enter your key here.`;
    }
    return `This database has ${evaluation.reasons.join(" and ")}. Exporting it whole, and searching across every table, are Pro features \u2014 ${price} once, no subscription and no account. Exporting one table at a time to CSV stays free and unlimited, so you can always get your data out.`;
  }
  var wallMessage = proMessage;
  var KEY_NOT_FOUND_REASON = "That key was not recognised. Copy it exactly as it appears in your receipt email \u2014 every character, including the dashes.";
  var KEY_EMPTY_REASON = "Enter the licence key from your receipt email.";
  var KEY_SET = new Set(KEY_HASHES);
  var keyHashCount = () => KEY_SET.size;
  async function checkLicenseKey(rawKey, hashes = KEY_SET, now = /* @__PURE__ */ new Date()) {
    const normalized = normalizeKey(rawKey);
    if (!normalized) return { ok: false, reason: KEY_EMPTY_REASON };
    if (!isWellFormedKey(normalized)) return { ok: false, reason: KEY_NOT_FOUND_REASON };
    let hash;
    try {
      hash = await hashKey(normalized);
    } catch {
      return { ok: false, reason: "This browser could not check the key. Please try again." };
    }
    const set = hashes instanceof Set ? hashes : new Set(hashes || []);
    if (!set.has(hash)) return { ok: false, reason: KEY_NOT_FOUND_REASON };
    return {
      ok: true,
      record: { key: formatKey(normalized), hash, activatedAt: now.toISOString() }
    };
  }
  var PRO_KEY = "al.pro";
  function readPro(storage) {
    try {
      const raw = storage.getItem(PRO_KEY);
      if (!raw) return null;
      const v = JSON.parse(raw);
      return v && typeof v.key === "string" && v.key ? v : null;
    } catch {
      return null;
    }
  }
  function writePro(storage, record) {
    try {
      storage.setItem(PRO_KEY, JSON.stringify(record));
      return true;
    } catch {
      return false;
    }
  }
  function clearPro(storage) {
    try {
      storage.removeItem(PRO_KEY);
      return true;
    } catch {
      return false;
    }
  }
  return __toCommonJS(gate_exports);
})();
