// AccessLens — Pro licence activation. NO NETWORK. Nothing in this product talks to a server.
//
// 2026-09-18: keys are checked on this device. The seller uploads a plain list of keys to the
// store (Payhip hands one unused key to each buyer, in the receipt email); the extension ships
// only SHA-256 hashes of those keys, inside gate.js. Activate = hash what was typed, look it up
// (ALGate.checkLicenseKey — pure, node-tested). The store is never contacted, so:
//  · the manifest stays PERMISSIONLESS and the release check requires ZERO network call sites,
//  · nothing identifying ever leaves the machine — not the key, not the file, not a fingerprint,
//  · Pro works offline forever; no provider outage or account trouble can strand a buyer.
// Provider history: Lemon Squeezy (09-02 → 09-18) and Polar (09-18, for one day) each needed an
// activation call and each was dropped for its rating before anything shipped. Payhip only
// sells the key; it never sees the extension.
(function () {
  'use strict';

  var STORE = {
    name: 'Payhip',
    // The Payhip checkout link for "AccessLens Pro". null = the Buy button hides and pack.mjs
    // refuses to package; activation itself needs nothing but the hashes in gate.js, so a buyer
    // who already has a key is never blocked by this value.
    CHECKOUT_URL: 'https://payhip.com/b/U60Cu',
    PRICE: '$5.99',
    // 2026-09-26: the same Payhip page also sells a Business licence (a product variant, same
    // key list). Keys do not record which one was bought — the split is an honour system, so
    // the extension only mentions it and never checks it.
    BUSINESS_PRICE: '$15',
  };

  function isConfigured() {
    return STORE.CHECKOUT_URL !== null && ALGate.keyHashCount() > 0;
  }

  // → { ok: true, record } | { ok: false, reason }
  function validateKey(rawKey) {
    return ALGate.checkLicenseKey(rawKey);
  }

  self.ALLicense = {
    validateKey: validateKey,
    isConfigured: isConfigured,
    checkoutUrl: function () { return STORE.CHECKOUT_URL; },
    price: function () { return STORE.PRICE; },
    businessPrice: function () { return STORE.BUSINESS_PRICE; },
    providerName: function () { return STORE.name; },
  };
})();
