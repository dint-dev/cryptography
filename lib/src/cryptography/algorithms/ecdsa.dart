// Copyright 2019 Gohilla Ltd (https://gohilla.com).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// For specification, see the License for the specific language governing permissions and
// limitations under the License.

import 'package:cryptography/cryptography.dart';

import 'web_crypto.dart';

/// NIST P-256 Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
/// __Currently supported only in the browser.__
const KeyExchangeAlgorithm ecdhP256 = WebEcdh(
  name: 'p256',
  webCryptoNamedCurve: 'P-256',
  keyPairGenerator: WebEcKeyPairGenerator(
    name: 'p256',
    webCryptoName: 'P-256',
  ),
  polyfill: null,
);

/// NIST P-384 Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
/// __Currently supported only in the browser.__
const KeyExchangeAlgorithm ecdhP384 = WebEcdh(
  name: 'p384',
  webCryptoNamedCurve: 'P-384',
  keyPairGenerator: WebEcKeyPairGenerator(
    name: 'p384',
    webCryptoName: 'P-384',
  ),
  polyfill: null,
);

/// NIST P-521 Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
/// __Currently supported only in the browser.__
const KeyExchangeAlgorithm ecdhP521 = WebEcdh(
  name: 'p521',
  webCryptoNamedCurve: 'P-521',
  keyPairGenerator: WebEcKeyPairGenerator(
    name: 'p521',
    webCryptoName: 'P-521',
  ),
  polyfill: null,
);

/// NIST P-256 Elliptic Curve Digital Signature Algorithm (ECDSA).
/// __Currently supported only in the browser.__
///
/// For more about ECDSA, see [RFC 6090](https://www.ietf.org/rfc/rfc6090.txt).
const SignatureAlgorithm ecdsaP256Sha256 = WebEcdsa(
  name: 'p256',
  webCryptoNamedCurve: 'P-256',
  webCryptoHashName: 'SHA-256',
  keyPairGenerator: WebEcKeyPairGenerator(
    name: 'p256',
    webCryptoName: 'P-256',
  ),
  polyfill: null,
);

/// NIST P-384 Elliptic Curve Digital Signature Algorithm (ECDSA).
/// __Currently supported only in the browser.__
///
/// For more about ECDSA, see [RFC 6090](https://www.ietf.org/rfc/rfc6090.txt).
const SignatureAlgorithm ecdsaP384Sha256 = WebEcdsa(
  name: 'p384',
  webCryptoNamedCurve: 'P-384',
  webCryptoHashName: 'SHA-256',
  keyPairGenerator: WebEcKeyPairGenerator(
    name: 'p384',
    webCryptoName: 'P-384',
  ),
  polyfill: null,
);

/// NIST P-521 Elliptic Curve Digital Signature Algorithm (ECDSA).
/// __Currently supported only in the browser.__
///
/// For more about ECDSA, see [RFC 6090](https://www.ietf.org/rfc/rfc6090.txt).
const SignatureAlgorithm ecdsaP521Sha256 = WebEcdsa(
  name: 'p521',
  webCryptoNamedCurve: 'P-521',
  webCryptoHashName: 'SHA-256',
  keyPairGenerator: WebEcKeyPairGenerator(
    name: 'p521',
    webCryptoName: 'P-521',
  ),
  polyfill: null,
);
