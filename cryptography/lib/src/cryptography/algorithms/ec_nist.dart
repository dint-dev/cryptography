// Copyright 2019-2020 Gohilla Ltd.
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

/// _NIST P-256_ Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
/// Currently supported __only in the browser.__
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = ecdhP256;
///   final localKeyPair = await algorithm.newKeyPair();
///   final remoteKeyPair = await algorithm.newKeyPair();
///   final sharedSecretKey = await algorithm.secretKey(
///     localPrivateKey: localKeyPair.privateKey,
///     remotePublicKey: remoteKeyPair.publicKey,
///   );
/// }
/// ```
const KeyExchangeAlgorithm ecdhP256 = webEcdhP256;

/// _NIST P-384_ Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
/// Currently supported __only in the browser.__
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = ecdhP384;
///   final localKeyPair = await algorithm.newKeyPair();
///   final remoteKeyPair = await algorithm.newKeyPair();
///   final sharedSecretKey = await algorithm.secretKey(
///     localPrivateKey: localKeyPair.privateKey,
///     remotePublicKey: remoteKeyPair.publicKey,
///   );
/// }
/// ```
const KeyExchangeAlgorithm ecdhP384 = webEcdhP384;

/// _NIST P-521_ Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
/// Currently supported __only in the browser.__
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = ecdhP521;
///   final localKeyPair = await algorithm.newKeyPair();
///   final remoteKeyPair = await algorithm.newKeyPair();
///   final sharedSecretKey = await algorithm.secretKey(
///     localPrivateKey: localKeyPair.privateKey,
///     remotePublicKey: remoteKeyPair.publicKey,
///   );
/// }
/// ```
const KeyExchangeAlgorithm ecdhP521 = webEcdhP521;

/// _NIST P-256_ Elliptic Curve Digital Signature Algorithm (ECDSA).
/// Currently supported __only in the browser.__
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = ecdsaP256Sha256;
///   final keyPair = await algorithm.newKeyPair();
///   final signature = await algorithm.sign([1,2,3], keyPair);
///
///   // Anyone can verify the signature
///   final isVerified = await algorithm.verify([1,2,3], signature);
/// }
/// ```
///
/// For more about ECDSA, see [RFC 6090](https://www.ietf.org/rfc/rfc6090.txt).
const SignatureAlgorithm ecdsaP256Sha256 = webEcdsaP256Sha256;

/// _NIST P-384_ Elliptic Curve Digital Signature Algorithm (ECDSA).
/// Currently supported __only in the browser.__
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = ecdsaP384Sha256;
///   final keyPair = await algorithm.newKeyPair();
///   final signature = await algorithm.sign([1,2,3], keyPair);
///
///   // Anyone can verify the signature
///   final isVerified = await algorithm.verify([1,2,3], signature);
/// }
/// ```
const SignatureAlgorithm ecdsaP384Sha256 = webEcdsaP384Sha256;

/// _NIST P-521_ Elliptic Curve Digital Signature Algorithm (ECDSA).
/// Currently supported __only in the browser.__
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = ecdsaP521Sha256;
///   final keyPair = await algorithm.newKeyPair();
///   final signature = await algorithm.sign([1,2,3], keyPair);
///
///   // Anyone can verify the signature
///   final isVerified = await algorithm.verify([1,2,3], signature);
/// }
/// ```
const SignatureAlgorithm ecdsaP521Sha256 = webEcdsaP521Sha256;
