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
import 'package:cryptography/src/cryptography/algorithms/ec_dsa_impl.dart';

import '../web_crypto/web_crypto.dart';

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-256_
/// (secp256r1 / prime256v1) curve and [sha256] hash algorithm.
/// Currently supported __only in the browser.__
///
/// Private keys are instances of [JwkPrivateKey].
///
/// ## Example
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
const SignatureAlgorithm ecdsaP256Sha256 =
    webEcdsaP256Sha256 ?? dartEcdsaP256Sha256;

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-384_
/// (secp384r1 / prime384v1) curve and [sha256] hash algorithm.
/// Currently supported __only in the browser.__
///
/// Private keys are instances of [JwkPrivateKey].
///
/// ## Example
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
const SignatureAlgorithm ecdsaP384Sha256 =
    webEcdsaP384Sha256 ?? dartEcdsaP384Sha256;

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-384_
/// (secp384r1 / prime384v1) curve and [sha384] hash algorithm.
/// Currently supported __only in the browser.__
///
/// Private keys are instances of [JwkPrivateKey].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = ecdsaP384Sha384;
///   final keyPair = await algorithm.newKeyPair();
///   final signature = await algorithm.sign([1,2,3], keyPair);
///
///   // Anyone can verify the signature
///   final isVerified = await algorithm.verify([1,2,3], signature);
/// }
/// ```
const SignatureAlgorithm ecdsaP384Sha384 =
    webEcdsaP384Sha384 ?? dartEcdsaP384Sha384;

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-521_
/// (secp521r1 / prime521v1) curve and [sha256] hash algorithm.
/// Currently supported __only in the browser.__
///
/// Private keys are instances of [JwkPrivateKey].
///
/// ## Example
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
const SignatureAlgorithm ecdsaP521Sha256 =
    webEcdsaP521Sha256 ?? dartEcdsaP521Sha256;

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-521_
/// (secp521r1 / prime521v1) curve and [sha512] hash algorithm.
/// Currently supported __only in the browser.__
///
/// Private keys are instances of [JwkPrivateKey].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = ecdsaP521Sha512;
///   final keyPair = await algorithm.newKeyPair();
///   final signature = await algorithm.sign([1,2,3], keyPair);
///
///   // Anyone can verify the signature
///   final isVerified = await algorithm.verify([1,2,3], signature);
/// }
/// ```
const SignatureAlgorithm ecdsaP521Sha512 =
    webEcdsaP521Sha512 ?? dartEcdsaP521Sha512;
