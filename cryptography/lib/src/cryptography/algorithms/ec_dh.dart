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

import '../web_crypto/web_crypto.dart';
import 'ec_dh_impl.dart';

/// _NIST P-256_ Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
/// Currently supported __only in the browser.__
///
/// Private key export format is `[...d, ...x, ...y]`.
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
const KeyExchangeAlgorithm ecdhP256 = webEcdhP256 ?? dartEcdhP256;

/// _NIST P-384_ Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
/// Currently supported __only in the browser.__
///
/// Private key export format is `[...d, ...x, ...y]`.
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
const KeyExchangeAlgorithm ecdhP384 = webEcdhP384 ?? dartEcdhP384;

/// _NIST P-521_ Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
/// Currently supported __only in the browser.__
///
/// Private key export format is `[...d, ...x, ...y]`.
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
const KeyExchangeAlgorithm ecdhP521 = webEcdhP521 ?? dartEcdhP521;
