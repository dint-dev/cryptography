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
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:cryptography/cryptography.dart';

import '../web_crypto/web_crypto.dart';

/// RSA-PSS signature algorithm. __Currently only supported in browsers__. The
/// hash algorithm must be [sha256], [sha384], or [sha512].
///
/// By default, [newKeyPair] generates 4096 bit keys.
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   const algorithm = RsaPss(sha256);
///   final keyPair = await algorithm.newKeyPair();
///   final signature = await algorithm.sign([1,2,3], keyPair);
///   final isOk = await algorithm.verify([1,2,3], signature);
/// }
/// ```
class RsaPss extends SignatureAlgorithm {
  final HashAlgorithm hashAlgorithm;
  final int nonceLength;

  const RsaPss(this.hashAlgorithm, {this.nonceLength});

  @override
  String get name => 'rsaPss';

  @override
  int get publicKeyLength => null;

  SignatureAlgorithm get _webCryptoImplementation {
    if (isWebCryptoSupported) {
      if (identical(hashAlgorithm, sha256) ||
          identical(hashAlgorithm, sha384) ||
          identical(hashAlgorithm, sha512)) {
        return WebRsaPss(hashAlgorithm);
      }
    }
    return null;
  }

  @override
  Future<KeyPair> newKeyPair() {
    final webCryptoImplementation = _webCryptoImplementation;
    if (webCryptoImplementation != null) {
      return webCryptoImplementation.newKeyPair();
    }
    return super.newKeyPair();
  }

  @override
  KeyPair newKeyPairSync() {
    throw UnimplementedError(
      'Only supported in browsers. Hash algorithm must be sha256, sha384, or sha512. Synchronous methods are not supported.',
    );
  }

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) {
    final webCryptoImplementation = _webCryptoImplementation;
    if (webCryptoImplementation != null) {
      return webCryptoImplementation.sign(input, keyPair);
    }
    return super.sign(input, keyPair);
  }

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    throw UnimplementedError(
      'Only supported in browsers. Hash algorithm must be sha256, sha384, or sha512. Synchronous methods are not supported.',
    );
  }

  @override
  Future<bool> verify(List<int> input, Signature signature) {
    final webCryptoImplementation = _webCryptoImplementation;
    if (webCryptoImplementation != null) {
      return webCryptoImplementation.verify(input, signature);
    }
    return super.verify(input, signature);
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    throw UnimplementedError(
      'Only supported in browsers. Hash algorithm must be sha256, sha384, or sha512. Synchronous methods are not supported.',
    );
  }
}
