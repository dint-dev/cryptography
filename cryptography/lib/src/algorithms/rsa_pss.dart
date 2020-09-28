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

import '../web_crypto/web_crypto.dart' as web_crypto;

/// _RSA-PSS_ signature algorithm. __Currently supported only in browsers__. The
/// hash algorithm must be [sha256], [sha384], or [sha512].
///
/// By default, key size is [defaultModulusLength] (4096 bits).
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
  static const int defaultModulusLength = 4096;
  static const List<int> defaultPublicExponent = [0x01, 0x00, 0x01];

  final HashAlgorithm hashAlgorithm;
  final int nonceLength;

  const RsaPss(this.hashAlgorithm, {this.nonceLength});

  @override
  String get name => 'rsaPss';

  @override
  int get publicKeyLength => null;

  @override
  Future<KeyPair> newKeyPair({
    int modulusLength = defaultModulusLength,
    List<int> publicExponent = defaultPublicExponent,
  }) {
    if (web_crypto.isWebCryptoSupported) {
      final hashName = _webCryptoHashName;
      if (hashName != null) {
        return web_crypto.rsaNewKeyPairForSigning(
          name: 'RSA-PSS',
          modulusLength: modulusLength,
          publicExponent: publicExponent,
          hashName: hashName,
        );
      }
    }
    return super.newKeyPair();
  }

  @override
  KeyPair newKeyPairSync({
    int modulusLength = defaultModulusLength,
    List<int> publicExponent = defaultPublicExponent,
  }) {
    throw UnimplementedError(
      '$name newKeyPair() is not supported on the current platform. Try asynchronous method?',
    );
  }

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) {
    if (web_crypto.isWebCryptoSupported) {
      final hashName = _webCryptoHashName;
      if (hashName != null) {
        return web_crypto.rsaPssSign(
          input,
          keyPair,
          saltLength: nonceLength,
          hashName: hashName,
        );
      }
    }
    return super.sign(input, keyPair);
  }

  String get _webCryptoHashName {
    return const <String, String>{
      'sha256': 'SHA-256',
      'sha384': 'SHA-384',
      'sha512': 'SHA-512',
    }[hashAlgorithm.name];
  }

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    throw UnimplementedError(
      '$name signSync(...) is not supported on the current platform. Try asynchronous method?',
    );
  }

  @override
  Future<bool> verify(List<int> input, Signature signature) {
    if (web_crypto.isWebCryptoSupported) {
      final hashName = _webCryptoHashName;
      if (hashName != null) {
        return web_crypto.rsaPssVerify(
          input,
          signature,
          saltLength: 32,
          hashName: hashName,
        );
      }
      throw UnimplementedError(
        'Unsupported hash algorithm: ${hashAlgorithm.name}',
      );
    }
    return super.verify(input, signature);
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    throw UnimplementedError(
      '$name verifySync(...) is not supported on the current platform. Try asynchronous method?',
    );
  }
}
