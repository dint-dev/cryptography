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
import 'package:meta/meta.dart';

import '../web_crypto/web_crypto.dart' as web_crypto;

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-256_
/// (secp256r1 / prime256v1) curve and [sha256] hash algorithm.
/// __Currently supported only in browsers.__
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
const SignatureAlgorithm ecdsaP256Sha256 = _EcdsaP256(
  sha256,
  name: 'ecdsaP256Sha256',
);

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-384_
/// (secp384r1 / prime384v1) curve and [sha256] hash algorithm.
/// __Currently supported only in browsers.__
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
const SignatureAlgorithm ecdsaP384Sha256 = _EcdsaP384(
  sha256,
  name: 'ecdsaP384Sha256',
);

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-384_
/// (secp384r1 / prime384v1) curve and [sha384] hash algorithm.
/// __Currently supported only in browsers.__
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
const SignatureAlgorithm ecdsaP384Sha384 = _EcdsaP384(
  sha384,
  name: 'ecdsaP384Sha384',
);

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-521_
/// (secp521r1 / prime521v1) curve and [sha256] hash algorithm.
/// __Currently supported only in browsers.__
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
const SignatureAlgorithm ecdsaP521Sha256 = _EcdsaP521(
  sha256,
  name: 'ecdsaP521Sha256',
);

/// Elliptic Curve Digital Signature Algorithm (ECDSA) using _P-521_
/// (secp521r1 / prime521v1) curve and [sha512] hash algorithm.
/// __Currently supported only in browsers.__
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
const SignatureAlgorithm ecdsaP521Sha512 = _EcdsaP521(
  sha512,
  name: 'ecdsaP521Sha512',
);

abstract class _EcdsaNist extends SignatureAlgorithm {
  @override
  final String name;

  @override
  final int publicKeyLength;

  final HashAlgorithm hashAlgorithm;

  const _EcdsaNist({
    @required this.hashAlgorithm,
    @required this.name,
    @required this.publicKeyLength,
  });

  int get privateKeyLength;

  BigInt get _a;

  BigInt get _b;

  BigInt get _n;

  /// Modulus
  BigInt get _p;

  String get _webCryptoName;

  @override
  Future<KeyPair> newKeyPair() {
    if (web_crypto.isWebCryptoSupported) {
      return web_crypto.ecdsaNewKeyPair(
        curve: _webCryptoName,
      );
    }
    return super.newKeyPair();
  }

  @override
  KeyPair newKeyPairSync() {
    throw UnimplementedError('Only implemented in browsers');
  }

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) {
    if (web_crypto.isWebCryptoSupported) {
      // Is the hash algorithm supported by Web Cryptography?
      final hashName = const <String, String>{
        'sha256': 'SHA-256',
        'sha384': 'SHA-384',
        'sha512': 'SHA-512',
      }[hashAlgorithm.name];
      if (hashName != null) {
        // Try performing this operation with Web Cryptography
        return web_crypto.ecdsaSign(
          input,
          keyPair,
          namedCurve: _webCryptoName,
          hashName: hashName,
        );
      }
      throw UnimplementedError(
        'Unsupported hash algorithm: ${hashAlgorithm.name}',
      );
    }
    throw UnimplementedError('$name is not supported on the current platform');
  }

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    assert(_p != null);
    assert(_a != null);
    assert(_b != null);
    assert(_n != null);
    throw UnimplementedError(
      '$name signSync(...) is not supported on the current platform. Try asynchronous method?',
    );
  }

  @override
  Future<bool> verify(List<int> input, Signature signature) {
    if (web_crypto.isWebCryptoSupported) {
      // Is the hash algorithm supported by Web Cryptography?
      final hashName = const <String, String>{
        'sha256': 'SHA-256',
        'sha384': 'SHA-384',
        'sha512': 'SHA-512',
      }[hashAlgorithm.name];
      if (hashName != null) {
        // Try performing this operation with Web Cryptography
        return web_crypto.ecdsaVerify(
          input,
          signature,
          namedCurve: _webCryptoName,
          hashName: hashName,
        );
      }
      throw UnimplementedError(
        'Unsupported hash algorithm: ${hashAlgorithm.name}',
      );
    }
    throw UnimplementedError('$name is not supported on the current platform');
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    throw UnimplementedError(
      '$name verifySync(...) is not supported on the current platform. Try asynchronous method?',
    );
  }
}

class _EcdsaP256 extends _EcdsaNist {
  static final _constantP = BigInt.parse(
    'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
    radix: 16,
  );
  static final _constantA = BigInt.parse(
    'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
    radix: 16,
  );
  static final _constantB = BigInt.parse(
    '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
    radix: 16,
  );
  static final _constantN = BigInt.parse(
    'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    radix: 16,
  );

  const _EcdsaP256(HashAlgorithm hashAlgorithm, {String name})
      : super(
          hashAlgorithm: hashAlgorithm,
          name: name,
          publicKeyLength: 32,
        );

  @override
  int get privateKeyLength => 32;

  @override
  BigInt get _a => _constantA;

  @override
  BigInt get _b => _constantB;

  @override
  BigInt get _n => _constantN;

  @override
  BigInt get _p => _constantP;

  @override
  String get _webCryptoName => 'P-256';
}

class _EcdsaP384 extends _EcdsaNist {
  static final _constantP = BigInt.parse(
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    'fffffffeffffffff0000000000000000ffffffff',
    radix: 16,
  );
  static final _constantA = BigInt.parse(
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    'fffffffeffffffff0000000000000000fffffffc',
    radix: 16,
  );
  static final _constantB = BigInt.parse(
    'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f'
    '5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
    radix: 16,
  );
  static final _constantN = BigInt.parse(
    'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81'
    'f4372ddf581a0db248b0a77aecec196accc52973',
    radix: 16,
  );

  const _EcdsaP384(HashAlgorithm hashAlgorithm, {String name})
      : super(
          hashAlgorithm: hashAlgorithm,
          name: name,
          publicKeyLength: 48,
        );

  @override
  int get privateKeyLength => 48;

  @override
  BigInt get _a => _constantA;

  @override
  BigInt get _b => _constantB;

  @override
  BigInt get _n => _constantN;

  @override
  BigInt get _p => _constantP;

  @override
  String get _webCryptoName => 'P-384';
}

class _EcdsaP521 extends _EcdsaNist {
  static final _constantP = BigInt.parse(
    '01ffffffffffffffffffffffffffffffffffffffffff'
    'ffffffffffffffffffffffffffffffffffffffffffffffff'
    'ffffffffffffffffffffffffffffffffffffffff',
    radix: 16,
  );
  static final _constantA = BigInt.parse(
    '01ffffffffffffffffffffffffffffffffffffffffff'
    'ffffffffffffffffffffffffffffffffffffffffffffffff'
    'fffffffffffffffffffffffffffffffffffffffc',
    radix: 16,
  );
  static final _constantB = BigInt.parse(
    '00000051953eb9618e1c9a1f929a21a0b68540eea2da725b'
    '99b315f3b8b489918ef109e156193951ec7e937b1652c0bd'
    '3bb1bf073573df883d2c34f1ef451fd46b503f00',
    radix: 16,
  );
  static final _constantN = BigInt.parse(
    '000001ffffffffffffffffffffffffffffffffffffffffff'
    'fffffffffffffffffffffffa51868783bf2f966b7fcc0148'
    'f709a5d03bb5c9b8899c47aebb6fb71e91386409',
    radix: 16,
  );

  const _EcdsaP521(HashAlgorithm hashAlgorithm, {String name})
      : super(
          hashAlgorithm: hashAlgorithm,
          name: name,
          publicKeyLength: 66,
        );

  @override
  int get privateKeyLength => 66;

  @override
  BigInt get _a => _constantA;

  @override
  BigInt get _b => _constantB;

  @override
  BigInt get _n => _constantN;

  @override
  BigInt get _p => _constantP;

  @override
  String get _webCryptoName => 'P-521';
}
