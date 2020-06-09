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

/// _P-256_ (secp256r1 / prime256v1) Elliptic Curve Diffie-Hellman (ECDH) key
/// exchange algorithm.
/// Currently supported __only in the browser.__
///
/// Private keys are instances of [JwkPrivateKey].
///
/// ## Example
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
const KeyExchangeAlgorithm ecdhP256 = _EcdhP256();

/// _P-384_ (secp384r1 / prime384v1) Elliptic Curve Diffie-Hellman (ECDH) key
/// exchange algorithm.
/// Currently supported __only in the browser.__
///
/// Private keys are instances of [JwkPrivateKey].
///
/// ## Example
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
const KeyExchangeAlgorithm ecdhP384 = _EcdhP384();

/// _P-521_ (secp521r1 / prime521v1) Elliptic Curve Diffie-Hellman (ECDH) key
/// exchange algorithm.
/// Currently supported __only in the browser.__
///
/// Private keys are instances of [JwkPrivateKey].
///
/// ## Example
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
const KeyExchangeAlgorithm ecdhP521 = _EcdhP521();

abstract class _EcdhNist extends KeyExchangeAlgorithm {
  @override
  final String name;

  @override
  final int publicKeyLength;

  const _EcdhNist({
    @required this.name,
    @required this.publicKeyLength,
  });
  BigInt get _a;
  BigInt get _b;
  BigInt get _n;

  BigInt get _p;

  String get _webCryptoName;

  @override
  Future<KeyPair> newKeyPair() {
    if (web_crypto.isWebCryptoSupported) {
      return web_crypto.ecdhNewKeyPair(
        curve: _webCryptoName,
      );
    }
    return super.newKeyPair();
  }

  @override
  KeyPair newKeyPairSync() {
    throw UnimplementedError();
  }

  @override
  Future<SecretKey> sharedSecret(
      {PrivateKey localPrivateKey, PublicKey remotePublicKey}) {
    if (web_crypto.isWebCryptoSupported) {
      return web_crypto.ecdhSharedSecret(
        localPrivateKey: localPrivateKey,
        remotePublicKey: remotePublicKey,
        curve: _webCryptoName,
      );
    }
    throw UnimplementedError('$name is not supported on the current platform');
  }

  @override
  SecretKey sharedSecretSync({
    @required PrivateKey localPrivateKey,
    @required PublicKey remotePublicKey,
  }) {
    assert(_p != null);
    assert(_a != null);
    assert(_b != null);
    assert(_n != null);
    throw UnimplementedError(
      '$name (synchronous method) is not supported on the current platform. Try asynchronous method?',
    );
  }
}

class _EcdhP256 extends _EcdhNist {
  static final _constantP = BigInt.parse(
    'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
    radix: 16,
  );
  static final _constantA = BigInt.parse(
    'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
  );
  static final _constantB = BigInt.parse(
    '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
  );
  static final _constantN = BigInt.parse(
    'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
  );

  const _EcdhP256()
      : super(
          name: 'ecdhP256',
          publicKeyLength: 32,
        );

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

class _EcdhP384 extends _EcdhNist {
  static final _constantP = BigInt.parse(
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    'fffffffeffffffff0000000000000000ffffffff',
  );
  static final _constantA = BigInt.parse(
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    'fffffffeffffffff0000000000000000fffffffc',
  );
  static final _constantB = BigInt.parse(
    'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f '
    '5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
  );
  static final _constantN = BigInt.parse(
    'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81'
    'f4372ddf581a0db248b0a77aecec196accc52973',
  );

  const _EcdhP384()
      : super(
          name: 'ecdhP384',
          publicKeyLength: 48,
        );

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

class _EcdhP521 extends _EcdhNist {
  static final _constantP = BigInt.parse(
    '000001ffffffffffffffffffffffffffffffffffffffffff '
    'ffffffffffffffffffffffffffffffffffffffffffffffff '
    'ffffffffffffffffffffffffffffffffffffffff',
  );
  static final _constantA = BigInt.parse(
    '000001ffffffffffffffffffffffffffffffffffffffffff '
    'ffffffffffffffffffffffffffffffffffffffffffffffff '
    'fffffffffffffffffffffffffffffffffffffffc',
  );
  static final _constantB = BigInt.parse(
    '00000051953eb9618e1c9a1f929a21a0b68540eea2da725b'
    '99b315f3b8b489918ef109e156193951ec7e937b1652c0bd'
    '3bb1bf073573df883d2c34f1ef451fd46b503f00',
  );
  static final _constantN = BigInt.parse(
    '000001ffffffffffffffffffffffffffffffffffffffffff '
    'fffffffffffffffffffffffa51868783bf2f966b7fcc0148 '
    'f709a5d03bb5c9b8899c47aebb6fb71e91386409',
  );

  const _EcdhP521()
      : super(
          name: 'ecdhP521',
          publicKeyLength: 66,
        );

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
