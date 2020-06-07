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

import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

const SignatureAlgorithm dartEcdsaP256Sha256 = _P256(
  sha256,
  name: 'ecdsaP256Sha256',
);

const SignatureAlgorithm dartEcdsaP384Sha256 = _P384(
  sha256,
  name: 'ecdsaP384Sha256',
);

const SignatureAlgorithm dartEcdsaP384Sha384 = _P384(
  sha384,
  name: 'ecdsaP384Sha384',
);

const SignatureAlgorithm dartEcdsaP521Sha256 = _P521(
  sha256,
  name: 'ecdsaP521Sha256',
);

const SignatureAlgorithm dartEcdsaP521Sha512 = _P521(
  sha512,
  name: 'ecdsaP521Sha512',
);

class _P384 extends _EcdsaNist {
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

  @override
  BigInt get _p => _constantP;

  @override
  BigInt get _a => _constantA;

  @override
  BigInt get _b => _constantB;

  @override
  BigInt get _n => _constantN;

  @override
  int get privateKeyLength => 48;

  const _P384(HashAlgorithm hashAlgorithm, {String name})
      : super(
          hashAlgorithm: hashAlgorithm,
          name: name,
          publicKeyLength: 48,
        );
}

class _P521 extends _EcdsaNist {
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

  @override
  BigInt get _p => _constantP;

  @override
  BigInt get _a => _constantA;

  @override
  BigInt get _b => _constantB;

  @override
  BigInt get _n => _constantN;

  @override
  int get privateKeyLength => 66;

  const _P521(HashAlgorithm hashAlgorithm, {String name})
      : super(
          hashAlgorithm: hashAlgorithm,
          name: name,
          publicKeyLength: 66,
        );
}

class _P256 extends _EcdsaNist {
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

  @override
  int get privateKeyLength => 32;

  @override
  BigInt get _p => _constantP;

  @override
  BigInt get _a => _constantA;

  @override
  BigInt get _b => _constantB;

  @override
  BigInt get _n => _constantN;

  const _P256(HashAlgorithm hashAlgorithm, {String name})
      : super(
          hashAlgorithm: hashAlgorithm,
          name: name,
          publicKeyLength: 32,
        );
}

abstract class _EcdsaNist extends SignatureAlgorithm {
  @override
  final String name;

  @override
  final int publicKeyLength;

  /// Modulus
  BigInt get _p;

  BigInt get _a;

  BigInt get _b;

  BigInt get _n;

  final HashAlgorithm hashAlgorithm;

  const _EcdsaNist({
    @required this.hashAlgorithm,
    @required this.name,
    @required this.publicKeyLength,
  });

  int get privateKeyLength;

  PublicKey _publicKeyFromPrivateKey(PrivateKey privateKey) {
    throw UnimplementedError();
  }

  @override
  KeyPair newKeyPairSync() {
    final privateKey = PrivateKey.randomBytes(privateKeyLength);
    return KeyPair(
      privateKey: privateKey,
      publicKey: _publicKeyFromPrivateKey(privateKey),
    );
  }

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    assert(_p != null);
    assert(_a != null);
    assert(_b != null);
    assert(_n != null);
    throw UnimplementedError();
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    throw UnimplementedError();
  }
}