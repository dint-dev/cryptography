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

/// A vendor-agnostic API for using Key Management Service (KMS) products/APIs.
library kms;

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';

class Kms {
  Future<void> deleteKeyPair(KmsKeyPair keyPair) {
    throw UnsupportedError('Does not support key pair deletion: $this');
  }

  Future<EcKeyPair> newKeyPairEcdh(Ecdh fallback) {
    return fallback.newKeyPair();
  }

  Future<EcKeyPair> newKeyPairEcdsa(Ecdsa fallback) {
    return fallback.newKeyPair();
  }

  Future<SimpleKeyPair> newKeyPairEd25519(Ed25519 fallback) {
    return fallback.newKeyPair();
  }

  Future<RsaKeyPair> newKeyPairRsaPss(
    RsaPss fallback, {
    int modulusLength = RsaPss.defaultModulusLength,
    List<int> publicExponent = RsaPss.defaultPublicExponent,
  }) {
    return fallback.newKeyPair(
      modulusLength: modulusLength,
      publicExponent: publicExponent,
    );
  }

  Future<RsaKeyPair> newKeyPairRsaSsaPkcs1v15(
    RsaSsaPkcs1v15 fallback, {
    int modulusLength = RsaSsaPkcs1v15.defaultModulusLength,
    List<int> publicExponent = RsaSsaPkcs1v15.defaultPublicExponent,
  }) {
    return fallback.newKeyPair();
  }

  Future<Signature> signEcdsa(Ecdsa fallback, List<int> message,
      {required KmsKeyPair keyPair}) {
    return fallback.sign(message, keyPair: keyPair);
  }

  Future<Signature> signEd25519(Ed25519 fallback, List<int> message,
      {required KmsKeyPair keyPair}) {
    return fallback.sign(message, keyPair: keyPair);
  }

  Future<Signature> signRsaPkcs1v15(RsaPss fallback, List<int> message,
      {required KmsKeyPair keyPair}) {
    return fallback.sign(message, keyPair: keyPair);
  }

  Future<Signature> signRsaPss(RsaPss fallback, List<int> message,
      {required KmsKeyPair keyPair}) {
    return fallback.sign(message, keyPair: keyPair);
  }
}

class KmsCryptography extends DelegatingCryptography {
  final Kms kms;

  @override
  final Cryptography fallback;

  const KmsCryptography(this.kms, this.fallback);

  @override
  Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm) {
    return _KmsEcdsa(kms, fallback.ecdsaP256(hashAlgorithm));
  }

  @override
  Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm) {
    return _KmsEcdsa(kms, fallback.ecdsaP384(hashAlgorithm));
  }

  @override
  Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm) {
    return _KmsEcdsa(kms, fallback.ecdsaP521(hashAlgorithm));
  }

  @override
  Ed25519 ed25519() {
    return _KmsEd25519(kms, fallback.ed25519());
  }

  @override
  RsaPss rsaPss(HashAlgorithm hashAlgorithm,
      {required int nonceLengthInBytes}) {
    return _KmsRsaPss(kms,
        super.rsaPss(hashAlgorithm, nonceLengthInBytes: nonceLengthInBytes));
  }
}

abstract class KmsKeyPair implements KeyPair {
  final Kms kms;

  KmsKeyPair(this.kms);

  Future<void> delete() {
    throw UnsupportedError('Deleting this KMS key pair is unsupported.');
  }
}

class _KmsEcdsa extends DelegatingEcdsa {
  final Kms kms;

  @override
  final Ecdsa fallback;

  _KmsEcdsa(this.kms, this.fallback);

  @override
  Future<Signature> sign(List<int> message, {required KeyPair keyPair}) {
    if (keyPair is KmsKeyPair) {
      return kms.signEcdsa(fallback, message, keyPair: keyPair);
    }
    return fallback.sign(message, keyPair: keyPair);
  }
}

class _KmsEd25519 extends DelegatingEd25519 {
  final Kms kms;

  @override
  final Ed25519 fallback;

  _KmsEd25519(this.kms, this.fallback);

  @override
  Future<Signature> sign(List<int> message, {required KeyPair keyPair}) {
    if (keyPair is KmsKeyPair) {
      return kms.signEd25519(fallback, message, keyPair: keyPair);
    }
    return fallback.sign(message, keyPair: keyPair);
  }
}

class _KmsRsaPss extends DelegatingRsaPss {
  final Kms kms;

  @override
  final RsaPss fallback;

  _KmsRsaPss(this.kms, this.fallback);

  @override
  Future<Signature> sign(List<int> message, {required KeyPair keyPair}) {
    if (keyPair is KmsKeyPair) {
      return kms.signRsaPss(fallback, message, keyPair: keyPair);
    }
    return fallback.sign(message, keyPair: keyPair);
  }
}
