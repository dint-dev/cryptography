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
import 'package:cryptography/dart.dart';

import 'aes_cbc.dart';
import 'aes_ctr.dart';
import 'aes_gcm.dart';
import 'ecdh.dart';
import 'ecdsa.dart';
import 'hash.dart';
import 'hkdf.dart';
import 'hmac.dart';
import 'pbkdf2.dart';
import 'rsa_pss.dart';
import 'rsa_ssa_pkcs1v15.dart';

// Documented in the non-browser variant.
class BrowserCryptography extends DartCryptography {
  static final BrowserCryptography defaultInstance = BrowserCryptography();

  BrowserCryptography();

  @override
  AesCbc aesCbc({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
  }) {
    // Web Cryptography API does not support 192 bit keys
    if (secretKeyLength == 24) {
      return super.aesCbc(
        macAlgorithm: macAlgorithm,
        secretKeyLength: secretKeyLength,
      );
    }
    return BrowserAesCbc(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
    );
  }

  @override
  AesCtr aesCtr({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
    int counterBits = 64,
  }) {
    // Web Cryptography API does not support 192 bit keys
    if (secretKeyLength == 24) {
      return super.aesCtr(
        macAlgorithm: macAlgorithm,
        secretKeyLength: secretKeyLength,
        counterBits: counterBits,
      );
    }
    return BrowserAesCtr(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
      counterBits: counterBits,
    );
  }

  @override
  AesGcm aesGcm({int secretKeyLength = 32, int nonceLength = 12}) {
    // We always need fallback when keyStreamIndex != 0
    final fallback = super.aesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
    );
    // Web Cryptography API does not support 192 bit keys
    if (secretKeyLength == 24) {
      return fallback;
    }
    return BrowserAesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
      fallback: fallback,
    );
  }

  @override
  Ecdh ecdhP256({required int length}) {
    return BrowserEcdh.p256(length: length);
  }

  @override
  Ecdh ecdhP384({required int length}) {
    return BrowserEcdh.p384(length: length);
  }

  @override
  Ecdh ecdhP521({required int length}) {
    return BrowserEcdh.p521(length: length);
  }

  @override
  Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm) {
    if (hashAlgorithm is BrowserHashAlgorithmMixin) {
      return BrowserEcdsa.p256(hashAlgorithm);
    }
    return super.ecdsaP256(hashAlgorithm);
  }

  @override
  Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm) {
    if (hashAlgorithm is BrowserHashAlgorithmMixin) {
      return BrowserEcdsa.p384(hashAlgorithm);
    }
    return super.ecdsaP384(hashAlgorithm);
  }

  @override
  Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm) {
    if (hashAlgorithm is BrowserHashAlgorithmMixin) {
      return BrowserEcdsa.p521(hashAlgorithm);
    }
    return super.ecdsaP521(hashAlgorithm);
  }

  @override
  Hkdf hkdf({required Hmac hmac, required int outputLength}) {
    if (hmac is BrowserHmac) {
      return BrowserHkdf(
        hmac: hmac,
        outputLength: outputLength,
      );
    }
    return super.hkdf(hmac: hmac, outputLength: outputLength);
  }

  @override
  Hmac hmac(HashAlgorithm hashAlgorithm) {
    if (hashAlgorithm is BrowserSha1) {
      return BrowserHmac.sha1;
    }
    if (hashAlgorithm is BrowserSha256) {
      return BrowserHmac.sha256;
    }
    if (hashAlgorithm is BrowserSha384) {
      return BrowserHmac.sha384;
    }
    if (hashAlgorithm is BrowserSha512) {
      return BrowserHmac.sha512;
    }
    return super.hmac(hashAlgorithm);
  }

  @override
  Pbkdf2 pbkdf2({
    required MacAlgorithm macAlgorithm,
    required int iterations,
    required int bits,
  }) {
    if (macAlgorithm is BrowserHmac) {
      return BrowserPbkdf2(
        macAlgorithm: macAlgorithm,
        iterations: iterations,
        bits: bits,
      );
    }
    return super.pbkdf2(
      macAlgorithm: macAlgorithm,
      iterations: iterations,
      bits: bits,
    );
  }

  @override
  RsaPss rsaPss(
    HashAlgorithm hashAlgorithm, {
    required int nonceLengthInBytes,
  }) {
    if (hashAlgorithm is BrowserHashAlgorithmMixin) {
      return BrowserRsaPss(
        hashAlgorithm,
        nonceLengthInBytes: nonceLengthInBytes,
      );
    }
    return super.rsaPss(
      hashAlgorithm,
      nonceLengthInBytes: nonceLengthInBytes,
    );
  }

  @override
  RsaSsaPkcs1v15 rsaSsaPkcs1v15(HashAlgorithm hashAlgorithm) {
    if (hashAlgorithm is BrowserSha1) {
      return const BrowserRsaSsaPkcs1v15(BrowserSha1());
    }
    if (hashAlgorithm is BrowserSha256) {
      return const BrowserRsaSsaPkcs1v15(BrowserSha256());
    }
    if (hashAlgorithm is BrowserSha384) {
      return const BrowserRsaSsaPkcs1v15(BrowserSha384());
    }
    if (hashAlgorithm is BrowserSha512) {
      return const BrowserRsaSsaPkcs1v15(BrowserSha512());
    }
    return super.rsaSsaPkcs1v15(hashAlgorithm);
  }

  @override
  Sha1 sha1() => const BrowserSha1();

  @override
  Sha256 sha256() => const BrowserSha256();

  @override
  Sha384 sha384() => const BrowserSha384();

  @override
  Sha512 sha512() => const BrowserSha512();
}
