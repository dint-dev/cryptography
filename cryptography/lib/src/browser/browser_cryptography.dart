// Copyright 2019-2020 Gohilla.
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

import 'dart:math';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/src/browser/rsa_pss.dart';
import 'package:cryptography_plus/src/browser/rsa_ssa_pkcs1v15.dart';
import 'package:meta/meta.dart';

import '_javascript_bindings.dart' show isWebCryptoAvailable;
import 'aes_cbc.dart';
import 'aes_ctr.dart';
import 'aes_gcm.dart';
import 'ecdh.dart';
import 'ecdsa.dart';
import 'hash.dart';
import 'hkdf.dart';
import 'hmac.dart';
import 'pbkdf2.dart';

class BrowserCryptography extends DartCryptography {
  // Documented in browser_cryptography_when_not_browser.dart
  static final Cryptography defaultInstance =
      isSupported ? BrowserCryptography() : DartCryptography();

  /// @nodoc
  // TODO: Remove this
  @visibleForTesting
  static bool isDisabledForTesting = false;

  // Documented in browser_cryptography_when_not_browser.dart
  static bool get isSupported => isWebCryptoAvailable && !isDisabledForTesting;

  final Random? _random;

  // Documented in browser_cryptography_when_not_browser.dart
  BrowserCryptography({
    Random? random,
  })  : _random = random,
        super(random: random);

  @override
  AesCbc aesCbc({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
    int secretKeyLength = 32,
  }) {
    // Web Cryptography API supports only 128 and 256 bit keys.
    if (isSupported &&
        secretKeyLength != 24 &&
        identical(paddingAlgorithm, PaddingAlgorithm.pkcs7)) {
      return BrowserAesCbc(
        macAlgorithm: macAlgorithm,
        secretKeyLength: secretKeyLength,
        random: _random,
      );
    }
    return super.aesCbc(
      macAlgorithm: macAlgorithm,
      paddingAlgorithm: paddingAlgorithm,
      secretKeyLength: secretKeyLength,
    );
  }

  @override
  AesCtr aesCtr({
    required MacAlgorithm macAlgorithm,
    int secretKeyLength = 32,
    int counterBits = AesCtr.defaultCounterBits,
  }) {
    // Web Cryptography API supports only 128 and 256 bit keys.
    if (isSupported && secretKeyLength != 24) {
      return BrowserAesCtr(
        macAlgorithm: macAlgorithm,
        secretKeyLength: secretKeyLength,
        counterBits: counterBits,
        random: _random,
      );
    }
    return super.aesCtr(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
      counterBits: counterBits,
    );
  }

  @override
  AesGcm aesGcm({int secretKeyLength = 32, int nonceLength = 12}) {
    final fallback = super.aesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
    );
    // Web Cryptography API supports only 128 and 256 bit keys.
    if (isSupported && secretKeyLength != 24) {
      return BrowserAesGcm(
        secretKeyLength: secretKeyLength,
        nonceLength: nonceLength,
        fallback: fallback,
        random: _random,
      );
    }
    return fallback;
  }

  @override
  Ecdh ecdhP256({required int length}) {
    if (isSupported) {
      return BrowserEcdh.p256(
        length: length,
        random: _random,
      );
    }
    return super.ecdhP256(length: length);
  }

  @override
  Ecdh ecdhP384({required int length}) {
    if (isSupported) {
      return BrowserEcdh.p384(
        length: length,
        random: _random,
      );
    }
    return super.ecdhP384(length: length);
  }

  @override
  Ecdh ecdhP521({required int length}) {
    if (isSupported) {
      return BrowserEcdh.p521(
        length: length,
        random: _random,
      );
    }
    return super.ecdhP521(length: length);
  }

  @override
  Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm) {
    if (isSupported && hashAlgorithm is Sha256) {
      return BrowserEcdsa.p256(
        hashAlgorithm,
        random: _random,
      );
    }
    return super.ecdsaP256(hashAlgorithm);
  }

  @override
  Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm) {
    if (isSupported && hashAlgorithm is Sha384) {
      return BrowserEcdsa.p384(
        hashAlgorithm,
        random: _random,
      );
    }
    return super.ecdsaP384(hashAlgorithm);
  }

  @override
  Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm) {
    if (isSupported && hashAlgorithm is Sha512) {
      return BrowserEcdsa.p521(
        hashAlgorithm,
        random: _random,
      );
    }
    return super.ecdsaP521(hashAlgorithm);
  }

  @override
  Hkdf hkdf({required Hmac hmac, required int outputLength}) {
    if (isSupported) {
      if (BrowserHashAlgorithmMixin.hashAlgorithmNameFor(hmac.hashAlgorithm) !=
          null) {
        return BrowserHkdf(
          hmac: hmac,
          outputLength: outputLength,
        );
      }
    }
    return super.hkdf(
      hmac: hmac,
      outputLength: outputLength,
    );
  }

  @override
  Hmac hmac(HashAlgorithm hashAlgorithm) {
    if (isSupported) {
      if (hashAlgorithm is Sha1) {
        return BrowserHmac.sha1;
      }
      if (hashAlgorithm is Sha256) {
        return BrowserHmac.sha256;
      }
      if (hashAlgorithm is Sha384) {
        return BrowserHmac.sha384;
      }
      if (hashAlgorithm is Sha512) {
        return BrowserHmac.sha512;
      }
    }
    return super.hmac(hashAlgorithm);
  }

  @override
  Pbkdf2 pbkdf2({
    required MacAlgorithm macAlgorithm,
    required int iterations,
    required int bits,
  }) {
    if (isSupported && macAlgorithm is BrowserHmac) {
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
    if (isSupported && hashAlgorithm is BrowserHashAlgorithmMixin) {
      return BrowserRsaPss(
        hashAlgorithm,
        nonceLengthInBytes: nonceLengthInBytes,
        random: _random,
      );
    }
    return super.rsaPss(
      hashAlgorithm,
      nonceLengthInBytes: nonceLengthInBytes,
    );
  }

  @override
  RsaSsaPkcs1v15 rsaSsaPkcs1v15(HashAlgorithm hashAlgorithm) {
    if (isSupported) {
      if (hashAlgorithm is BrowserSha1) {
        return BrowserRsaSsaPkcs1v15(
          const BrowserSha1(),
          random: _random,
        );
      }
      if (hashAlgorithm is BrowserSha256) {
        return BrowserRsaSsaPkcs1v15(
          const BrowserSha256(),
          random: _random,
        );
      }
      if (hashAlgorithm is BrowserSha384) {
        return BrowserRsaSsaPkcs1v15(
          const BrowserSha384(),
          random: _random,
        );
      }
      if (hashAlgorithm is BrowserSha512) {
        return BrowserRsaSsaPkcs1v15(
          const BrowserSha512(),
          random: _random,
        );
      }
    }
    return super.rsaSsaPkcs1v15(hashAlgorithm);
  }

  @override
  Sha1 sha1() {
    if (isSupported) {
      return const BrowserSha1();
    }
    return super.sha1();
  }

  @override
  Sha256 sha256() {
    if (isSupported) {
      return const BrowserSha256();
    }
    return super.sha256();
  }

  @override
  Sha384 sha384() {
    if (isSupported) {
      return const BrowserSha384();
    }
    return super.sha384();
  }

  @override
  Sha512 sha512() {
    if (isSupported) {
      return const BrowserSha512();
    }
    return super.sha512();
  }

  @override
  BrowserCryptography withRandom(Random? random) {
    return BrowserCryptography(random: random);
  }
}
