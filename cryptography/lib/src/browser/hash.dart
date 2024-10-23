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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:meta/meta.dart';

import '_javascript_bindings.dart' as web_crypto;
import '_javascript_bindings.dart' show jsArrayBufferFrom;

mixin BrowserHashAlgorithmMixin implements HashAlgorithm {
  /// Web Cryptography API algorithm name ("SHA-256", etc.).
  String get webCryptoName;

  @override
  Future<Hash> hash(List<int> bytes) async {
    final byteBuffer = await web_crypto.digest(
      webCryptoName,
      jsArrayBufferFrom(bytes),
    );
    return Hash(Uint8List.view(byteBuffer));
  }

  static String? hashAlgorithmNameFor(HashAlgorithm hashAlgorithm) {
    if (hashAlgorithm is Sha1) {
      return 'SHA-1';
    }
    if (hashAlgorithm is Sha256) {
      return 'SHA-256';
    }
    if (hashAlgorithm is Sha384) {
      return 'SHA-384';
    }
    if (hashAlgorithm is Sha512) {
      return 'SHA-512';
    }
    return null;
  }
}

/// [Sha1] implementation that uses _Web Cryptography API_ in browsers.
///
/// See [BrowserCryptography].
class BrowserSha1 extends Sha1 with BrowserHashAlgorithmMixin {
  @literal
  const BrowserSha1() : super.constructor();

  @override
  String get webCryptoName => 'SHA-1';
}

/// [Sha256] implementation that uses _Web Cryptography API_ in browsers.
///
/// See [BrowserCryptography].
class BrowserSha256 extends Sha256 with BrowserHashAlgorithmMixin {
  @literal
  const BrowserSha256() : super.constructor();

  @override
  String get webCryptoName => 'SHA-256';
}

/// [Sha384] implementation that uses _Web Cryptography API_ in browsers.
///
/// See [BrowserCryptography].
class BrowserSha384 extends Sha384 with BrowserHashAlgorithmMixin {
  @literal
  const BrowserSha384() : super.constructor();

  @override
  String get webCryptoName => 'SHA-384';
}

/// [Sha512] implementation that uses _Web Cryptography API_ in browsers.
///
/// See [BrowserCryptography].
class BrowserSha512 extends Sha512 with BrowserHashAlgorithmMixin {
  @literal
  const BrowserSha512() : super.constructor();

  @override
  String get webCryptoName => 'SHA-512';
}
