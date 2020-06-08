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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

import 'pbkdf2_impl.dart'
    if (dart.library.html) '../web_crypto/web_crypto_impl_browser.dart';

/// PBKDF2 password hashing algorithm. PBKDF2 is recommended by NIST.
///
/// In browsers, the implementation automatically uses Web Cryptography API.
///
/// ## Things to know
///   * `macAlgorithm` can be any MAC algorithm, but we recommend [Hmac]:
///     * `Hmac(sha256)`
///     * `Hmac(sha384)`
///     * `Hmac(sha512)`
///   * `iterations` should be at least 10,000, preferably over 100,000.
///   * `bits` should be 128 or higher.
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final pbkdf2 = Pbkdf2(
///     macAlgorithm: Hmac(sha256),
///     iterations: 100000,
///     bits: 128,
///   );
///
///   final hashBytes = await pbkdf2.deriveBits(
///     utf8.encode('qwerty'),
///     salt:[1,2,3],
///   );
///
///   print('Hash: $hashBytes');
/// }
/// ```
abstract class Pbkdf2 {
  const factory Pbkdf2({
    @required MacAlgorithm macAlgorithm,
    @required int iterations,
    @required int bits,
  }) = Pbkdf2Impl;

  MacAlgorithm get macAlgorithm;
  int get bits;
  int get iterations;

  Future<Uint8List> deriveBits(
    List<int> input, {
    @required Nonce nonce,
  });

  Uint8List deriveBitsSync(
    List<int> input, {
    @required Nonce nonce,
  });
}
