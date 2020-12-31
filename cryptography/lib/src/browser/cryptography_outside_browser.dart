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

/// An implementation of [Cryptography] using Web Cryptography API.
///
/// # Algorithms
/// The following algorithms are supported:
///   * [aesCbc]
///   * [aesCtr]
///   * [aesGcm]
///   * [ecdhP256]
///   * [ecdhP384]
///   * [ecdhP521]
///   * [ecdsaP256]
///   * [ecdsaP384]
///   * [ecdsaP521]
///   * [hkdf]
///   * [hmac]
///   * [pbkdf2]
///   * [rsaPss]
///   * [rsaSsaPkcs1v15]
///   * [sha1]
///   * [sha256]
///   * [sha384]
///   * [sha512]
class BrowserCryptography extends DartCryptography {
  static final BrowserCryptography defaultInstance = BrowserCryptography();
}
