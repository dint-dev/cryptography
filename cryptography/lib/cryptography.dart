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

/// Cryptographic algorithms for Dart / Flutter developers.
///
/// ## Algorithm types
///   * [Cipher]
///   * [KeyExchangeAlgorithm]
///   * [KdfAlgorithm]
///   * [HashAlgorithm]
///   * [MacAlgorithm]
///   * [SignatureAlgorithm]
///
/// ## Implementation factory
///
/// [Cryptography.instance] determines which implementation of an algorithm is
/// used when you call factory method such as [Sha256()].
///
library cryptography;

import 'package:cryptography/cryptography.dart';

export 'src/cryptography/algorithms.dart';
export 'src/cryptography/cipher.dart';
export 'src/cryptography/cryptography.dart';
export 'src/cryptography/ec_key_pair.dart';
export 'src/cryptography/ec_public_key.dart';
export 'src/cryptography/hash.dart';
export 'src/cryptography/hash_algorithm.dart';
export 'src/cryptography/kdf_algorithm.dart';
export 'src/cryptography/key_exchange_algorithm.dart';
export 'src/cryptography/key_pair.dart';
export 'src/cryptography/key_pair_type.dart';
export 'src/cryptography/mac.dart';
export 'src/cryptography/mac_algorithm.dart';
export 'src/cryptography/rsa_key_pair.dart';
export 'src/cryptography/rsa_public_key.dart';
export 'src/cryptography/secret_box.dart';
export 'src/cryptography/secret_key.dart';
export 'src/cryptography/secret_key_type.dart';
export 'src/cryptography/signature.dart';
export 'src/cryptography/signature_algorithm.dart';
export 'src/cryptography/simple_key_pair.dart';
export 'src/cryptography/simple_public_key.dart';
