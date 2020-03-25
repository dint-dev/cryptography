// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

/// Generates [KeyPair] instances from seeds.
///
/// For example, [x25519] supports this seeds.
abstract class SeedableKeyPairGenerator extends KeyPairGenerator {
  int get defaultSeedLength;

  const SeedableKeyPairGenerator();

  @override
  Future<KeyPair> generate() async {
    return Future<KeyPair>(() => generateSync());
  }

  /// Generates a key pair from the seed bytes. The result is deterministic.
  Future<KeyPair> generateFromSeed(PrivateKey seedKey) {
    return Future<KeyPair>(() => generateFromSeedSync(seedKey));
  }

  /// Generates a key pair from the seed bytes. The result is deterministic.
  KeyPair generateFromSeedSync(PrivateKey seedKey);

  @override
  KeyPair generateSync() {
    return generateFromSeedSync(PrivateKey.randomBytes(defaultSeedLength));
  }
}

/// Generates [KeyPair] instances.
///
/// This is helper used by [KeyExchangeAlgorithm] and [SignatureAlgorithm]
/// subclasses.
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final keyPairGenerator = x25519.keyPairGenerator;
///   final keyPair = keyPairGenerator.generateSync();
/// }
/// ```
abstract class KeyPairGenerator {
  String get name;

  int get lengthInBytes => null;

  const KeyPairGenerator();

  /// Generates a random [KeyPair].
  Future<KeyPair> generate() async {
    return Future<KeyPair>(() => generateSync());
  }

  /// Generates a random [KeyPair].
  KeyPair generateSync();
}
