// Copyright 2019 Gohilla (opensource@gohilla.com).
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

abstract class KeyExchangeAlgorithm {
  String get name;

  final int keyLengthInBytes;

  const KeyExchangeAlgorithm({this.keyLengthInBytes});

  /// Generates a random [KeyPair].
  ///
  /// Optional parameter [seed] can be used to supply the bytes the key is
  /// derived from. If the implementation does not support seeds, it will throw
  /// [UnsupportedError].
  KeyPair newKeyPair() {
    return newKeyPairFromSeed(SecretKey.randomBytes(keyLengthInBytes));
  }

  /// Generates a key pair from the seed bytes.
  KeyPair newKeyPairFromSeed(SecretKey seedKey);

  /// Calculates a shared secret.
  SecretKey sharedSecret(SecretKey secretKey, PublicKey publicKey);
}
