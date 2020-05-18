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
import 'package:cryptography/src/utils/parameters.dart';
import 'package:meta/meta.dart';

import 'chacha20_impl.dart';

/// XChaCha20 cipher ([draft-irtf-cfrg-xchacha](https://tools.ietf.org/html/draft-arciszewski-xchacha-03)).
///
/// XChaCha20 uses 192-bit nonces whereas ChaCha20 uses 96-bit nonces.
///
/// ## Things to know
///   * `secretKey` must be 32 bytes.
///   * `nonce` must be 24 bytes.
///   * `keyStreamIndex` enables choosing index in the key  stream.
///   * Make sure you don't use the same (key, nonce) combination twice.
///   * Make sure you don't use the cipher without authentication (such as
///     [xchacha20Poly1305Aead] or [CipherWithAppendedMac]).
///
/// ## Example
///
/// See examples in [chacha20].
const Cipher xchacha20 = _XChaCha(
  name: 'xchacha20',
  rounds: 20,
);

class _XChaCha extends Cipher {
  final int _rounds;

  @override
  final String name;

  const _XChaCha({
    @required this.name,
    @required int rounds,
  })  : assert(name != null),
        assert(rounds != null),
        _rounds = rounds;

  @override
  int get nonceLength => 24;

  @override
  int get nonceLengthMax => 24;

  @override
  int get nonceLengthMin => 24;

  @override
  int get secretKeyLength => 32;

  @override
  Set<int> get secretKeyValidLengths => <int>{32};

  @override
  Uint8List decryptSync(List<int> input,
      {SecretKey secretKey,
      Nonce nonce,
      List<int> aad,
      int keyStreamIndex = 0}) {
    final secretKeyBytes = secretKey.extractSync();
    checkCipherParameters(
      this,
      secretKeyLength: secretKeyBytes.length,
      nonce: nonce,
      aad: aad != null,
      keyStreamIndex: keyStreamIndex,
      keyStreamFactor: 1,
    );

    // Create a new secret key with hchacha20.
    final oldNonceBytes = Uint8List.fromList(nonce.bytes);
    final newSecretKey = const HChacha20().deriveKeySync(
      secretKey: secretKey,
      nonce: Nonce(Uint8List.view(oldNonceBytes.buffer, 0, 16)),
    );

    // Create new nonce.
    // The first 4 bytes will be zeroes.
    // The last 8 bytes will be the last 8 bytes of the original nonce.
    final newNonceBytes = Uint8List(12);
    for (var i = 0; i < 8; i++) {
      newNonceBytes[4 + i] = oldNonceBytes[16 + i];
    }

    // Decrypt with chacha
    return _chacha.decryptSync(
      input,
      secretKey: newSecretKey,
      nonce: Nonce(newNonceBytes),
      keyStreamIndex: keyStreamIndex,
    );
  }

  /// Chacha cipher with the same rounds count.
  Cipher get _chacha {
    final rounds = _rounds;
    return rounds == 20
        ? chacha20
        : ChaCha(
            rounds: rounds,
            name: '',
          );
  }

  @override
  Uint8List encryptSync(List<int> input,
      {SecretKey secretKey,
      Nonce nonce,
      List<int> aad,
      int keyStreamIndex = 0}) {
    ArgumentError.checkNotNull(secretKey, 'secretKey');
    final secretKeyBytes = secretKey.extractSync();
    checkCipherParameters(
      this,
      secretKeyLength: secretKeyBytes.length,
      nonce: nonce,
      aad: aad != null,
      keyStreamIndex: keyStreamIndex,
      keyStreamFactor: 1,
    );

    // Create a new secret key with hchacha20.
    final oldNonceBytes = Uint8List.fromList(nonce.bytes);
    final newSecretKey = const HChacha20().deriveKeySync(
      secretKey: secretKey,
      nonce: Nonce(Uint8List.view(oldNonceBytes.buffer, 0, 16)),
    );

    // Create new nonce.
    // The first 4 bytes will be zeroes.
    // The last 8 bytes will be the last 8 bytes of the original nonce.
    final newNonceBytes = Uint8List(12);
    for (var i = 0; i < 8; i++) {
      newNonceBytes[4 + i] = oldNonceBytes[16 + i];
    }

    // Encrypt with chacha
    return _chacha.encryptSync(
      input,
      secretKey: newSecretKey,
      nonce: Nonce(newNonceBytes),
      keyStreamIndex: keyStreamIndex,
    );
  }
}
