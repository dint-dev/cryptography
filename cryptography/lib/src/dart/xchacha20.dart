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
import 'package:cryptography_plus/dart.dart';

/// [Xchacha20] implemented in pure Dart.
///
/// For more information about the algorithm and examples, see documentation
/// for the class [Xchacha20].
class DartXchacha20 extends Xchacha20
    with DartCipherMixin, DartCipherWithStateMixin {
  /// [MacAlgorithm] used by [DartXchacha20.poly1305Aead].
  static const MacAlgorithm poly1305AeadMacAlgorithm =
      _DartXchacha20Poly1305AeadMacAlgorithm();

  @override
  final MacAlgorithm macAlgorithm;

  /// Constructs [Xchacha20] with any [MacAlgorithm].
  DartXchacha20({
    required this.macAlgorithm,
    super.random,
  }) : super.constructor();

  const DartXchacha20.poly1305Aead({
    super.random,
  })  : macAlgorithm = poly1305AeadMacAlgorithm,
        super.constructor();

  @override
  int get nonceLength => 24;

  @override
  int get secretKeyLength => 32;

  @override
  DartCipherState newState() {
    return _DartXchacha20State(
      cipher: this,
    );
  }
}

/// [MacAlgorithm] used by [DartXchacha20.poly1305Aead].
class _DartXchacha20Poly1305AeadMacAlgorithm
    extends DartChacha20Poly1305AeadMacAlgorithm {
  const _DartXchacha20Poly1305AeadMacAlgorithm();

  @override
  DartMacSinkMixin newMacSinkSync({
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    final result = _DartXchacha20Poly1305AeadMacAlgorithmSink();
    result.initializeSync(
      secretKey: secretKeyData,
      nonce: nonce,
      aad: aad,
    );
    return result;
  }

  @override
  _DartXchacha20Poly1305AeadMacAlgorithm toSync() {
    return this;
  }
}

/// [MacSink] used by [DartXchacha20.poly1305Aead].
class _DartXchacha20Poly1305AeadMacAlgorithmSink
    extends DartChacha20Poly1305AeadMacAlgorithmSink {
  @override
  SecretKeyData deriveSecretKey({
    required SecretKeyData secretKey,
    required List<int> nonce,
  }) {
    if (nonce.length != 24) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Invalid length ${nonce.length}',
      );
    }
    final intermediateSecretKey = const DartHChacha20().deriveKeySync(
      secretKeyData: secretKey,
      nonce: nonce.sublist(0, 16),
    );
    final intermediateNonce = Uint8List(12);
    for (var i = 0; i < 8; i++) {
      intermediateNonce[4 + i] = nonce[16 + i];
    }
    return super.deriveSecretKey(
      secretKey: intermediateSecretKey,
      nonce: intermediateNonce,
    );
  }
}

/// [CipherState] used by [DartXchacha20].
class _DartXchacha20State extends DartChacha20State {
  _DartXchacha20State({
    required super.cipher,
  });

  @override
  SecretKeyData deriveKeySync({
    required SecretKeyData secretKey,
    required List<int> nonce,
  }) {
    if (nonce.length != 24) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Invalid length ${nonce.length}',
      );
    }
    return const DartHChacha20().deriveKeySync(
      secretKeyData: secretKey,
      nonce: nonce.sublist(0, 16),
    );
  }

  @override
  List<int> deriveNonce({
    required SecretKeyData secretKey,
    required List<int> nonce,
  }) {
    final nonce96Bits = Uint8List(12);
    for (var i = 0; i < 8; i++) {
      nonce96Bits[4 + i] = nonce[16 + i];
    }
    return nonce96Bits;
  }
}
