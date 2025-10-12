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

import '../../helpers.dart';
import '../utils.dart';
import 'aes_impl.dart';

/// [AesCtr] implemented in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the class [AesCtr].
class DartAesCtr extends AesCtr with DartAesMixin, DartCipherWithStateMixin {
  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int counterBits;

  @override
  final int secretKeyLength;

  const DartAesCtr({
    required this.macAlgorithm,
    this.secretKeyLength = 32,
    this.counterBits = AesCtr.defaultCounterBits,
    super.random,
  })  : assert(secretKeyLength == 16 ||
            secretKeyLength == 24 ||
            secretKeyLength == 32),
        super.constructor();

  /// Constructs [DartAesCtr] with 128-bit secret keys.
  const DartAesCtr.with128bits({
    required MacAlgorithm macAlgorithm,
    int counterBits = AesCtr.defaultCounterBits,
  }) : this(
          secretKeyLength: 16,
          macAlgorithm: macAlgorithm,
          counterBits: counterBits,
        );

  /// Constructs [DartAesCtr] with 192-bit secret keys.
  const DartAesCtr.with192bits({
    required MacAlgorithm macAlgorithm,
    int counterBits = AesCtr.defaultCounterBits,
  }) : this(
          secretKeyLength: 24,
          macAlgorithm: macAlgorithm,
          counterBits: counterBits,
        );

  /// Constructs [DartAesCtr] with 256-bit secret keys.
  const DartAesCtr.with256bits({
    required MacAlgorithm macAlgorithm,
    int counterBits = AesCtr.defaultCounterBits,
  }) : this(
          secretKeyLength: 32,
          macAlgorithm: macAlgorithm,
          counterBits: counterBits,
        );

  @override
  DartCipherState newState() {
    return _DartAesCtrState(
      cipher: this,
    );
  }

  @override
  DartAesCtr toSync() => this;
}

class _DartAesCtrState extends DartCipherState {
  late Uint32List _preparedKey;

  @override
  final Uint8List block = Uint8List(16);

  @override
  late Uint32List blockAsUint32List = Uint32List.view(block.buffer);

  final Uint8List _internalState = Uint8List(16);

  late final Uint32List _internalStateAsUint32List =
      Uint32List.view(_internalState.buffer);

  Uint32List? _internalStateCopyAsUint32List;

  _DartAesCtrState({
    required super.cipher,
  });

  @override
  void beforeData({
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const [],
  }) {
    final internalState = _internalState;
    internalState.setAll(0, nonce);
    for (var i = nonce.length; i < block.length; i++) {
      internalState[i] = 0;
    }
    _internalStateCopyAsUint32List = Uint32List.fromList(
      _internalStateAsUint32List,
    );
    _preparedKey = aesExpandKeyForEncrypting(secretKey);
  }

  @override
  void setBlock(int blockIndex) {
    final copy = _internalStateCopyAsUint32List!;
    for (var i = 0; i < copy.length; i++) {
      _internalStateAsUint32List[i] = copy[i];
    }

    // Increment nonce.
    bytesIncrementBigEndian(_internalState, blockIndex);

    // Encrypt nonce with AES
    aesEncryptBlock(
      blockAsUint32List,
      0,
      _internalStateAsUint32List,
      0,
      _preparedKey,
    );
    flipUint32ListEndianUnless(blockAsUint32List, Endian.little);
  }
}
