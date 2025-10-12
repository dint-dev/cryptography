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

import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:meta/meta.dart';

/// Superclass for pure Dart implementations of [Cipher].
abstract class DartCipher implements Cipher {
  @override
  DartCipher toSync() => this;
}

/// Base class for [Cipher] implementations written in Dart.
mixin DartCipherMixin implements DartCipher {
  @nonVirtual
  @override
  Future<SecretKey> newSecretKey() async {
    return newSecretKeySync();
  }

  /// Synchronous version of [newSecretKey].
  SecretKey newSecretKeySync() {
    return SecretKeyData.random(
      length: secretKeyLength,
      random: random,
    );
  }
}

/// Base class for stream cipher states that XOR key stream bytes with input
/// bytes.
abstract class DartCipherState extends CipherState {
  /// Default chunk size for [convert] / [convertSync].
  static const int defaultChunkSize = 1024 * 1024;

  static final _emptyUint8List = Uint8List(0);

  @override
  final Cipher cipher;

  /// Whether the state is encrypting.
  ///
  /// If false, the state is decrypting.
  bool _isEncrypting = true;

  late MacSink _macSink;

  bool _isInitialized = false;

  int keyStreamIndex = 0;

  int _blockIndex = -1;

  Mac? _mac;

  DartCipherState({
    required this.cipher,
  });

  Uint8List get block;

  Uint32List get blockAsUint32List;

  @override
  Mac get mac {
    final mac = _mac;
    if (mac == null) {
      throw StateError('convert() has not been called.');
    }
    return mac;
  }

  MacSink get macSink => _macSink;

  /// Called before [close].
  @protected
  List<int> beforeClose() {
    return _emptyUint8List;
  }

  /// Called before data is added.
  @protected
  void beforeData({
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const [],
  });

  @override
  Future<List<int>> convert(
    List<int> input, {
    Uint8List? possibleBuffer,
    Mac? expectedMac,
    int? chunkSize,
  }) async {
    if (!_isInitialized) {
      throw StateError('Not initialized');
    }
    final outputChunks = <List<int>>[];
    chunkSize ??= defaultChunkSize;
    if (chunkSize < 0) {
      //
      // Do not split the input
      //
      final outputChunk = convertChunkSync(
        input,
        possibleBuffer: possibleBuffer,
      );
      outputChunks.add(outputChunk);
    } else {
      //
      // Split the input
      //
      if (chunkSize < 64) {
        throw ArgumentError.value(chunkSize, 'chunkSize');
      }
      if (input is! Uint8List) {
        input = Uint8List.fromList(input);
        possibleBuffer = input;
      }
      for (var i = 0; i < input.length; i += chunkSize) {
        // Pause to avoid blocking the event loop.
        if (i > 0) {
          await Future.delayed(const Duration(milliseconds: 1));
        }
        final thisChunkSize = min(chunkSize, input.length - i);
        final inputChunk = input.buffer.asUint8List(
          input.offsetInBytes + i,
          thisChunkSize,
        );
        final outputChunk = convertChunkSync(
          inputChunk,
          possibleBuffer: possibleBuffer,
        );
        outputChunks.add(outputChunk);
      }
    }
    final suffix = beforeClose();
    if (suffix.isNotEmpty) {
      macSink.add(suffix);
      outputChunks.add(suffix);
    }
    macSink.close();
    final mac = await macSink.mac();
    _mac = mac;
    if (expectedMac != null && mac != expectedMac) {
      throw SecretBoxAuthenticationError();
    }
    return _concatenate(outputChunks);
  }

  @nonVirtual
  @override
  List<int> convertChunkSync(
    List<int> input, {
    Uint8List? possibleBuffer,
  }) {
    if (!_isInitialized) {
      throw StateError('Not initialized');
    }
    if (input.isEmpty) {
      return input;
    }
    final macSink = this.macSink;
    final block = this.block;
    final blockLength = block.length;
    var allowUseSameBytes = identical(input, possibleBuffer);
    if (!allowUseSameBytes) {
      input = Uint8List.fromList(input);
    }

    // If we are decrypting, the input is now the cipher text.
    // So we add it to the sink.
    if (!_isEncrypting) {
      macSink.add(input);
    }

    var keyStreamIndex = this.keyStreamIndex;

    // Compute block if needed
    if (keyStreamIndex % blockLength != 0) {
      final blockIndex = keyStreamIndex ~/ blockLength;
      if (blockIndex != _blockIndex) {
        setBlock(blockIndex);
        _blockIndex = blockIndex;
      }
    }

    for (var i = 0; i < input.length; i++) {
      // First byte of a block?
      final indexInBlock = keyStreamIndex % blockLength;
      if (indexInBlock == 0) {
        final blockIndex = keyStreamIndex ~/ blockLength;
        setBlock(blockIndex);
        _blockIndex = blockIndex;
      }

      // XOR
      input[i] ^= block[indexInBlock];
      keyStreamIndex++;
    }
    this.keyStreamIndex = keyStreamIndex;

    // If we are encrypting, the input is now the cipher text.
    // So we add it to the sink.
    // (If we are decrypting, we added it earlier)
    if (_isEncrypting) {
      macSink.add(input);
    }
    return input;
  }

  List<int> convertSync(
    List<int> input, {
    Uint8List? possibleBuffer,
    Mac? expectedMac,
  }) {
    if (!_isInitialized) {
      throw StateError('Not initialized');
    }
    var output = convertChunkSync(
      input,
      possibleBuffer: possibleBuffer,
    );
    final suffix = beforeClose();
    final macSink = this.macSink as DartMacSinkMixin;
    if (suffix.isNotEmpty) {
      macSink.add(suffix);
      final tmp = Uint8List(output.length + suffix.length);
      tmp.setAll(0, output);
      tmp.setAll(output.length, suffix);
      output = tmp;
    }
    macSink.close();
    final mac = macSink.macSync();
    _mac = mac;
    if (expectedMac != null && mac != expectedMac) {
      throw SecretBoxAuthenticationError();
    }
    return output;
  }

  @protected
  SecretKeyData deriveKeySync({
    required SecretKeyData secretKey,
    required List<int> nonce,
  }) {
    return secretKey;
  }

  @protected
  List<int> deriveNonce({
    required SecretKeyData secretKey,
    required List<int> nonce,
  }) {
    return nonce;
  }

  @override
  Future<void> initialize({
    required bool isEncrypting,
    required SecretKey secretKey,
    required List<int> nonce,
    List<int> aad = const [],
    int keyStreamIndex = 0,
  }) async {
    _isInitialized = false;
    _isEncrypting = isEncrypting;
    this.keyStreamIndex = keyStreamIndex;
    final secretKeyData = await secretKey.extract();
    final derivedSecretKey = deriveKeySync(
      secretKey: secretKeyData,
      nonce: nonce,
    );
    final derivedNonce = deriveNonce(
      secretKey: secretKeyData,
      nonce: nonce,
    );
    final macSink = await cipher.macAlgorithm.newMacSink(
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    _macSink = macSink;
    assert(!_isInitialized);
    _isInitialized = true;
    beforeData(
      secretKey: derivedSecretKey,
      nonce: derivedNonce,
      aad: aad,
    );
  }

  void initializeSync({
    required bool isEncrypting,
    required SecretKey secretKey,
    required List<int> nonce,
    List<int> aad = const [],
    int keyStreamIndex = 0,
  }) {
    _isInitialized = false;
    _isEncrypting = isEncrypting;
    this.keyStreamIndex = keyStreamIndex;
    final secretKeyData = secretKey as SecretKeyData;
    final derivedSecretKey = deriveKeySync(
      secretKey: secretKeyData,
      nonce: nonce,
    );
    final derivedNonce = deriveNonce(
      secretKey: secretKeyData,
      nonce: nonce,
    );
    final macSink = cipher.macAlgorithm.toSync().newMacSinkSync(
          secretKeyData: secretKeyData,
          nonce: nonce,
          aad: aad,
        );
    _macSink = macSink;
    assert(!_isInitialized);
    _isInitialized = true;
    beforeData(
      secretKey: derivedSecretKey,
      nonce: derivedNonce,
      aad: aad,
    );
  }

  /// Fills [block] with a new key stream block.
  @protected
  void setBlock(int blockIndex);

  static List<int> _concatenate(List<List<int>> chunks) {
    if (chunks.isEmpty) {
      return _emptyUint8List;
    }
    if (chunks.length == 1) {
      return chunks.single;
    }
    var length = 0;
    for (var chunk in chunks) {
      length += chunk.length;
    }
    final first = chunks.first;
    if (first is Uint8List) {
      final buffer = first.buffer;
      var previousEnd = first.offsetInBytes + first.length;
      var isContiguous = true;
      for (var i = 1; i < chunks.length; i++) {
        final chunk = chunks[i];
        if (!(chunk is Uint8List &&
            identical(chunk.buffer, buffer) &&
            chunk.offsetInBytes == previousEnd)) {
          isContiguous = false;
          break;
        }
        previousEnd += chunk.length;
      }
      if (isContiguous) {
        return first.buffer.asUint8List(
          first.offsetInBytes,
          length,
        );
      }
    }
    final output = Uint8List(length);
    var i = 0;
    for (var chunk in chunks) {
      output.setAll(i, chunk);
      i += chunk.length;
    }
    return output;
  }
}

mixin DartCipherWithStateMixin implements StreamingCipher {
  /// Length of chunks that are processed in one go.
  ///
  /// When you call [encrypt] or [decrypt], the work is done in chunks.
  int get optimalChunkSize => 1 << 14;

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    int? chunkSize,
    Uint8List? possibleBuffer,
  }) async {
    checkParameters(
      length: secretBox.cipherText.length,
      secretKey: secretKey,
      nonceLength: secretBox.nonce.length,
      aadLength: aad.length,
      keyStreamIndex: keyStreamIndex,
    );
    final state = newState();
    await state.initialize(
      isEncrypting: false,
      secretKey: secretKey,
      nonce: secretBox.nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    final clearText = await state.convert(
      secretBox.cipherText,
      expectedMac: secretBox.mac,
      possibleBuffer: possibleBuffer,
      chunkSize: chunkSize,
    );
    if (secretBox.mac != state.mac) {
      throw SecretBoxAuthenticationError();
    }
    return clearText;
  }

  List<int> decryptSync(
    SecretBox secretBox, {
    required SecretKeyData secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) {
    checkParameters(
      length: secretBox.cipherText.length,
      secretKey: secretKey,
      nonceLength: secretBox.nonce.length,
      aadLength: aad.length,
      keyStreamIndex: keyStreamIndex,
    );
    final state = newState();
    state.initializeSync(
      isEncrypting: false,
      secretKey: secretKey,
      nonce: secretBox.nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    final clearText = state.convertSync(
      secretBox.cipherText,
      possibleBuffer: possibleBuffer,
    );
    if (secretBox.mac != state.mac) {
      throw SecretBoxAuthenticationError();
    }
    return clearText;
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    int? chunkSize,
    Uint8List? possibleBuffer,
  }) async {
    nonce ??= newNonce();
    checkParameters(
      length: clearText.length,
      secretKey: secretKey,
      nonceLength: nonce.length,
      aadLength: aad.length,
      keyStreamIndex: keyStreamIndex,
    );
    final state = newState();
    await state.initialize(
      isEncrypting: true,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    final cipherText = await state.convert(
      clearText,
      possibleBuffer: possibleBuffer,
      chunkSize: chunkSize,
    );
    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: state.mac,
    );
  }

  SecretBox encryptSync(
    List<int> clearText, {
    required SecretKeyData secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) {
    nonce ??= newNonce();
    checkParameters(
      length: clearText.length,
      secretKey: secretKey,
      nonceLength: nonce.length,
      aadLength: aad.length,
      keyStreamIndex: keyStreamIndex,
    );
    final state = newState();
    state.initializeSync(
      isEncrypting: true,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    final cipherText = state.convertSync(
      clearText,
      possibleBuffer: possibleBuffer,
    );
    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: state.mac,
    );
  }

  @override
  DartCipherState newState();
}

/// Base class for [StreamingCipher] implementations written in Dart.
mixin DartStreamingCipherMixin implements StreamingCipher, DartCipher {
  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) async {
    final secretKeyData = await secretKey.extract();
    return decryptSync(
      secretBox,
      secretKey: secretKeyData,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  /// Synchronous version of [decrypt].
  List<int> decryptSync(
    SecretBox secretBox, {
    required SecretKeyData secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  });

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  }) async {
    final secretKeyData = await secretKey.extract();
    return encryptSync(
      clearText,
      secretKey: secretKeyData,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  /// Synchronous version of [encrypt].
  SecretBox encryptSync(
    List<int> clearText, {
    required SecretKeyData secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  });

  @nonVirtual
  @override
  Future<SecretKey> newSecretKey() async {
    return newSecretKeySync();
  }

  /// Synchronous version of [newSecretKey].
  SecretKey newSecretKeySync() {
    return SecretKeyData.random(
      length: secretKeyLength,
      random: random,
    );
  }
}
