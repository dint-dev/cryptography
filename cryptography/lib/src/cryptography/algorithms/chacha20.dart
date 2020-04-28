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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:meta/meta.dart';

/// _ChaCha20_ cipher ([RFC 7539](https://tools.ietf.org/html/rfc7539)).
///
/// About the algorithm:
///   * You must give 32 byte long `secretKey`.
///   * You must give 12 byte long `nonce`. You must never use the same (key,
///     nonce) combination twice.
///   * The cipher is NOT authenticated. Consider using [chacha20Poly1305Aead].
///
/// You can pass ChaCha20_ block counter value with `keyStreamIndex` (index
/// 0..63 --> counter 0, index 64..128 --> block counter 1, etc.).
///
/// When using ChaCha20, you must not use the same key/nonce combination twice.
/// The message is not authenticated.
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = chacha20;
///
///   // Generate a random 256-bit secret key
///   final secretKey = await algorithm.newSecretKey();
///
///   // Generate a random 96-bit nonce.
///   final nonce = algorithm.newNonce();
///
///   // Encrypt
///   final encrypted = await algorithm.encrypt(
///     [1, 2, 3],
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decrypted = await algorithm.decrypt(
///     encrypted,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher chacha20 = _Chacha20._();

/// XChaCha20 cipher ([draft-irtf-cfrg-xchacha](https://tools.ietf.org/html/draft-arciszewski-xchacha-03)).
///
/// XChaCha20 uses 192-bit nonces whereas ChaCha20 uses 96-bit nonces.
///
/// About the algorithm:
///   * You must give 32 byte long `secretKey`.
///   * You must give 12 byte long `nonce`. You must never use the same (key,
///     nonce) combination twice.
///   * The cipher is NOT authenticated. Consider using [xchacha20Poly1305Aead].
const Cipher xchacha20 = _XChaCha20();

/// _HChaCha20_ ([draft-irtf-cfrg-xchacha](https://tools.ietf.org/html/draft-arciszewski-xchacha-03))
/// key derivation algorithm, which produces a 256-bit secret key from 256-bit
/// secret key and 96-bit nonce.
@visibleForTesting
class HChacha20 {
  const HChacha20();

  SecretKey deriveKeySync({
    @required SecretKey secretKey,
    @required Nonce nonce,
  }) {
    final secretKeyBytes = secretKey.extractSync();
    if (secretKeyBytes.length != 32) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Must be 32 bytes',
      );
    }
    if (nonce.bytes.length != 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be 16 bytes',
      );
    }
    final nonceBytes = Uint8List.fromList(nonce.bytes);
    final nonceByteData = ByteData.view(nonceBytes.buffer);

    // Initialize state
    final stateInitializer = _Chacha20State(const _Chacha20._());
    stateInitializer._initialize(
      key: secretKeyBytes,
      nonce: Uint8List.view(nonceBytes.buffer, 4, 12),
      keyStreamIndex: 64 * nonceByteData.getUint32(0, Endian.little),
    );

    // Get state
    final state = stateInitializer.initialState;

    // -------------------------------------------------------------------------
    // Step 1: Initialize
    // -------------------------------------------------------------------------
    var v0 = state[0],
        v1 = state[1],
        v2 = state[2],
        v3 = state[3],
        v4 = state[4],
        v5 = state[5],
        v6 = state[6],
        v7 = state[7],
        v8 = state[8],
        v9 = state[9],
        v10 = state[10],
        v11 = state[11],
        v12 = state[12],
        v13 = state[13],
        v14 = state[14],
        v15 = state[15];

    // -------------------------------------------------------------------------
    // Step 2: Do 20 column/diagonal rounds
    //
    // We inlined the 'quarterRound' function because benchmarks showed
    // significant enough difference to non-inlined version.
    // -------------------------------------------------------------------------
    for (var i = 0; i < 10; i++) {
      // -------
      // Columns
      // -------
      v0 = uint32mask & (v0 + v4);
      v12 = rotateLeft32(v12 ^ v0, 16);
      v8 = uint32mask & (v8 + v12);
      v4 = rotateLeft32(v4 ^ v8, 12);
      v0 = uint32mask & (v0 + v4);
      v12 = rotateLeft32(v12 ^ v0, 8);
      v8 = uint32mask & (v8 + v12);
      v4 = rotateLeft32(v4 ^ v8, 7);

      v1 = uint32mask & (v1 + v5);
      v13 = rotateLeft32(v13 ^ v1, 16);
      v9 = uint32mask & (v9 + v13);
      v5 = rotateLeft32(v5 ^ v9, 12);
      v1 = uint32mask & (v1 + v5);
      v13 = rotateLeft32(v13 ^ v1, 8);
      v9 = uint32mask & (v9 + v13);
      v5 = rotateLeft32(v5 ^ v9, 7);

      v2 = uint32mask & (v2 + v6);
      v14 = rotateLeft32(v14 ^ v2, 16);
      v10 = uint32mask & (v10 + v14);
      v6 = rotateLeft32(v6 ^ v10, 12);
      v2 = uint32mask & (v2 + v6);
      v14 = rotateLeft32(v14 ^ v2, 8);
      v10 = uint32mask & (v10 + v14);
      v6 = rotateLeft32(v6 ^ v10, 7);

      v3 = uint32mask & (v3 + v7);
      v15 = rotateLeft32(v15 ^ v3, 16);
      v11 = uint32mask & (v11 + v15);
      v7 = rotateLeft32(v7 ^ v11, 12);
      v3 = uint32mask & (v3 + v7);
      v15 = rotateLeft32(v15 ^ v3, 8);
      v11 = uint32mask & (v11 + v15);
      v7 = rotateLeft32(v7 ^ v11, 7);

      // ---------
      // Diagonals
      // ---------
      v0 = uint32mask & (v0 + v5);
      v15 = rotateLeft32(v15 ^ v0, 16);
      v10 = uint32mask & (v10 + v15);
      v5 = rotateLeft32(v5 ^ v10, 12);
      v0 = uint32mask & (v0 + v5);
      v15 = rotateLeft32(v15 ^ v0, 8);
      v10 = uint32mask & (v10 + v15);
      v5 = rotateLeft32(v5 ^ v10, 7);

      v1 = uint32mask & (v1 + v6);
      v12 = rotateLeft32(v12 ^ v1, 16);
      v11 = uint32mask & (v11 + v12);
      v6 = rotateLeft32(v6 ^ v11, 12);
      v1 = uint32mask & (v1 + v6);
      v12 = rotateLeft32(v12 ^ v1, 8);
      v11 = uint32mask & (v11 + v12);
      v6 = rotateLeft32(v6 ^ v11, 7);

      v2 = uint32mask & (v2 + v7);
      v13 = rotateLeft32(v13 ^ v2, 16);
      v8 = uint32mask & (v8 + v13);
      v7 = rotateLeft32(v7 ^ v8, 12);
      v2 = uint32mask & (v2 + v7);
      v13 = rotateLeft32(v13 ^ v2, 8);
      v8 = uint32mask & (v8 + v13);
      v7 = rotateLeft32(v7 ^ v8, 7);

      v3 = uint32mask & (v3 + v4);
      v14 = rotateLeft32(v14 ^ v3, 16);
      v9 = uint32mask & (v9 + v14);
      v4 = rotateLeft32(v4 ^ v9, 12);
      v3 = uint32mask & (v3 + v4);
      v14 = rotateLeft32(v14 ^ v3, 8);
      v9 = uint32mask & (v9 + v14);
      v4 = rotateLeft32(v4 ^ v9, 7);
    }

    // First 128 bits
    state[0] = v0;
    state[1] = v1;
    state[2] = v2;
    state[3] = v3;

    // Last 128 bits
    state[4] = v12;
    state[5] = v13;
    state[6] = v14;
    state[7] = v15;

    // Change endian
    if (Endian.host != Endian.little) {
      final stateByteData = ByteData.view(state.buffer);
      for (var i = 0; i < 32; i += 4) {
        stateByteData.setUint32(
          i,
          stateByteData.getUint32(i, Endian.host),
          Endian.little,
        );
      }
    }

    return SecretKey(Uint8List.view(
      state.buffer,
      state.offsetInBytes,
      32,
    ));
  }
}

/// Constructed by [_SyncKeyStreamCipher].
abstract class SyncKeyStreamCipherState
    extends Converter<List<int>, Uint8List> {
  int keyStreamIndex;

  bool _isClosed = false;

  SyncKeyStreamCipherState({@required this.keyStreamIndex});

  bool get isClosed => _isClosed;

  @mustCallSuper
  void close() {
    _isClosed = true;
  }

  @override
  Uint8List convert(List<int> input) {
    final result = Uint8List(input.length);
    fillWithConverted(
      output: result,
      outputStart: 0,
      input: input,
      inputStart: 0,
    );
    return result;
  }

  /// Fills the list with converted bytes.
  ///
  /// Throws [StateError] if [_initialize] has not been invoked or [deleteAll] has
  /// been invoked.
  void fillWithConverted({
    @required List<int> output,
    int outputStart = 0,
    @required List<int> input,
    int inputStart = 0,
    int length,
  }) {
    if (length == null) {
      length = output.length - outputStart;
      final inputLength = input.length - inputStart;
      if (inputLength < length) {
        length = inputLength;
      }
    }

    // Fill result with key stream
    fillWithKeyStream(output, start: outputStart, length: length);

    // XOR
    for (var i = 0; i < length; i++) {
      output[outputStart + i] ^= input[inputStart + i];
    }
  }

  /// Fills the list with key stream bytes.
  ///
  /// Throws [StateError] if [_initialize] has not been invoked or [deleteAll] has
  /// been invoked.
  void fillWithKeyStream(List<int> result, {int start = 0, int length});

  static void checkNotClosed(SyncKeyStreamCipherState state) {
    if (state.isClosed) {
      throw StateError('Cipher state is closed');
    }
  }
}

class _Chacha20 extends _SyncKeyStreamCipher {
  const _Chacha20._();

  @override
  String get name => 'chacha20';

  @override
  int get nonceLength => 12;

  @override
  int get secretKeyLength => 32;

  @override
  Set<int> get secretKeyValidLengths => const {32};

  @override
  SyncKeyStreamCipherState newState({
    @required SecretKey secretKey,
    @required Nonce nonce,
    int keyStreamIndex = 0,
  }) {
    _SyncKeyStreamCipher.checkNewStateArguments(
      this,
      secretKey: secretKey,
      keyStreamIndex: keyStreamIndex,
      nonce: nonce,
    );
    final state = _Chacha20State(this);
    state._initialize(
      key: secretKey.extractSync(),
      nonce: nonce.bytes,
      keyStreamIndex: keyStreamIndex,
    );
    return state;
  }

  void _encryptState(Uint32List state, Uint32List initialState) {
    // Validate that we have a proper initial state.
    _validateInitialState(initialState);

    // -------------------------------------------------------------------------
    // Step 1: Initialize
    // -------------------------------------------------------------------------
    var v0 = initialState[0],
        v1 = initialState[1],
        v2 = initialState[2],
        v3 = initialState[3],
        v4 = initialState[4],
        v5 = initialState[5],
        v6 = initialState[6],
        v7 = initialState[7],
        v8 = initialState[8],
        v9 = initialState[9],
        v10 = initialState[10],
        v11 = initialState[11],
        v12 = initialState[12],
        v13 = initialState[13],
        v14 = initialState[14],
        v15 = initialState[15];

    // -------------------------------------------------------------------------
    // Step 2: Do 20 column/diagonal rounds
    //
    // We inlined the 'quarterRound' function because benchmarks showed
    // significant enough difference to non-inlined version.
    // -------------------------------------------------------------------------
    for (var i = 0; i < 10; i++) {
      // -------
      // Columns
      // -------
      v0 = uint32mask & (v0 + v4);
      v12 = rotateLeft32(v12 ^ v0, 16);
      v8 = uint32mask & (v8 + v12);
      v4 = rotateLeft32(v4 ^ v8, 12);
      v0 = uint32mask & (v0 + v4);
      v12 = rotateLeft32(v12 ^ v0, 8);
      v8 = uint32mask & (v8 + v12);
      v4 = rotateLeft32(v4 ^ v8, 7);

      v1 = uint32mask & (v1 + v5);
      v13 = rotateLeft32(v13 ^ v1, 16);
      v9 = uint32mask & (v9 + v13);
      v5 = rotateLeft32(v5 ^ v9, 12);
      v1 = uint32mask & (v1 + v5);
      v13 = rotateLeft32(v13 ^ v1, 8);
      v9 = uint32mask & (v9 + v13);
      v5 = rotateLeft32(v5 ^ v9, 7);

      v2 = uint32mask & (v2 + v6);
      v14 = rotateLeft32(v14 ^ v2, 16);
      v10 = uint32mask & (v10 + v14);
      v6 = rotateLeft32(v6 ^ v10, 12);
      v2 = uint32mask & (v2 + v6);
      v14 = rotateLeft32(v14 ^ v2, 8);
      v10 = uint32mask & (v10 + v14);
      v6 = rotateLeft32(v6 ^ v10, 7);

      v3 = uint32mask & (v3 + v7);
      v15 = rotateLeft32(v15 ^ v3, 16);
      v11 = uint32mask & (v11 + v15);
      v7 = rotateLeft32(v7 ^ v11, 12);
      v3 = uint32mask & (v3 + v7);
      v15 = rotateLeft32(v15 ^ v3, 8);
      v11 = uint32mask & (v11 + v15);
      v7 = rotateLeft32(v7 ^ v11, 7);

      // ---------
      // Diagonals
      // ---------
      v0 = uint32mask & (v0 + v5);
      v15 = rotateLeft32(v15 ^ v0, 16);
      v10 = uint32mask & (v10 + v15);
      v5 = rotateLeft32(v5 ^ v10, 12);
      v0 = uint32mask & (v0 + v5);
      v15 = rotateLeft32(v15 ^ v0, 8);
      v10 = uint32mask & (v10 + v15);
      v5 = rotateLeft32(v5 ^ v10, 7);

      v1 = uint32mask & (v1 + v6);
      v12 = rotateLeft32(v12 ^ v1, 16);
      v11 = uint32mask & (v11 + v12);
      v6 = rotateLeft32(v6 ^ v11, 12);
      v1 = uint32mask & (v1 + v6);
      v12 = rotateLeft32(v12 ^ v1, 8);
      v11 = uint32mask & (v11 + v12);
      v6 = rotateLeft32(v6 ^ v11, 7);

      v2 = uint32mask & (v2 + v7);
      v13 = rotateLeft32(v13 ^ v2, 16);
      v8 = uint32mask & (v8 + v13);
      v7 = rotateLeft32(v7 ^ v8, 12);
      v2 = uint32mask & (v2 + v7);
      v13 = rotateLeft32(v13 ^ v2, 8);
      v8 = uint32mask & (v8 + v13);
      v7 = rotateLeft32(v7 ^ v8, 7);

      v3 = uint32mask & (v3 + v4);
      v14 = rotateLeft32(v14 ^ v3, 16);
      v9 = uint32mask & (v9 + v14);
      v4 = rotateLeft32(v4 ^ v9, 12);
      v3 = uint32mask & (v3 + v4);
      v14 = rotateLeft32(v14 ^ v3, 8);
      v9 = uint32mask & (v9 + v14);
      v4 = rotateLeft32(v4 ^ v9, 7);
    }

    // -------------------------------------------------------------------------
    // Step 3: Addition
    // -------------------------------------------------------------------------
    state[0] = uint32mask & (v0 + initialState[0]);
    state[1] = uint32mask & (v1 + initialState[1]);
    state[2] = uint32mask & (v2 + initialState[2]);
    state[3] = uint32mask & (v3 + initialState[3]);
    state[4] = uint32mask & (v4 + initialState[4]);
    state[5] = uint32mask & (v5 + initialState[5]);
    state[6] = uint32mask & (v6 + initialState[6]);
    state[7] = uint32mask & (v7 + initialState[7]);
    state[8] = uint32mask & (v8 + initialState[8]);
    state[9] = uint32mask & (v9 + initialState[9]);
    state[10] = uint32mask & (v10 + initialState[10]);
    state[11] = uint32mask & (v11 + initialState[11]);
    state[12] = uint32mask & (v12 + initialState[12]);
    state[13] = uint32mask & (v13 + initialState[13]);
    state[14] = uint32mask & (v14 + initialState[14]);
    state[15] = uint32mask & (v15 + initialState[15]);
  }

  void _validateInitialState(Uint32List initialState) {
    if (initialState[0] != 0x61707865) {
      throw Error();
    }
  }
}

class _Chacha20State extends SyncKeyStreamCipherState {
  static const int _keyLengthInBytes = 32;
  static const int _nonceLengthInBytes = 12;
  static const int _stateLength = 16;

  // ---------------------------------------------------------------------------
  // Static buffers.
  //
  // They are cleared after every operation so sensitive data
  // will not remain in the heap.
  // ---------------------------------------------------------------------------
  static final Uint32List _state = Uint32List(_stateLength);
  static final ByteData _stateByteData = ByteData.view(
    _state.buffer,
    _state.offsetInBytes,
    _state.lengthInBytes,
  );

  final _Chacha20 _chacha;

  final Uint32List initialState = Uint32List(_stateLength);

  int _keyStreamIndex = 0;

  _Chacha20State(this._chacha);

  @override
  int get keyStreamIndex => _keyStreamIndex;

  @override
  set keyStreamIndex(int value) {
    if (value < 0) {
      throw ArgumentError.value(value);
    }
    _keyStreamIndex = value;
    initialState[12] = value ~/ 64;
  }

  @override
  void close() {
    initialState.fillRange(0, initialState.length, 0);
    super.close();
  }

  @override
  void fillWithKeyStream(List<int> result, {int start = 0, int length}) {
    SyncKeyStreamCipherState.checkNotClosed(this);
    if (start < 0) {
      throw ArgumentError.value(start, 'start');
    }
    if (length == null) {
      length = result.length - start;
    } else if (length < 0 || length > result.length - start) {
      throw ArgumentError.value(length, 'length');
    }
    _chacha._validateInitialState(initialState);

    // ----------------------------
    // Special case for empty lists
    // ----------------------------
    if (length == 0) {
      return;
    }

    // -----------------
    // Declare variables
    // -----------------
    final state = _state;
    final stateByteData = _stateByteData;
    var keyStreamIndex = this.keyStreamIndex;

    // -----------------------------
    // Prepare for optimized copying
    // -----------------------------
    // For key streams over 256 bytes:
    // Whole blocks will be copied using 16 uint32 assignments
    // (including host endian to little endian conversion).
    //
    // Benchmarks indicated this has a surprisingly high (>30%) impact
    // on converting long streams.
    //
    // Minimum length 256 bytes is just a guess of a good value.
    ByteData resultByteData;
    if (length > 256 && keyStreamIndex % 64 == 0 && result is Uint8List) {
      resultByteData = ByteData.view(
        result.buffer,
        result.offsetInBytes,
        result.lengthInBytes,
      );
    }

    try {
      // -----------------------------------------------------------------------
      // For each byte
      // -----------------------------------------------------------------------
      while (length > 0) {
        // Encrypt state
        _chacha._encryptState(state, initialState);

        // Should we copy
        if (resultByteData != null && length >= 64) {
          // ---------------------------------
          // Optimized method for whole blocks
          // ---------------------------------

          // Copy whole block using 16 uint32 assignments
          for (var i = 0; i < 16; i++) {
            resultByteData.setUint32(start, state[i], Endian.little);
            start += 4;
          }

          // Increment variables
          keyStreamIndex += 64;
          length -= 64;
        } else {
          // -------------------
          // Byte-by-byte method
          // -------------------

          // Convert state:
          // Host endian --> little endian
          for (var i = 0; i < state.length; i++) {
            stateByteData.setUint32(4 * i, state[i], Endian.little);
          }

          // Do uint8 assignments
          for (var i = keyStreamIndex % 64; i < 64 && length > 0; i++) {
            result[start] = stateByteData.getUint8(i);

            // Increment key stream index
            keyStreamIndex++;
            length--;
            start++;
          }
        }

        // Store current 'keyStreamIndex'
        this.keyStreamIndex = keyStreamIndex;
      }
    } finally {
      // Clear static state buffer.
      // This is not strictly necessary, but it's good for data protection.
      for (var i = 0; i < state.length; i++) {
        state[i] = 0;
      }
    }
  }

  void _initialize({
    @required List<int> key,
    @required List<int> nonce,
    int keyStreamIndex = 0,
  }) {
    if (key == null) {
      throw ArgumentError.notNull('key');
    } else if (key.length != _keyLengthInBytes) {
      throw ArgumentError.value(
        key,
        'key',
        'Must ${_keyLengthInBytes} bytes',
      );
    }
    if (nonce != null && nonce.length != _nonceLengthInBytes) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be ${_nonceLengthInBytes} bytes',
      );
    }

    // Mark as uninitialized so encryption will fail if this method throws.
    final state = initialState;
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    final stateByteData = ByteData.view(
      state.buffer,
      state.offsetInBytes,
      state.lengthInBytes,
    );

    //
    // Key
    //
    var stateBytesIndex = 4 * 4;
    for (var i = 0; i < key.length; i++) {
      stateByteData.setUint8(stateBytesIndex, key[i]);
      stateBytesIndex++;
    }
    // Convert little endian --> host endian
    for (var i = 4; i < 12; i++) {
      state[i] = stateByteData.getUint32(4 * i, Endian.little);
    }

    //
    // Counter
    //
    this.keyStreamIndex = keyStreamIndex;

    //
    // Nonce
    //
    if (nonce == null) {
      for (var i = 13; i < 16; i++) {
        initialState[i] = 0;
      }
    } else {
      stateBytesIndex = 13 * 4;
      for (var i = 0; i < nonce.length; i++) {
        stateByteData.setUint8(stateBytesIndex, nonce[i]);
        stateBytesIndex++;
      }
      // Convert little endian --> host endian
      for (var i = 13; i < 16; i++) {
        state[i] = stateByteData.getUint32(4 * i, Endian.little);
      }
    }
  }
}

/// Superclass for key stream ciphers.
abstract class _SyncKeyStreamCipher extends Cipher {
  const _SyncKeyStreamCipher();

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (aad != null) {
      throw ArgumentError.value(aad, 'aad');
    }
    final state = newState(
      secretKey: secretKey,
      nonce: nonce,
      keyStreamIndex: keyStreamIndex,
    );
    return state.convert(input);
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (aad != null) {
      throw ArgumentError.value(aad, 'aad');
    }
    final state = newState(
      secretKey: secretKey,
      nonce: nonce,
      keyStreamIndex: keyStreamIndex,
    );
    return state.convert(input);
  }

  SyncKeyStreamCipherState newState({
    @required SecretKey secretKey,
    @required Nonce nonce,
    int keyStreamIndex,
  });

  static void checkNewStateArguments(_SyncKeyStreamCipher cipher,
      {@required SecretKey secretKey,
      @required int keyStreamIndex,
      Nonce nonce}) {
    ArgumentError.checkNotNull(secretKey, 'secretKey');
    ArgumentError.checkNotNull(keyStreamIndex, 'offset');

    final secretKeyBytes = secretKey.extractSync();
    if (!cipher.isSecretKeyLengthInBytesValid(secretKeyBytes.length)) {
      throw ArgumentError(
        'Secret key length ${secretKeyBytes.length} is invalid',
      );
    }

    final expectedNonceLength = cipher.nonceLength;
    if (expectedNonceLength == null) {
      if (nonce != null) {
        throw ArgumentError.value(nonce, 'nonce');
      }
    } else {
      ArgumentError.checkNotNull(nonce, 'nonce');
      final nonceLength = nonce.bytes.length;
      if (nonceLength != expectedNonceLength) {
        throw ArgumentError(
          'Nonce length is $nonceLength is invalid: should be $expectedNonceLength',
        );
      }
    }
  }
}

class _XChaCha20 extends Cipher {
  const _XChaCha20();

  @override
  String get name => 'xchacha20';

  @override
  int get nonceLength => 24;

  @override
  int get secretKeyLength => 32;

  @override
  Set<int> get secretKeyValidLengths => <int>{32};

  @override
  List<int> decryptSync(List<int> input,
      {SecretKey secretKey,
      Nonce nonce,
      List<int> aad,
      int keyStreamIndex = 0}) {
    if (nonce.bytes.length != 24) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be 24 bytes',
      );
    }
    final oldNonceBytes = Uint8List.fromList(nonce.bytes);

    // Create a new secret key with hchacha20.
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

    // Decrypt with chacha20
    return chacha20.decryptSync(
      input,
      secretKey: newSecretKey,
      nonce: Nonce(newNonceBytes),
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  List<int> encryptSync(List<int> input,
      {SecretKey secretKey,
      Nonce nonce,
      List<int> aad,
      int keyStreamIndex = 0}) {
    // Check that nonce is 24 bytes.
    if (nonce.bytes.length != 24) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must be 24 bytes',
      );
    }
    final oldNonceBytes = Uint8List.fromList(nonce.bytes);

    // Create a new secret key with hchacha20.
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

    // Encrypt with chacha20
    return chacha20.encryptSync(
      input,
      secretKey: newSecretKey,
      nonce: Nonce(newNonceBytes),
      keyStreamIndex: keyStreamIndex,
    );
  }
}
