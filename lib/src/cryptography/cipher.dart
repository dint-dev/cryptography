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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

/// Superclass for symmetric ciphers.
///
/// Examples:
///   * [aesGcm]
///   * [chacha20]
abstract class Cipher {
  const Cipher();
  String get name;
  int get nonceLength => 0;

  SecretKeyGenerator get secretKeyGenerator;

  /// Decrypts a message.
  Future<Uint8List> decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    int offset = 0,
  }) {
    return Future<Uint8List>(
      () => decryptSync(
        input,
        secretKey: secretKey,
        offset: offset,
        nonce: nonce,
      ),
    );
  }

  /// Decrypts a message.
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    int offset = 0,
  });

  /// Encrypts a message.
  Future<Uint8List> encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    int offset = 0,
  }) {
    return Future<Uint8List>(
      () => encryptSync(
        input,
        secretKey: secretKey,
        offset: offset,
        nonce: nonce,
      ),
    );
  }

  /// Encrypts a message.
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    int offset = 0,
  });

  Nonce newNonce() {
    final nonceLength = this.nonceLength;
    if (nonceLength == null) {
      return null;
    }
    return Nonce.randomBytes(nonceLength);
  }

  Future<SecretKey> newSecretKey() => secretKeyGenerator.generate();

  SecretKey newSecretKeySync() => secretKeyGenerator.generateSync();
}

/// Superclass for key stream ciphers.
abstract class SyncKeyStreamCipher extends Cipher {
  const SyncKeyStreamCipher();

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    int offset = 0,
  }) {
    final state = newState(
      secretKey: secretKey,
      keyStreamIndex: offset,
      nonce: nonce,
    );
    return state.convert(input);
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    int offset = 0,
  }) {
    final state = newState(
      secretKey: secretKey,
      keyStreamIndex: offset,
      nonce: nonce,
    );
    return state.convert(input);
  }

  SyncKeyStreamCipherState newState({
    @required SecretKey secretKey,
    @required Nonce nonce,
    int keyStreamIndex,
  });

  static void checkNewStateArguments(SyncKeyStreamCipher cipher,
      {@required SecretKey secretKey,
      @required int keyStreamIndex,
      Nonce nonce}) {
    ArgumentError.checkNotNull(secretKey, 'secretKey');
    ArgumentError.checkNotNull(keyStreamIndex, 'offset');

    if (!cipher.secretKeyGenerator.isValidLength(secretKey.bytes.length)) {
      throw ArgumentError(
        'Secret key length ${secretKey.bytes.length} is invalid',
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

/// Constructed by [SyncKeyStreamCipher].
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
    fillWithConverted(result, 0, input, 0);
    return result;
  }

  /// Fills the list with converted bytes.
  ///
  /// Throws [StateError] if [initialize] has not been invoked or [deleteAll] has
  /// been invoked.
  void fillWithConverted(
      List<int> result, int resultStart, List<int> input, int inputStart,
      {int length}) {
    if (length == null) {
      length = result.length - resultStart;
      final inputLength = input.length - inputStart;
      if (inputLength < length) {
        length = inputLength;
      }
    }

    // Fill result with key stream
    fillWithKeyStream(result, resultStart, length: length);

    // XOR
    for (var i = 0; i < length; i++) {
      result[resultStart + i] ^= input[inputStart + i];
    }
  }

  /// Fills the list with key stream bytes.
  ///
  /// Throws [StateError] if [initialize] has not been invoked or [deleteAll] has
  /// been invoked.
  void fillWithKeyStream(List<int> result, int start, {int length});

  static void checkNotClosed(SyncKeyStreamCipherState state) {
    if (state.isClosed) {
      throw StateError('Cipher state is closed');
    }
  }
}
