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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

abstract class Cipher {
  const Cipher();

  String get name;

  int get nonceLength => null;

  int get secretKeyLength;

  /// Decrypts a message.
  Uint8List decrypt(
    List<int> input,
    SecretKey secretKey, {
    int offset = 0,
    SecretKey nonce,
  });

  /// Encrypts a message.
  Uint8List encrypt(
    List<int> input,
    SecretKey secretKey, {
    int offset = 0,
    SecretKey nonce,
  });

  SecretKey newNonce() {
    final nonceLength = this.nonceLength;
    if (nonceLength == null) {
      return null;
    }
    return SecretKey.randomBytes(nonceLength);
  }

  SecretKey newSecretKey() => SecretKey.randomBytes(secretKeyLength);
}

/// Superclass for key stream ciphers.
abstract class KeyStreamCipher extends Cipher {
  const KeyStreamCipher();

  static void checkNewStateArguments(
      KeyStreamCipher cipher, SecretKey secretKey,
      {@required int keyStreamIndex, SecretKey nonce}) {
    ArgumentError.checkNotNull(secretKey, "secretKey");
    ArgumentError.checkNotNull(keyStreamIndex, "offset");
    final expectedSecretKeyLength = cipher.secretKeyLength;
    final secretKeyLength = secretKey.bytes.length;
    if (secretKeyLength != expectedSecretKeyLength) {
      throw ArgumentError.value(
        secretKey,
        "secretKey",
        "Secret key length is $secretKeyLength, should be $expectedSecretKeyLength",
      );
    }

    final expectedNonceLength = cipher.nonceLength;
    if (expectedNonceLength == null) {
      if (nonce != null) {
        throw ArgumentError.value(nonce, "nonce");
      }
    } else {
      ArgumentError.checkNotNull(nonce, "nonce");
      final nonceLength = nonce.bytes.length;
      if (nonceLength != expectedNonceLength) {
        throw ArgumentError.value(
          nonce,
          "nonce",
          "Secret key length is $nonceLength, should be $expectedNonceLength",
        );
      }
    }
  }

  @override
  Uint8List decrypt(List<int> input, SecretKey secretKey,
      {int offset = 0, SecretKey nonce}) {
    final state = newState(secretKey, keyStreamIndex: offset, nonce: nonce);
    return state.convert(input);
  }

  @override
  Uint8List encrypt(List<int> input, SecretKey secretKey,
      {int offset = 0, SecretKey nonce}) {
    final state = newState(secretKey, keyStreamIndex: offset, nonce: nonce);
    return state.convert(input);
  }

  KeyStreamCipherState newState(SecretKey secretKey,
      {int keyStreamIndex, SecretKey nonce});
}

/// Constructed by [KeyStreamCipher].
abstract class KeyStreamCipherState extends Converter<List<int>, Uint8List> {
  int keyStreamIndex;

  bool _isClosed = false;

  KeyStreamCipherState({@required this.keyStreamIndex});

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

  static void checkNotClosed(KeyStreamCipherState state) {
    if (state.isClosed) {
      throw StateError("Cipher state is closed");
    }
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
}
