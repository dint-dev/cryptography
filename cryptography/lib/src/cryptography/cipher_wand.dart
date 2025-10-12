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

import 'dart:convert';
import 'dart:typed_data';

import '../../cryptography_plus.dart';

/// An opaque object that possesses some non-extractable secret key.
///
/// It support [encrypt] and/or [decrypt].
///
/// ## Example
/// In this example, we use [Chacha20.poly1305Aead]:
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final cipher = Chacha20.poly1305Aead();
///   final secretKey = await cipher.newSecretKey();
///   final wand = await cipher.newCipherWandFromSecretKey(secretKey);
///
///   // Encrypt
///   final secretBox = await wand.encrypt([1,2,3]);
///
///   print('Nonce: ${secretBox.nonce}');
///   print('Cipher text: ${secretBox.cipherText}');
///   print('MAC: ${secretBox.mac.bytes}');
///
///   // Decrypt
///   final clearText = await wand.decrypt(secretBox);
///   print('Clear text: $clearText');
/// }
/// ```
abstract class CipherWand extends Wand {
  /// Constructor for subclasses.
  CipherWand.constructor();

  /// Decrypts a [SecretBox] and returns the clear text.
  ///
  /// See [Cipher.decrypt] for more information.
  ///
  /// ## Example
  /// In this example, we use [Chacha20.poly1305Aead]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final cipher = Chacha20.poly1305Aead();
  ///   final secretKey = await cipher.newSecretKey();
  ///   final wand = await cipher.newCipherWandFromSecretKey(secretKey);
  ///
  ///   // Encrypt
  ///   final secretBox = await wand.encrypt([1,2,3]);
  ///
  ///   print('Nonce: ${secretBox.nonce}');
  ///   print('Cipher text: ${secretBox.cipherText}');
  ///   print('MAC: ${secretBox.mac.bytes}');
  ///
  ///   // Decrypt
  ///   final clearText = await wand.decrypt(secretBox);
  ///   print('Clear text: $clearText');
  /// }
  /// ```
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  });

  /// Decrypts a string.
  ///
  /// The decrypted bytes are converted to string using [utf8] codec.
  ///
  /// ## Example
  /// In this example, we use [Chacha20.poly1305Aead]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final cipher = Chacha20.poly1305Aead();
  ///   final secretKey = await cipher.newSecretKey();
  ///   final wand = await cipher.newCipherWandFromSecretKey(secretKey);
  ///
  ///   // Encrypt
  ///   final secretBox = await wand.encryptString('Hello, world!');
  ///   print('Nonce: ${secretBox.nonce}');
  ///   print('Cipher text: ${secretBox.cipherText}');
  ///   print('MAC: ${secretBox.mac.bytes}');
  ///
  ///   // Decrypt
  ///   final clearText = await wand.decryptString(secretBox);
  ///   print('Clear text: $clearText');
  /// }
  /// ```
  Future<String> decryptString(SecretBox secretBox) async {
    final clearText = await decrypt(secretBox);
    try {
      return utf8.decode(clearText);
    } finally {
      try {
        // Cut the amount of possibly sensitive data in the heap.
        // This should be a cheap operation relative to decryption.
        clearText.fillRange(0, clearText.length, 0);
      } catch (_) {}
    }
  }

  /// Encrypts the [clearText] and returns the [SecretBox].
  ///
  /// See [Cipher.encrypt] for more information.
  ///
  /// ## Example
  /// In this example, we use [Chacha20.poly1305Aead]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final cipher = Chacha20.poly1305Aead();
  ///   final secretKey = await cipher.newSecretKey();
  ///   final wand = await cipher.newCipherWandFromSecretKey(secretKey);
  ///
  ///   // Encrypt
  ///   final secretBox = await wand.encrypt([1,2,3]);
  ///
  ///   print('Nonce: ${secretBox.nonce}');
  ///   print('Cipher text: ${secretBox.cipherText}');
  ///   print('MAC: ${secretBox.mac.bytes}');
  ///
  ///   // Decrypt
  ///   final clearText = await wand.decrypt(secretBox);
  /// }
  /// ```
  Future<SecretBox> encrypt(
    List<int> clearText, {
    List<int>? nonce,
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  });

  /// Encrypts a string.
  ///
  /// The string is converted to bytes using [utf8] codec.
  ///
  /// See [Cipher.encrypt] for more information.
  ///
  /// ## Example
  /// In this example, we use [Chacha20.poly1305Aead]:
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final cipher = Chacha20.poly1305Aead();
  ///   final secretKey = await cipher.newSecretKey();
  ///   final wand = await cipher.newCipherWandFromSecretKey(secretKey);
  ///
  ///   // Encrypt
  ///   final secretBox = await wand.encryptString('Hello, world!');
  ///   print('Nonce: ${secretBox.nonce}');
  ///   print('Cipher text: ${secretBox.cipherText}');
  ///   print('MAC: ${secretBox.mac.bytes}');
  ///
  ///   // Decrypt
  ///   final clearText = await wand.decryptString(secretBox);
  ///   print('Clear text: $clearText');
  /// }
  /// ```
  Future<SecretBox> encryptString(String clearText) async {
    final bytes = utf8.encode(clearText);
    final secretBox = await encrypt(
      bytes,
      possibleBuffer: bytes,
    );

    // Cut the amount of possibly sensitive data in the heap.
    // This should be a cheap operation relative to encryption.
    final cipherText = secretBox.cipherText;
    if (cipherText is! Uint8List ||
        !identical(bytes.buffer, cipherText.buffer)) {
      bytes.fillRange(0, bytes.length, 0);
    }

    return secretBox;
  }
}
