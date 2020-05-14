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
import 'package:meta/meta.dart';

/// Wraps some [Cipher] and adds authentication with some [MacAlgorithm].
///
/// After encrypting bytes ([encrypt] or [encryptSync]), the class calculates
/// MAC code and appends it after encrypted bytes.
///
/// Before decrypting bytes ([decrypt] or [decryptSync]), the class
/// checks the MAC and throws [MacValidationException] if it's wrong.
///
/// Other method calls (such as [newNonce]) are delegated directly to the
/// wrapped cipher.
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final cipher = CipherWithAppendedMac(chacha20, Hmac(sha256));
///
///   // Use it like a normal cipher.
/// }
/// ```
class CipherWithAppendedMac implements Cipher {
  @protected
  final Cipher cipher;

  @protected
  final MacAlgorithm macAlgorithm;

  const CipherWithAppendedMac(
    this.cipher,
    this.macAlgorithm,
  );

  @override
  bool get isAuthenticated => true;

  @override
  String get name => '${cipher.name}-${macAlgorithm.name}';

  @override
  int get nonceLength => cipher.nonceLength;

  @override
  int get secretKeyLength => cipher.secretKeyLength;

  @override
  Set<int> get secretKeyValidLengths => cipher.secretKeyValidLengths;

  @override
  bool get supportsAad => cipher.supportsAad;

  @protected
  Future<Mac> calculateMac(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    @required List<int> aad,
  }) {
    assert(!cipher.isAuthenticated);
    if (!supportsAad && aad != null && aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad');
    }
    return macAlgorithm.calculateMac(
      cipherText,
      secretKey: secretKey,
    );
  }

  @protected
  Mac calculateMacSync(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    @required List<int> aad,
  }) {
    assert(!cipher.isAuthenticated);
    if (!supportsAad && aad != null && aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad');
    }
    return macAlgorithm.calculateMacSync(
      cipherText,
      secretKey: secretKey,
    );
  }

  @override
  Future<List<int>> decrypt(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    if (!supportsAad && aad != null && aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad');
    }
    final n = cipherText.length - macAlgorithm.macLengthInBytes;
    final dataSection = cipherText.take(n).toList(growable: false);
    final macSection = cipherText.skip(n).toList(growable: false);

    // Verify mac
    final calculatedMac = await calculateMac(
      dataSection,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    if (Mac(macSection) != calculatedMac) {
      throw MacValidationException();
    }

    return cipher.decrypt(
      dataSection,
      secretKey: secretKey,
      nonce: nonce,
      aad: cipher.supportsAad ? aad : null,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  List<int> decryptSync(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (!supportsAad && aad != null && aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad');
    }
    final n = cipherText.length - macAlgorithm.macLengthInBytes;
    final dataSection = cipherText.take(n).toList(growable: false);
    final macSection = cipherText.skip(n).toList(growable: false);

    // Verify mac
    final calculatedMac = calculateMacSync(
      dataSection,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    if (Mac(macSection) != calculatedMac) {
      throw MacValidationException();
    }

    return cipher.decryptSync(
      dataSection,
      secretKey: secretKey,
      nonce: nonce,
      aad: cipher.supportsAad ? aad : null,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<int> decryptToBuffer(
    List<int> input, {
    @required List<int> buffer,
    int bufferStart = 0,
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    ArgumentError.checkNotNull(buffer, 'buffer');
    ArgumentError.checkNotNull(bufferStart, 'bufferStart');
    if (!supportsAad && aad != null && aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad');
    }
    final tmp = await decrypt(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    buffer.setAll(bufferStart, tmp);
    return tmp.length;
  }

  @override
  Future<List<int>> encrypt(
    List<int> clearText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    if (!supportsAad && aad != null && aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad');
    }
    final cipherText = await cipher.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
      aad: cipher.supportsAad ? aad : null,
      keyStreamIndex: keyStreamIndex,
    );

    final calculatedMac = await calculateMac(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );

    final output = Uint8List(cipherText.length + calculatedMac.bytes.length);
    output.setAll(0, cipherText);
    output.setAll(cipherText.length, calculatedMac.bytes);
    return output;
  }

  @override
  List<int> encryptSync(
    List<int> clearText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (!supportsAad && aad != null && aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad');
    }
    final cipherText = cipher.encryptSync(
      clearText,
      secretKey: secretKey,
      nonce: nonce,
      aad: cipher.supportsAad ? aad : null,
      keyStreamIndex: keyStreamIndex,
    );

    final calculatedMac = calculateMacSync(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );

    final output = Uint8List(cipherText.length + calculatedMac.bytes.length);
    output.setAll(0, cipherText);
    output.setAll(cipherText.length, calculatedMac.bytes);
    return output;
  }

  @override
  Future<int> encryptToBuffer(
    List<int> input, {
    @required List<int> buffer,
    int bufferStart = 0,
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    ArgumentError.checkNotNull(buffer, 'buffer');
    ArgumentError.checkNotNull(bufferStart, 'bufferStart');
    if (!supportsAad && aad != null && aad.isNotEmpty) {
      throw ArgumentError.value(aad, 'aad');
    }
    final tmp = await encrypt(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
    buffer.setAll(bufferStart, tmp);
    return tmp.length;
  }

  @override
  List<int> getDataInCipherText(List<int> cipherText) {
    final n = cipherText.length - macAlgorithm.macLengthInBytes;
    return cipherText.sublist(0, n);
  }

  @override
  Mac getMacInCipherText(List<int> cipherText) {
    final n = cipherText.length - macAlgorithm.macLengthInBytes;
    return Mac(cipherText.sublist(n));
  }

  @override
  bool isSecretKeyLengthInBytesValid(int length) =>
      cipher.isSecretKeyLengthInBytesValid(length);

  @override
  Nonce newNonce() => cipher.newNonce();

  @override
  Future<SecretKey> newSecretKey({int length}) =>
      cipher.newSecretKey(length: length);

  @override
  SecretKey newSecretKeySync({int length}) =>
      cipher.newSecretKeySync(length: length);

  @override
  String toString() {
    return 'CipherWithAppendedMac($cipher, $macAlgorithm)';
  }
}
