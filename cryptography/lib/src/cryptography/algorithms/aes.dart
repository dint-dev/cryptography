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
import 'package:pointycastle/api.dart' as pointycastle;
import 'package:pointycastle/block/aes_fast.dart' as pointycastle;
import 'package:pointycastle/block/modes/cbc.dart' as pointycastle;
import 'package:pointycastle/padded_block_cipher/padded_block_cipher_impl.dart'
    as pointycastle;
import 'package:pointycastle/paddings/pkcs7.dart' as pointycastle;
import 'package:pointycastle/stream/ctr.dart' as pointycastle;

import 'web_crypto.dart';

/// _AES-CBC_ cipher.
///
/// The secret key can be any value with 128, 192, or 256 bits. By default, the
/// key generator returns 256 bit keys.
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final cipher = aesCbc;
///
///   final input = <int>[1,2,3];
///   final secretKey = cipher.newSecretKeySync();
///   final nonce = cipher.newNonce();
///
///   // Encrypt
///   final encryptedBytes = cipher.encrypt(
///     input,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decryptedBytes = cipher.encrypt(
///     encryptedBytes,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher aesCbc = webAesCbc ?? _AesCbcImplPointyCastle();

/// _AES-CTR_ cipher with a 96-bit nonce and a 32-bit counter.
///
/// The secret key can be any value with 128, 192, or 256 bits. By default, the
/// key generator returns 256 bit keys.
///
/// AES-CTR takes a 16-byte initialization vector and allows you to specify how
/// many right-most bits are taken by the counter.
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final cipher = aesCtr;
///
///   final input = <int>[1,2,3];
///   final secretKey = cipher.newSecretKeySync();
///   final nonce = cipher.newNonce();
///
///   // Encrypt
///   final encryptedBytes = cipher.encrypt(
///     input,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decryptedBytes = cipher.encrypt(
///     encryptedBytes,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher aesCtr32 = webAesCtr32 ?? _AesCtr32ImplPointyCastle();

/// _AES-GCM_ (Galois/Counter Mode) cipher.
/// Currently supported __only in the browser.__
///
/// The secret key can be any value with 128, 192, or 256 bits. By default, the
/// key generator returns 256 bit keys.
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final cipher = aesGcm;
///
///   final input = <int>[1,2,3];
///   final secretKey = cipher.newSecretKeySync();
///   final nonce = cipher.newNonce();
///
///   // Encrypt
///   final encryptedBytes = await cipher.encrypt(
///     input,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///
///   // Decrypt
///   final decryptedBytes = await cipher.encrypt(
///     encryptedBytes,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
const Cipher aesGcm = webAesGcm;

class _AesCbcImplPointyCastle extends Cipher {
  const _AesCbcImplPointyCastle();

  @override
  String get name => 'aesCbc';

  @override
  Set<int> get secretKeyValidLengths => const {16, 24, 32};

  @override
  int get secretKeyLength => 32;

  @override
  int get nonceLength => 16;

  @override
  List<int> decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (aad != null) {
      throw ArgumentError.value(aad, 'aad');
    }
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(keyStreamIndex, 'offset');
    }
    final implementation = pointycastle.PaddedBlockCipherImpl(
      pointycastle.PKCS7Padding(),
      pointycastle.CBCBlockCipher(
        pointycastle.AESFastEngine(),
      ),
    );

    final secretKeyUint8List = Uint8List.fromList(
      secretKey.extractSync(),
    );
    final nonceBytes = Uint8List.fromList(
      nonce.bytes.sublist(0, 16),
    );
    implementation.init(
      false,
      pointycastle.PaddedBlockCipherParameters(
        pointycastle.ParametersWithIV(
          pointycastle.KeyParameter(secretKeyUint8List),
          nonceBytes,
        ),
        pointycastle.ParametersWithIV(
          pointycastle.KeyParameter(secretKeyUint8List),
          nonceBytes,
        ),
      ),
    );
    return implementation.process(Uint8List.fromList(input));
  }

  @override
  List<int> encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (aad != null) {
      throw ArgumentError.value(aad, 'aad');
    }
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(keyStreamIndex, 'offset');
    }
    final implementation = pointycastle.PaddedBlockCipherImpl(
      pointycastle.PKCS7Padding(),
      pointycastle.CBCBlockCipher(
        pointycastle.AESFastEngine(),
      ),
    );

    final secretKeyUint8List = Uint8List.fromList(
      secretKey.extractSync(),
    );
    final nonceBytes = Uint8List.fromList(
      nonce.bytes.sublist(0, 16),
    );
    implementation.init(
      true,
      pointycastle.PaddedBlockCipherParameters(
        pointycastle.ParametersWithIV(
          pointycastle.KeyParameter(secretKeyUint8List),
          nonceBytes,
        ),
        pointycastle.ParametersWithIV(
          pointycastle.KeyParameter(secretKeyUint8List),
          nonceBytes,
        ),
      ),
    );
    return implementation.process(Uint8List.fromList(input));
  }
}

class _AesCtr32ImplPointyCastle extends Cipher {
  const _AesCtr32ImplPointyCastle();

  @override
  String get name => 'aesCtr32';

  @override
  int get nonceLength => 12;

  @override
  Set<int> get secretKeyValidLengths => const {16, 24, 32};

  @override
  int get secretKeyLength => 32;

  @override
  List<int> decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (aad != null) {
      throw ArgumentError.value(aad, 'aad');
    }
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(keyStreamIndex, 'offset');
    }
    final implementation = pointycastle.CTRStreamCipher(
      pointycastle.AESFastEngine(),
    );

    final secretKeyUint8List = Uint8List.fromList(
      secretKey.extractSync(),
    );
    final counterBytes = Uint8List(16);
    counterBytes.setRange(0, 12, nonce.bytes);
    final counterByteData = ByteData.view(counterBytes.buffer);
    counterByteData.setUint32(12, keyStreamIndex, Endian.big);
    implementation.init(
      false,
      pointycastle.ParametersWithIV(
        pointycastle.KeyParameter(secretKeyUint8List),
        counterBytes,
      ),
    );
    return implementation.process(Uint8List.fromList(input));
  }

  @override
  List<int> encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    if (aad != null) {
      throw ArgumentError.value(aad, 'aad');
    }
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(keyStreamIndex, 'offset');
    }
    final implementation = pointycastle.CTRStreamCipher(
      pointycastle.AESFastEngine(),
    );

    final secretKeyUint8List = Uint8List.fromList(
      secretKey.extractSync(),
    );
    final counterBytes = Uint8List(16);
    counterBytes.setRange(0, 12, nonce.bytes);
    final counterByteData = ByteData.view(counterBytes.buffer);
    counterByteData.setUint32(12, keyStreamIndex, Endian.big);
    implementation.init(
      true,
      pointycastle.ParametersWithIV(
        pointycastle.KeyParameter(secretKeyUint8List),
        counterBytes,
      ),
    );
    return implementation.process(Uint8List.fromList(input));
  }
}
