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
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';

/// A cipher that supports [encrypt()] and [decrypt()].
///
/// ## Available algorithms
///   * [AesCbc]
///   * [AesCtr]
///   * [AesGcm]
///   * [Chacha20]
///   * [Chacha20.poly1305Aead]
///   * [Xchacha20]
///   * [Xchacha20.poly1305Aead]
///
/// ## Example
/// An example of using [AesCtr] and [Hmac]:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   // AES-CTR with 128 bit keys and HMAC-SHA256 authentication.
///   final algorithm = AesCtr.with128bits(
///     macAlgorithm: Hmac.sha256(),
///   );
///   final secretKey = await algorithm.newSecretKey();
///   final nonce = algorithm.newNonce();
///
///   // Encrypt
///   final secretBox = await algorithm.encrypt(
///     message,
///     secretKey: secretKey,
///   );
///   print('Nonce: ${secretBox.nonce}')
///   print('Ciphertext: ${secretBox.cipherText}')
///   print('MAC: ${secretBox.mac.bytes}')
///
///   // Decrypt
///   final clearText = await algorithm.encrypt(
///     secretBox,
///     secretKey: secretKey,
///   );
///   print('Cleartext: $clearText');
/// }
/// ```
abstract class Cipher {
  /// Methods [encryptStream] and [decryptStream] do 1ms pauses every this many
  /// bytes to avoid blocking the event loop.
  static const _pauseStreamEveryBytes = 4 * 1024 * 1024;
  static const _pauseDuration = Duration(milliseconds: 1);

  static final _emptyUint8List = Uint8List(0);

  final Random? _random;

  /// Constructor for subclasses.
  const Cipher({Random? random}) : _random = random;

  @override
  int get hashCode;

  /// Message authentication code ([MacAlgorithm]) used by the cipher.
  MacAlgorithm get macAlgorithm;

  /// Number of bytes in the nonce ("Initialization Vector", "IV", "salt").
  ///
  /// Method [newNonce] uses this property to generate correct-length nonces.
  ///
  /// Methods [encrypt] and [decrypt] will throw [ArgumentError] if they receive
  /// incorrect-length nonces.
  int get nonceLength;

  /// Number of bytes in the [SecretKey].
  ///
  /// Method [newSecretKey] uses this property to generate correct-length secret
  /// keys.
  ///
  /// Methods [encrypt] and [decrypt] will throw [ArgumentError] if they receive
  /// incorrect-length secret keys.
  int get secretKeyLength;

  @override
  bool operator ==(other);

  /// Checks parameters for [encrypt] / [decrypt] and throws [ArgumentError] if
  /// any is invalid.
  void checkParameters({
    int? length,
    required SecretKey secretKey,
    required int nonceLength,
    int aadLength = 0,
    int keyStreamIndex = 0,
  }) {
    if (secretKey is SecretKeyData) {
      final secretKeyLength = secretKey.bytes.length;
      final expectedSecretKeyLength = this.secretKeyLength;
      if (secretKeyLength != expectedSecretKeyLength) {
        throw ArgumentError(
          '$this expects a secret key with $expectedSecretKeyLength bytes, got $secretKeyLength bytes',
        );
      }
    }
    final expectedNonceLength = this.nonceLength;
    if (nonceLength != expectedNonceLength) {
      throw ArgumentError(
        '$this expects a nonce with $expectedNonceLength bytes, got $nonceLength bytes',
      );
    }
    if (aadLength != 0 && !macAlgorithm.supportsAad) {
      throw ArgumentError(
        '$this does not support AAD',
      );
    }
    if (keyStreamIndex != 0 && !macAlgorithm.supportsKeyStreamIndex) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        '$this does not support key stream index',
      );
    }
    macAlgorithm.checkParameters(
      length: length,
      secretKey: secretKey,
      nonceLength: nonceLength,
      aadLength: aadLength,
      keyStreamIndex: keyStreamIndex,
    );
  }

  /// Calculates the length of the ciphertext given a clear text length.
  int cipherTextLength(int clearTextLength) => clearTextLength;

  /// Decrypts [SecretBox] and returns the bytes.
  ///
  /// Subclasses of `Cipher` do the following:
  ///   1.Authenticates [SecretBox.mac] with [macAlgorithm].
  ///   2.Decrypts [SecretBox.cipherText].
  ///   3.Returns the cleartext.
  ///
  /// The [SecretBox] is authenticated with [SecretBox.checkMac()), which will
  /// throw [SecretBoxAuthenticationError] if the MAC is incorrect.
  ///
  /// You must give a [SecretKey] that has the correct length and type.
  ///
  /// Optional parameter `nonce` (also known as "initialization vector",
  /// "IV", or "salt") is some non-secret unique sequence of bytes.
  /// If you don't define it, the cipher will generate nonce for you.
  ///
  /// Parameter `aad` can be used to pass _Associated Authenticated Data_ (AAD).
  /// If you pass a non-empty list and the underlying cipher doesn't support
  /// AAD, the method will throw [ArgumentError].
  ///
  /// If [possibleBuffer] is non-null, the method is allowed (but not required)
  /// to write the output to it. The buffer can be the same as [input].
  /// Otherwise the method will allocate memory for the output.
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  });

  /// Decrypts a [Stream] of bytes.
  ///
  /// Parameter [stream] is a stream of chunks of bytes.
  ///
  /// Parameter [secretKey] is the secret key. You can generate a secret key
  /// with [newSecretKey].
  ///
  /// Parameter [nonce] is the nonce.
  ///
  /// You must give [mac] for message authentication. If authentication fails,
  /// the output stream will have a [SecretBoxAuthenticationError]. For example,
  /// if your [macAlgorithm] is [MacAlgorithm.empty], use [Mac.empty].
  ///
  /// You can use [aad] to pass _Associated Authenticated Data_ (AAD).
  ///
  /// If [allowUseSameBytes] is `true`, the method is allowed (but not required)
  /// to reduce memory allocations by using the same byte array for input and
  /// output. If you use the same byte array for other purposes, this may be
  /// unsafe.
  ///
  /// The default implementation reads the input stream into a buffer and,
  /// after the input stream has been closed, calls [decrypt]. Subclasses are
  /// encouraged to override the default implementation so that the input stream
  /// is processed as it is received.
  Stream<List<int>> decryptStream(
    Stream<List<int>> stream, {
    required SecretKey secretKey,
    required List<int> nonce,
    required FutureOr<Mac> mac,
    List<int> aad = const [],
    bool allowUseSameBytes = false,
  }) async* {
    final state = newState();
    await state.initialize(
      isEncrypting: false,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    var count = 0;
    await for (var chunk in stream) {
      final convertedChunk = state.convertChunkSync(
        chunk,
        possibleBuffer: allowUseSameBytes && chunk is Uint8List ? chunk : null,
      );
      yield (convertedChunk);

      // Pause every now and then to avoid blocking the event loop.
      count += chunk.length;
      if (count >= _pauseStreamEveryBytes) {
        await Future.delayed(_pauseDuration);
        count = 0;
      }
    }
    final convertedSuffix = await state.convert(
      _emptyUint8List,
      expectedMac: await mac,
    );
    if (convertedSuffix.isNotEmpty) {
      yield (convertedSuffix);
    }
    if (state.mac != await mac) {
      throw SecretBoxAuthenticationError();
    }
  }

  /// Calls [decode] and then converts the bytes to a string by using
  /// [utf8] codec.
  Future<String> decryptString(
    SecretBox secretBox, {
    required SecretKey secretKey,
  }) async {
    final clearText = await decrypt(
      secretBox,
      secretKey: secretKey,
    );
    try {
      return utf8.decode(clearText);
    } finally {
      // Don't leave possibly sensitive data in the heap.
      clearText.fillRange(0, clearText.length, 0);
    }
  }

  /// Encrypts bytes and returns [SecretBox].
  ///
  /// You must give a [SecretKey] that has the correct length and type.
  ///
  /// Optional parameter `nonce` (also known as "initialization vector",
  /// "IV", or "salt") is some sequence of bytes.
  /// You can generate a nonce with [newNonce].
  /// If you don't define it, the cipher will generate a random nonce for you.
  /// The nonce must be unique for each encryption with the same secret key.
  /// It doesn't have to be secret.
  ///
  /// Parameter `aad` can be used to pass _Associated Authenticated Data_ (AAD).
  /// If you pass a non-empty list and the underlying cipher doesn't support
  /// AAD, the method will throw [ArgumentError].
  ///
  /// If [possibleBuffer] is non-null, the method is allowed (but not required)
  /// to write the output to it. The buffer can be the same as [input].
  /// Otherwise the method will allocate memory for the output.
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  });

  /// Encrypts a [Stream] of bytes.
  ///
  /// Parameter [stream] is the encrypted stream of bytes.
  ///
  /// Parameter [secretKey] is the secret key. You can generate a random secret
  /// key with [newSecretKey].
  ///
  /// Optional parameter `nonce` (also known as "initialization vector",
  /// "IV", or "salt") is some sequence of bytes.
  /// You can generate a nonce with [newNonce].
  /// If you don't define it, the cipher will generate a random nonce for you.
  /// The nonce must be unique for each encryption with the same secret key.
  /// It doesn't have to be secret.
  ///
  /// You will receive a Message Authentication Code (MAC) using the callback
  /// [onMac] after the input stream is closed and before the output stream is
  /// closed. For example, if your [macAlgorithm] is [MacAlgorithm.empty], the
  /// MAC will be [Mac.empty].
  ///
  /// You can use [aad] to pass _Associated Authenticated Data_ (AAD).
  ///
  /// If [allowUseSameBytes] is `true`, the method is allowed (but not required)
  /// to reduce memory allocations by using the same byte array for input and
  /// output. If you use the same byte array for other purposes, this may be
  /// unsafe.
  ///
  /// The default implementation reads the input stream into a buffer and,
  /// after the input stream has been closed, calls [encrypt]. Subclasses are
  /// encouraged to override the default implementation so that the input stream
  /// is processed as it is received.
  ///
  /// ## Example
  /// ```dart
  /// import 'package:cryptography.dart';
  ///
  /// void main() {
  ///   final cipher = Chacha20.poly1305Aead();
  ///   final secretKey = cipher.newSecretKey();
  ///   final nonce = cipher.newNonce();
  ///
  ///   final file = File('example.txt');
  ///   final encryptedFile = File('example.txt.encrypted');
  ///
  ///   final sink = encryptedFile.openWrite();
  ///   try {
  ///     final clearTextStream = file.openRead();
  ///     final encryptedStream = state.encryptStream(
  ///       clearTextStream,
  ///       secretKey: secretKey,
  ///       nonce: nonce,
  ///     );
  ///     await encryptedSink.addStream(encryptedStream);
  ///   } finally {
  ///     sink.close();
  ///   }
  /// }
  /// ```
  Stream<List<int>> encryptStream(
    Stream<List<int>> stream, {
    required SecretKey secretKey,
    required List<int> nonce,
    required void Function(Mac mac) onMac,
    List<int> aad = const [],
    bool allowUseSameBytes = false,
  }) async* {
    final state = newState();
    await state.initialize(
      isEncrypting: true,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    var count = 0;
    await for (var chunk in stream) {
      final convertedChunk = state.convertChunkSync(
        chunk,
        possibleBuffer: allowUseSameBytes && chunk is Uint8List ? chunk : null,
      );
      yield (convertedChunk);

      // Pause every now and then to avoid blocking the event loop.
      count += chunk.length;
      if (count >= _pauseStreamEveryBytes) {
        await Future.delayed(_pauseDuration);
        count = 0;
      }
    }
    final convertedSuffix = await state.convert(
      _emptyUint8List,
      expectedMac: null,
    );
    if (convertedSuffix.isNotEmpty) {
      yield (convertedSuffix);
    }
    onMac(state.mac);
  }

  /// Converts a string to bytes using [utf8] codec and then calls [encrypt].
  Future<SecretBox> encryptString(
    String clearText, {
    required SecretKey secretKey,
  }) async {
    final bytes = utf8.encode(clearText);
    final secretBox = await encrypt(
      bytes,
      secretKey: secretKey,
      possibleBuffer: bytes is Uint8List ? bytes : null,
    );

    // Overwrite `bytes` if it was not overwritten by the cipher.
    final cipherText = secretBox.cipherText;
    if (bytes is! Uint8List ||
        cipherText is! Uint8List ||
        !identical(bytes.buffer, cipherText.buffer)) {
      bytes.fillRange(0, bytes.length, 0);
    }

    return secretBox;
  }

  /// Constructs a [CipherWand] that uses this implementation and a new random
  /// secret key (that can't be extracted).
  Future<CipherWand> newCipherWand() async {
    final secretKey = await newSecretKey();
    return newCipherWandFromSecretKey(secretKey);
  }

  /// Constructs a [CipherWand] that uses this implementation and the
  /// given [SecretKey].
  Future<CipherWand> newCipherWandFromSecretKey(
    SecretKey secretKey, {
    bool allowEncrypt = true,
    bool allowDecrypt = true,
  }) async {
    return _CipherWand(
      this,
      secretKey,
      allowEncrypt: allowEncrypt,
      allowDecrypt: allowDecrypt,
    );
  }

  /// Generates a new nonce.
  ///
  /// It will have the correct length ([nonceLength]).
  ///
  /// The source of random bytes is [Random.secure] (a cryptographically secure
  /// random number generator) unless specified another random number generator
  /// when you constructed the cipher (or your [Cryptography]).
  List<int> newNonce() {
    final bytes = Uint8List(nonceLength);
    fillBytesWithSecureRandom(bytes, random: _random);
    return bytes;
  }

  /// Generates a new [SecretKey].
  ///
  /// It will have the correct length ([secretKeyLength]).
  ///
  /// The source of random bytes is [Random.secure] (a cryptographically secure
  /// random number generator) unless specified another random number generator
  /// when you constructed the cipher (or your [Cryptography]).
  Future<SecretKey> newSecretKey() async {
    return SecretKeyData.random(
      length: secretKeyLength,
      random: _random,
    );
  }

  /// Constructs a new [SecretKey] from the bytes.
  ///
  /// Throws [ArgumentError] if the argument length is not [secretKeyLength].
  Future<SecretKey> newSecretKeyFromBytes(List<int> bytes) async {
    if (bytes.length != secretKeyLength) {
      throw ArgumentError('Invalid secret key length');
    }
    return SecretKeyData(
      Uint8List.fromList(bytes),
      overwriteWhenDestroyed: true, // We copied the bytes so overwriting is ok.
    );
  }

  CipherState newState() => _DefaultCipherState(cipher: this);

  @override
  String toString();
}

class _CipherWand extends CipherWand {
  final Cipher cipher;
  final SecretKey _secretKey;
  final bool allowEncrypt;
  final bool allowDecrypt;

  _CipherWand(
    this.cipher,
    this._secretKey, {
    required this.allowEncrypt,
    required this.allowDecrypt,
  }) : super.constructor();

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  }) async {
    if (hasBeenDestroyed) {
      throw StateError('destroy() has been called');
    }
    if (!allowEncrypt) {
      throw StateError('Decrypting is not allowed by $this');
    }
    return cipher.decrypt(
      secretBox,
      secretKey: _secretKey,
      aad: aad,
    );
  }

  @override
  Future<void> destroy() async {
    await super.destroy();
    _secretKey.destroy();
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    List<int>? nonce,
    List<int> aad = const <int>[],
    Uint8List? possibleBuffer,
  }) async {
    if (hasBeenDestroyed) {
      throw StateError('destroy() has been called');
    }
    if (!allowEncrypt) {
      throw StateError('Encrypting is not allowed by $this');
    }
    return await cipher.encrypt(
      clearText,
      secretKey: _secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  String toString() {
    String? s;
    assert(() {
      s = 'CipherWand(\n'
          '  cipher: $cipher,\n'
          '  secretKey: $_secretKey,\n'
          '  allowEncrypt: $allowEncrypt,\n'
          '  allowDecrypt: $allowDecrypt,\n'
          ')';
      return true;
    }());
    return s ?? super.toString();
  }
}

/// Default implementation of [CipherState].
///
/// This will call [Cipher.encrypt] and [Cipher.decrypt] methods.
class _DefaultCipherState extends CipherState {
  static final _emptyUint8List = Uint8List(0);
  @override
  late final Cipher cipher;
  late final List<List<int>> _chunks = [];
  late final SecretKey _secretKey;
  late final List<int> _nonce;
  late final List<int> _aad;
  late final bool isEncrypting;
  late final int _keyStreamIndex;
  Mac? _mac;

  Mac? _expectedMac;

  _DefaultCipherState({
    required this.cipher,
  });

  @override
  Mac get mac {
    final mac = _mac;
    if (mac == null) {
      throw StateError('close() has not been called or has not finished');
    }
    return mac;
  }

  @override
  Future<List<int>> convert(
    List<int> event, {
    Uint8List? possibleBuffer,
    Mac? expectedMac,
  }) async {
    final input = _concatenate();
    final keyStreamIndex = _keyStreamIndex;
    if (isEncrypting) {
      final secretBox = keyStreamIndex == 0
          ? await cipher.encrypt(
              input,
              secretKey: _secretKey,
              nonce: _nonce,
              aad: _aad,
            )
          : await (cipher as StreamingCipher).encrypt(
              input,
              secretKey: _secretKey,
              nonce: _nonce,
              aad: _aad,
              keyStreamIndex: keyStreamIndex,
            );
      _mac = secretBox.mac;
      return secretBox.cipherText;
    } else {
      final clearText = keyStreamIndex == 0
          ? await cipher.decrypt(
              SecretBox(
                input,
                nonce: _nonce,
                mac: _expectedMac ?? Mac.empty,
              ),
              secretKey: _secretKey,
              aad: _aad,
            )
          : await (cipher as StreamingCipher).decrypt(
              SecretBox(
                input,
                nonce: _nonce,
                mac: _expectedMac ?? Mac.empty,
              ),
              secretKey: _secretKey,
              aad: _aad,
              keyStreamIndex: keyStreamIndex,
            );
      return clearText;
    }
  }

  @override
  List<int> convertChunkSync(
    List<int> bytes, {
    Uint8List? possibleBuffer,
  }) {
    _chunks.add(Uint8List.fromList(bytes));
    return _emptyUint8List;
  }

  @override
  Future<void> initialize({
    required bool isEncrypting,
    required SecretKey secretKey,
    required List<int> nonce,
    List<int> aad = const [],
    int keyStreamIndex = 0,
    bool allowUseSameBytes = false,
  }) async {
    _secretKey = secretKey;
    _nonce = nonce;
    _aad = aad;
    _keyStreamIndex = keyStreamIndex;
  }

  List<int> _concatenate() {
    final chunks = _chunks;
    if (chunks.isEmpty) {
      return _emptyUint8List;
    }
    if (chunks.length == 1) {
      return chunks.single;
    }
    final length = chunks.fold<int>(0, (sum, chunk) => sum + chunk.length);
    final result = Uint8List(length);
    var offset = 0;
    for (var chunk in chunks) {
      result.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
    }
    return result;
  }
}
