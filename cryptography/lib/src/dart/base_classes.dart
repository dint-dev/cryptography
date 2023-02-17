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

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

/// A [HashAlgorithm] that supports synchronous evaluation ([hashSync]).
mixin DartHashAlgorithmMixin implements HashAlgorithm {
  @override
  Future<Hash> hash(List<int> input) async {
    return Future<Hash>(() => hashSync(input));
  }

  /// Synchronous version of [hash()].
  Hash hashSync(List<int> data) {
    ArgumentError.checkNotNull(data);
    var sink = newHashSink();
    sink.add(data);
    sink.close();
    return sink.hashSync();
  }

  /// Synchronous version of [newHashSink()].
  @override
  DartHashSink newHashSink();
}

/// A [HashSink] that supports synchronous evaluation ([hashSync]).
abstract class DartHashSink extends HashSink {
  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast);

  @override
  void close();

  @nonVirtual
  @override
  Future<Hash> hash() async {
    return hashSync();
  }

  /// Computes a hash synchronously (unlike [hash]).
  Hash hashSync();
}

/// A mixin for pure Dart implementations of [KeyExchangeAlgorithm].
mixin DartKeyExchangeAlgorithmMixin implements KeyExchangeAlgorithm {
  @override
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) async {
    final keyPairData = await keyPair.extract();
    return sharedSecretSync(
      keyPairData: keyPairData,
      remotePublicKey: remotePublicKey,
    );
  }

  /// Computes shared secret synchronously (unlike [sharedSecretKey]).
  ///
  /// ## Example
  /// In this example, we use [DartX25519] class:
  /// ```dart
  /// import 'package:cryptography/cryptography.dart';
  ///
  /// void main() async {
  ///   final algorithm = DartX25519();
  ///
  ///   // We need the private key pair of Alice.
  ///   final aliceKeyPair = algorithm.newKeyPairSync();
  ///
  ///   // We need only public key of Bob.
  ///   final bobKeyPair = algorithm.newKeyPairSync();
  ///   final bobPublicKey = bobKeyPair.publicKey;
  ///
  ///   // We can now calculate a 32-byte shared secret key.
  ///   final sharedSecretKey = algorithm.sharedSecretKeySync(
  ///     keyPair: aliceKeyPair,
  ///     remotePublicKey: bobPublicKey,
  ///   );
  /// }
  /// ```
  SecretKey sharedSecretSync({
    required KeyPairData keyPairData,
    required PublicKey remotePublicKey,
  });
}

/// A mixin for pure Dart implementations of [MacAlgorithm].
mixin DartMacAlgorithmMixin implements MacAlgorithm {
  @override
  Future<Mac> calculateMac(
    List<int> bytes, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    final secretKeyData = await secretKey.extract();
    return Future<Mac>.value(calculateMacSync(
      bytes,
      secretKeyData: secretKeyData,
      nonce: nonce,
      aad: aad,
    ));
  }

  /// Computes a MAC synchronously (unlike [calculateMac]).
  Mac calculateMacSync(
    List<int> cipherText, {
    required SecretKeyData secretKeyData,
    required List<int> nonce,
    List<int> aad = const <int>[],
  }) {
    final sink = newMacSinkSync(
      secretKeyData: secretKeyData,
      nonce: nonce,
      aad: aad,
    );
    sink.add(cipherText);
    return sink.macSync();
  }

  /// Returns [DartMacSink], which can be used synchronously.
  DartMacSink newMacSinkSync({
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  });
}

/// A mixin for pure Dart implementations of [MacSink]
mixin DartMacSink implements MacSink {
  @override
  Future<Mac> mac() => Future<Mac>.value(macSync());

  /// Computes the MAC synchronously.
  Mac macSync();
}

/// A mixin for pure Dart implementations of [SignatureAlgorithm].
mixin DartSignatureAlgorithmMixin implements SignatureAlgorithm {
  @override
  Future<Signature> sign(
    List<int> input, {
    required KeyPair keyPair,
  }) async {
    final keyPairData = await keyPair.extract();
    return signSync(
      input,
      keyPairData: keyPairData,
    );
  }

  /// Signs a message synchronously (unlike [sign]).
  Signature signSync(
    List<int> input, {
    required KeyPairData keyPairData,
  });

  @override
  Future<bool> verify(
    List<int> input, {
    required Signature signature,
  }) async {
    return verifySync(input, signature: signature);
  }

  /// Verifies a signature synchronously (unlike [verify]).
  bool verifySync(
    List<int> input, {
    required Signature signature,
  });
}
