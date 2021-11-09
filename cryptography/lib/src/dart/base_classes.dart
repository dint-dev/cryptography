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

  Hash hashSync();
}

/// Base class for pure Dart implementations of [KeyExchangeAlgorithm].
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

  SecretKey sharedSecretSync({
    required KeyPairData keyPairData,
    required PublicKey remotePublicKey,
  });
}

/// Base class for pure Dart implementations of [MacAlgorithm].
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

  DartMacSink newMacSinkSync({
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  });
}

mixin DartMacSink implements MacSink {
  @override
  Future<Mac> mac() => Future<Mac>.value(macSync());

  Mac macSync();
}

/// Base class for pure Dart implementations of [SignatureAlgorithm].
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

  bool verifySync(
    List<int> input, {
    required Signature signature,
  });
}
