import 'dart:async';

import 'package:noise/noise.dart';
import 'package:test/test.dart';

void main() {
  test('NoiseConnection', () async {
    final protocol = NoiseProtocol(
      handshakePattern: HandshakePattern.xx,
      keyExchangeAlgorithm: NoiseKeyExchangeAlgorithm.x25519,
      cipher: NoiseCipher.chachaPoly,
      hashAlgorithm: NoiseHashAlgorithm.blake2s,
    );

    final localStreamController = StreamController<List<int>>.broadcast();
    final remoteStreamController = StreamController<List<int>>.broadcast();

    final localConnection = NoiseConnection.messagePrefixing(
      protocol: protocol,
      authenticator: NoiseAuthenticator(),
      sink: remoteStreamController,
      stream: localStreamController.stream,
    );
    final remoteConnection = NoiseConnection.messagePrefixing(
      protocol: protocol,
      authenticator: NoiseAuthenticator(),
      sink: remoteStreamController,
      stream: localStreamController.stream,
    );

    final localReceived = <int>[];
    localConnection.listen((chunk) {
      localReceived.addAll(chunk);
    });
    final remoteReceived = <int>[];
    remoteConnection.listen((chunk) {
      remoteReceived.addAll(chunk);
    });

    localConnection.add([1, 2]);
    localConnection.add([3]);
    await Future.delayed(Duration(milliseconds: 1));
    expect(localReceived, []);
    expect(remoteReceived, [1, 2, 3]);

    remoteConnection.add([4, 5]);
    remoteConnection.add([6]);
    await Future.delayed(Duration(milliseconds: 1));
    expect(localReceived, [4, 5, 6]);
    expect(remoteReceived, [1, 2, 3]);
  });
}
