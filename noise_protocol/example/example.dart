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

import 'package:cryptography/src/utils.dart';
import 'package:noise_protocol/noise_protocol.dart';

Future<void> main() async {
  final protocol = NoiseProtocol(
    handshakePattern: NoiseHandshakePattern.xx,
    noiseKeyExchangeAlgorithm: NoiseKeyExchangeAlgorithm.x25519,
    cipher: NoiseCipher.chachaPoly,
    hashAlgorithm: NoiseHashAlgorithm.blake2s,
  );

  // A buffer for messages
  final buffer = <int>[];

  // Handshake states
  final localHandshakeState = HandshakeState(
    protocol: protocol,
    authenticator: NoiseAuthenticationParameters(
        // You can fix local/remote keys here
        ),
  );
  final remoteHandshakeState = HandshakeState(
    protocol: protocol,
    authenticator: NoiseAuthenticationParameters(),
  );

  // Let's do a handshake with KK pattern
  await localHandshakeState.initialize(
    isInitiator: true,
  );
  await remoteHandshakeState.initialize(
    isInitiator: false,
  );

  // local --> remote
  await localHandshakeState.writeMessage(
    messageBuffer: buffer,
    payload: [1, 2, 3], // Should contain be unique to prevent replay attacks
  );
  await remoteHandshakeState.readMessage(
    message: buffer,
  );
  print('Local --> remote: ${hexFromBytes(buffer)}');
  buffer.clear();

  // local <-- remote
  await remoteHandshakeState.writeMessage(
    messageBuffer: buffer,
    payload: [4, 5, 6], // Should contain be unique to prevent replay attacks
  );
  await localHandshakeState.readMessage(
    message: buffer,
  );
  print('Local <-- remote: ${hexFromBytes(buffer)}');
  buffer.clear();

  // local --> remote
  final localState = (await localHandshakeState.writeMessage(
    messageBuffer: buffer,
  ))!;
  final remoteState = (await remoteHandshakeState.readMessage(
    message: buffer,
  ))!;

  print('Local --> remote: ${hexFromBytes(buffer)}');
  print('');
  buffer.clear();

  {
    final keyForSending = await localState.encryptingState.secretKey!.extract();
    final keyForReceiving =
        await localState.decryptingState.secretKey!.extract();
    print('Local keys:');
    print('  Sending: ${hexFromBytes(keyForSending.bytes)}');
    print('  Receiving: ${hexFromBytes(keyForReceiving.bytes)}');
  }
  {
    final keyForSending =
        await remoteState.encryptingState.secretKey!.extract();
    final keyForReceiving =
        await remoteState.decryptingState.secretKey!.extract();
    print('');
    print('Remote keys:');
    print('  Sending: ${hexFromBytes(keyForSending.bytes)}');
    print('  Receiving: ${hexFromBytes(keyForReceiving.bytes)}');
  }

  // Now both parties have:
  //   * A secret key for sending.
  //   * A secret key receiving.
}
