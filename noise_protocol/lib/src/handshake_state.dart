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

part of noise_protocol;

/// _HandshakeState_ in the [specification](https://noiseprotocol.org/noise.html).
class HandshakeState {
  /// Noise protocol defines message pattern and algorithms.
  final NoiseProtocol protocol;

  /// Handshake algorithms.
  final NoiseAuthenticationParameters authenticator;

  /// Symmetric state.
  @visibleForTesting
  final SymmetricState symmetricState;

  /// Optional rekey function.
  final FutureOr<SecretKey> Function(SecretKey secretKey)? rekey;

  // Remaining message patterns for this handshake.
  late Queue<NoiseMessagePattern> _messagePatterns;

  // Are we an initiator or responder?
  bool? _isInitiator;

  // Is it our turn to send or receive?
  bool? _isSending;

  // Local ephemeral key pair.
  SimpleKeyPair? _localEphemeralKeyPair;

  /// Optional local static key pair. Some handshake patterns require this.
  ///
  /// The default value is obtained from [authenticator].
  SimpleKeyPair? localStaticKeyPair;

  /// Optional pre-shared key. Some handshake patterns require this.
  ///
  /// The default value is obtained from [authenticator].
  SecretKeyData? presharedKey;

  // Remote ephemeral public key.
  SimplePublicKey? _remoteEphemeralPublicKey;

  // Remote static public key.
  SimplePublicKey? _remoteStaticPublicKey;

  HandshakeState({
    required this.protocol,
    required this.authenticator,
    this.rekey,
  }) : symmetricState = SymmetricState(protocol: protocol) {
    final publicKeyLength = protocol.publicKeyLength;
    if (authenticator.remoteStaticPublicKey != null &&
        authenticator.remoteStaticPublicKey!.bytes.length != publicKeyLength) {
      throw ArgumentError.value(
        'remote static public key must have $publicKeyLength bytes',
      );
    }
    final presharedKey = authenticator.presharedKey;
    if (presharedKey == null &&
        authenticator.onValidateRemotePublicKey == null &&
        protocol.handshakePattern.usesPresharedKey) {
      throw ArgumentError(
        'pattern uses pre-shared key, thus authenticator must have either presharedKey or onRemotePublicKey',
      );
    }
    if (presharedKey != null && presharedKey.bytes.length != 32) {
      throw ArgumentError('pre-shared key must have 32 bytes');
    }
  }

  /// Whether the local party is initiator.
  bool? get isInitiator => _isInitiator;

  /// Local ephemeral key pair.
  SimpleKeyPair? get localEphemeralKeyPair => _localEphemeralKeyPair;

  /// Remote static ephemeral public key.
  SimplePublicKey? get remoteEphemeralPublicKey => _remoteEphemeralPublicKey;

  /// Remote static public key.
  SimplePublicKey? get remoteStaticPublicKey => _remoteStaticPublicKey;

  /// See the [specification](https://noiseprotocol.org/noise.html).
  Future<void> initialize({
    required bool isInitiator,
    List<int> prologue = const <int>[],
    SimpleKeyPair? localEphemeralKeyPair,
  }) async {
    if (protocol.handshakePattern.noiseMessagePatterns
        .any((p) => p.tokens.contains(NoiseMessageToken.e))) {
      if (_localEphemeralKeyPair == null) {
        final newKeyPair = await protocol
            .noiseKeyExchangeAlgorithm.implementation
            .newKeyPair();
        localEphemeralKeyPair =
            (await newKeyPair.extract()) as SimpleKeyPairData;
      }
    }

    //
    // Initialize
    //
    _messagePatterns = Queue<NoiseMessagePattern>.from(
      protocol.handshakePattern.noiseMessagePatterns,
    );
    _isInitiator = isInitiator;

    // Initialize symmetric state
    await symmetricState.initializeSymmetric();

    // Set keys
    final authenticator = this.authenticator;
    localStaticKeyPair = authenticator.localStaticKeyPair;
    if (localEphemeralKeyPair != null) {
      _localEphemeralKeyPair = await localEphemeralKeyPair.extract();
    }
    _remoteStaticPublicKey = authenticator.remoteStaticPublicKey!;
    _remoteEphemeralPublicKey = null;

    // Mix prologue
    await symmetricState.mixHash(prologue);

    // Mix public keys from pre-messages
    final handshakePattern = protocol.handshakePattern;
    if (isInitiator) {
      //
      // This is initiator
      //
      if (handshakePattern.isInitiatorKnown) {
        // Mix local public key
        final publicKey = await localStaticKeyPair!.extractPublicKey();
        await symmetricState.mixHash(publicKey.bytes);
      }
      if (handshakePattern.isResponderKnown) {
        // Mix remote public key
        await symmetricState.mixHash(remoteStaticPublicKey!.bytes);
      }
    } else {
      //
      // This is responder
      //
      if (handshakePattern.isInitiatorKnown) {
        await symmetricState.mixHash(remoteStaticPublicKey!.bytes);
      }
      if (handshakePattern.isResponderKnown) {
        final publicKey = await localStaticKeyPair!.extractPublicKey();
        await symmetricState.mixHash(publicKey.bytes);
      }
    }

    _isSending = isInitiator;
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  ///
  /// If this is the last handshake message, the method returns
  /// [HandshakeResult] and you can discard the handshake state.
  /// Otherwise returns null.
  Future<HandshakeResult?> readMessage({
    required List<int> message,
    List<int>? payloadBuffer,
    void Function(List<int> payload)? onPayload,
  }) async {
    if (_isSending == null) {
      throw StateError(
        'Handshake state is uninitialized',
      );
    }

    // Is it our turn to read?
    if (_isSending!) {
      throw StateError(
        'Expecting to write a message (not read)',
      );
    }

    // Get the message pattern
    final messagePattern = _messagePatterns.removeFirst();

    // Handle each token in the message pattern
    final keyExchangeAlgorithm =
        protocol.noiseKeyExchangeAlgorithm.implementation;
    var messageStart = 0;
    for (var token in messagePattern.tokens) {
      switch (token) {
        case NoiseMessageToken.e:
          // ------------------------------------------------------------------
          // Read remote ephemeral public key
          // ------------------------------------------------------------------
          if (_remoteEphemeralPublicKey != null) {
            throw StateError(
              'Received ephemeral public key twice.',
            );
          }
          // Read remote ephemeral public key
          final publicKeyLength = protocol.publicKeyLength;
          final publicKey = message.sublist(
            messageStart,
            messageStart + publicKeyLength,
          );
          messageStart += publicKeyLength;
          _remoteEphemeralPublicKey = SimplePublicKey(
            publicKey,
            type: keyExchangeAlgorithm.keyPairType,
          );

          // Call mixHash
          await symmetricState.mixHash(publicKey);
          break;

        case NoiseMessageToken.s:
          // ------------------------------------------------------------------
          // Read remote static public key (possibly encrypted)
          // ------------------------------------------------------------------
          if (_remoteStaticPublicKey != null) {
            throw StateError(
              'Received static public key twice.',
            );
          }
          final publicKeyLength = protocol.publicKeyLength;
          if (symmetricState.cipherState.secretKey == null) {
            // The bytes are not encrypted
            final n = publicKeyLength;
            final bytes = message.sublist(
              messageStart,
              messageStart + n,
            );
            messageStart += n;
            _remoteStaticPublicKey = SimplePublicKey(
              bytes,
              type: keyExchangeAlgorithm.keyPairType,
            );
          } else {
            // The bytes are encrypted
            final n = publicKeyLength + 16;
            var bytes = message.sublist(
              messageStart,
              messageStart + n,
            );
            messageStart += n;
            bytes = await symmetricState.decryptAndHash(bytes);
            _remoteStaticPublicKey = SimplePublicKey(
              bytes,
              type: keyExchangeAlgorithm.keyPairType,
            );
          }
          final onReceivedPublicKey = authenticator.onValidateRemotePublicKey;
          if (onReceivedPublicKey != null) {
            await onReceivedPublicKey(this);
          }
          break;

        case NoiseMessageToken.ee:
          // ------------------------------------------------------------------
          // Mix key with DH(ephemeral, ephemeral)
          // ------------------------------------------------------------------
          final secretKey = await keyExchangeAlgorithm.sharedSecretKey(
            keyPair: _localEphemeralKeyPair!,
            remotePublicKey: _remoteEphemeralPublicKey!,
          );
          final extractedSecretKey = await secretKey.extract();
          await symmetricState.mixKey(extractedSecretKey.bytes);
          break;

        case NoiseMessageToken.es:
          // ------------------------------------------------------------------
          // Mix key with DH(ephemeral, static)
          // ------------------------------------------------------------------
          SecretKey secretKey;
          if (isInitiator!) {
            secretKey = await keyExchangeAlgorithm.sharedSecretKey(
              keyPair: _localEphemeralKeyPair!,
              remotePublicKey: _remoteStaticPublicKey!,
            );
          } else {
            secretKey = await keyExchangeAlgorithm.sharedSecretKey(
              keyPair: localStaticKeyPair!,
              remotePublicKey: _remoteEphemeralPublicKey!,
            );
          }
          final extractedSecretKey = await secretKey.extract();
          await symmetricState.mixKey(extractedSecretKey.bytes);
          break;

        case NoiseMessageToken.se:
          // ------------------------------------------------------------------
          // Mix key with DH(static, ephemeral)
          // ------------------------------------------------------------------
          SecretKey secretKey;
          if (isInitiator!) {
            secretKey = await keyExchangeAlgorithm.sharedSecretKey(
              keyPair: localStaticKeyPair!,
              remotePublicKey: _remoteEphemeralPublicKey!,
            );
          } else {
            secretKey = await keyExchangeAlgorithm.sharedSecretKey(
              keyPair: localEphemeralKeyPair!,
              remotePublicKey: _remoteStaticPublicKey!,
            );
          }
          final extractedSecretKey = await secretKey.extract();
          await symmetricState.mixKey(extractedSecretKey.bytes);
          break;

        case NoiseMessageToken.ss:
          // ------------------------------------------------------------------
          // Mix key with DH(static, static)
          // ------------------------------------------------------------------
          final secretKey = await keyExchangeAlgorithm.sharedSecretKey(
            keyPair: localStaticKeyPair!,
            remotePublicKey: _remoteStaticPublicKey!,
          );
          final secretKeyBytes = await secretKey.extractBytes();
          await symmetricState.mixKey(secretKeyBytes);
          break;

        case NoiseMessageToken.psk:
          // ------------------------------------------------------------------
          // Mix key with psk
          // ------------------------------------------------------------------
          final presharedKey = await authenticator.presharedKey!.extract();
          if (presharedKey.bytes.length != 32) {
            throw StateError('onPresharedKey must return 32 bytes');
          }
          await symmetricState.mixKey(presharedKey.bytes);
          break;

        default:
          throw UnimplementedError();
      }
    }
    if (messageStart != message.length) {
      if (onPayload == null) {
        throw StateError('Message has payload, but `onPayload` is null');
      }
      var payload = message.skip(messageStart).toList(growable: false);
      payload = await symmetricState.cipherState.decrypt(payload);
      onPayload(payload);
    }

    // We are done with receiving.
    _isSending = true;

    // Are we expecting to send a message?
    if (_messagePatterns.isNotEmpty) {
      return null;
    }

    // No, this was the last message.
    return symmetricState.split(isInitiator: isInitiator!);
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  ///
  /// If this is the last handshake message, the method returns
  /// [HandshakeResult] and you can discard the handshake state.
  /// Otherwise returns null.
  Future<HandshakeResult?> writeMessage({
    required List<int> messageBuffer,
    List<int>? payload = const <int>[],
  }) async {
    if (_isSending == null) {
      throw StateError(
        'Handshake state is uninitialized',
      );
    }

    // Is it our turn to send?
    if (!_isSending!) {
      throw StateError(
        'Expecting to read a message (not write)',
      );
    }

    // Get the message pattern
    final messagePattern = _messagePatterns.removeFirst();

    // Handle each token in the message pattern
    final keyExchangeAlgorithm =
        protocol.noiseKeyExchangeAlgorithm.implementation;
    for (var token in messagePattern.tokens) {
      switch (token) {
        case NoiseMessageToken.e:
          // ------------------------------------------------------------------
          // Write local ephemeral public key.
          // ------------------------------------------------------------------
          // In the specification, ephemeral key should be generated at this
          // point, but we have already generated it at initialize().
          final publicKey = await localEphemeralKeyPair!.extractPublicKey();
          final bytes = publicKey.bytes;
          messageBuffer.addAll(bytes);
          await symmetricState.mixHash(bytes);
          break;

        case NoiseMessageToken.s:
          // ------------------------------------------------------------------
          // Write static public key (possibly encrypted).
          // ------------------------------------------------------------------
          final publicKey = await localStaticKeyPair!.extractPublicKey();
          var bytes = publicKey.bytes;
          bytes = await symmetricState.encryptAndHash(bytes);
          messageBuffer.addAll(bytes);
          break;

        case NoiseMessageToken.ee:
          // ------------------------------------------------------------------
          // Mix key with DH(ephemeral, ephemeral)
          // ------------------------------------------------------------------
          final secretKey = await keyExchangeAlgorithm.sharedSecretKey(
            keyPair: _localEphemeralKeyPair!,
            remotePublicKey: _remoteEphemeralPublicKey!,
          );
          final extractedSecretKey = await secretKey.extract();
          await symmetricState.mixKey(extractedSecretKey.bytes);
          break;

        case NoiseMessageToken.es:
          // ------------------------------------------------------------------
          // Mix key with DH(ephemeral, static)
          // ------------------------------------------------------------------
          SecretKey secretKey;
          if (isInitiator!) {
            secretKey = await keyExchangeAlgorithm.sharedSecretKey(
              keyPair: _localEphemeralKeyPair!,
              remotePublicKey: _remoteStaticPublicKey!,
            );
          } else {
            secretKey = await keyExchangeAlgorithm.sharedSecretKey(
              keyPair: localStaticKeyPair!,
              remotePublicKey: _remoteEphemeralPublicKey!,
            );
          }
          final extractedSecretKey = await secretKey.extract();
          await symmetricState.mixKey(extractedSecretKey.bytes);
          break;

        case NoiseMessageToken.se:
          // ------------------------------------------------------------------
          // Mix key with DH(static, ephemeral)
          // ------------------------------------------------------------------
          SecretKey secretKey;
          if (isInitiator!) {
            secretKey = await keyExchangeAlgorithm.sharedSecretKey(
              keyPair: localStaticKeyPair!,
              remotePublicKey: _remoteEphemeralPublicKey!,
            );
          } else {
            secretKey = await keyExchangeAlgorithm.sharedSecretKey(
              keyPair: _localEphemeralKeyPair!,
              remotePublicKey: _remoteStaticPublicKey!,
            );
          }
          final extractedSecretKey = await secretKey.extract();
          await symmetricState.mixKey(extractedSecretKey.bytes);
          break;

        case NoiseMessageToken.ss:
          // ------------------------------------------------------------------
          // Mix key with DH(static, static)
          // ------------------------------------------------------------------
          final secretKey = await keyExchangeAlgorithm.sharedSecretKey(
            keyPair: localStaticKeyPair!,
            remotePublicKey: _remoteStaticPublicKey!,
          );
          final extractedSecretKey = await secretKey.extract();
          await symmetricState.mixKey(extractedSecretKey.bytes);
          break;

        default:
          throw UnimplementedError();
      }
    }

    // Do we have a payload?
    if (payload!.isNotEmpty) {
      // Encrypt it
      payload = await symmetricState.cipherState.encrypt(payload);

      // Write it
      messageBuffer.addAll(payload);
    }

    // We are done with writing.
    _isSending = false;

    // Are we expecting to receive a message?
    if (_messagePatterns.isNotEmpty) {
      return null;
    }

    // No, this was the last message.
    return symmetricState.split(isInitiator: isInitiator!);
  }
}
