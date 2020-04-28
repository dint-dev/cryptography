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
  final NoiseAuthenticator authenticator;

  /// Symmetric state.
  @visibleForTesting
  final SymmetricState symmetricState;

  /// Optional rekey function.
  final FutureOr<SecretKey> Function(SecretKey secretKey) rekey;

  // Remaining message patterns for this handshake.
  Queue<MessagePattern> _messagePatterns;

  // Are we an initiator or responder?
  bool _isInitiator;

  // Is it our turn to send or receive?
  bool _isSending;

  // Local ephemeral key pair.
  KeyPair _localEphemeralKeyPair;

  /// Optional local static key pair. Some handshake patterns require this.
  ///
  /// The default value is obtained from [authenticator].
  KeyPair localStaticKeyPair;

  /// Optional pre-shared key. Some handshake patterns require this.
  ///
  /// The default value is obtained from [authenticator].
  SecretKey presharedKey;

  // Remote ephemeral public key.
  PublicKey _remoteEphemeralPublicKey;

  // Remote static public key.
  PublicKey _remoteStaticPublicKey;

  HandshakeState({
    @required this.protocol,
    @required this.authenticator,
    this.rekey,
  })  : assert(protocol != null),
        assert(authenticator != null),
        symmetricState = SymmetricState(protocol: protocol) {
    final publicKeyLength = protocol.publicKeyLength;
    if (authenticator.localStaticKeyPair != null &&
        authenticator.localStaticKeyPair.publicKey.bytes.length !=
            publicKeyLength) {
      throw ArgumentError(
        'local static public key must have $publicKeyLength bytes',
      );
    }
    if (authenticator.remoteStaticPublicKey != null &&
        authenticator.remoteStaticPublicKey.bytes.length != publicKeyLength) {
      throw ArgumentError.value(
        'remote static public key must have $publicKeyLength bytes',
      );
    }
    final presharedKey = authenticator.presharedKey;
    if (presharedKey == null &&
        authenticator.onRemotePublicKey == null &&
        protocol.handshakePattern.usesPresharedKey) {
      throw ArgumentError(
        'pattern uses pre-shared key, thus authenticator must have either presharedKey or onRemotePublicKey',
      );
    }
    if (presharedKey != null && presharedKey.extractSync().length != 32) {
      throw ArgumentError('pre-shared key must have 32 bytes');
    }
  }

  /// Whether the local party is initiator.
  bool get isInitiator => _isInitiator;

  /// Local ephemeral key pair.
  KeyPair get localEphemeralKeyPair => _localEphemeralKeyPair;

  /// Remote static ephemeral public key.
  PublicKey get remoteEphemeralPublicKey => _remoteEphemeralPublicKey;

  /// Remote static public key.
  PublicKey get remoteStaticPublicKey => _remoteStaticPublicKey;

  /// See the [specification](https://noiseprotocol.org/noise.html).
  void initialize({
    @required bool isInitiator,
    List<int> prologue = const <int>[],
    KeyPair localEphemeralKeyPair,
  }) async {
    ArgumentError.checkNotNull(isInitiator);
    ArgumentError.checkNotNull(prologue);
    if (protocol.handshakePattern.messagePatterns
        .any((p) => p.tokens.contains(MessageToken.e))) {
      localEphemeralKeyPair ??=
          protocol.keyExchangeAlgorithm.implementation.newKeyPairSync();
    }

    //
    // Initialize
    //
    _messagePatterns = Queue<MessagePattern>.from(
      protocol.handshakePattern.messagePatterns,
    );
    _isInitiator = isInitiator;

    // Initialize symmetric state
    await symmetricState.initializeSymmetric();

    // Set keys
    localStaticKeyPair = authenticator.localStaticKeyPair;
    _localEphemeralKeyPair = localEphemeralKeyPair;
    _remoteStaticPublicKey = authenticator.remoteStaticPublicKey;
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
        await symmetricState.mixHash(localStaticKeyPair.publicKey.bytes);
      }
      if (handshakePattern.isResponderKnown) {
        await symmetricState.mixHash(remoteStaticPublicKey.bytes);
      }
    } else {
      //
      // This is responder
      //
      if (handshakePattern.isInitiatorKnown) {
        await symmetricState.mixHash(remoteStaticPublicKey.bytes);
      }
      if (handshakePattern.isResponderKnown) {
        await symmetricState.mixHash(localStaticKeyPair.publicKey.bytes);
      }
    }

    _isSending = isInitiator;
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  ///
  /// If this is the last handshake message, the method returns
  /// [HandshakeResult] and you can discard the handshake state.
  /// Otherwise returns null.
  Future<HandshakeResult> readMessage({
    @required List<int> message,
    List<int> payloadBuffer,
    void Function(List<int> payload) onPayload,
  }) async {
    if (_isSending == null) {
      throw StateError(
        'Handshake state is uninitialized',
      );
    }

    // Is it our turn to read?
    if (_isSending) {
      throw StateError(
        'Expecting to write a message (not read)',
      );
    }

    // Get the message pattern
    final messagePattern = _messagePatterns.removeFirst();

    // Handle each token in the message pattern
    final keyExchangeAlgorithm = protocol.keyExchangeAlgorithm.implementation;
    var messageStart = 0;
    for (var token in messagePattern.tokens) {
      switch (token) {
        case MessageToken.e:
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
          _remoteEphemeralPublicKey = PublicKey(publicKey);

          // Call mixHash
          await symmetricState.mixHash(publicKey);
          break;

        case MessageToken.s:
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
            _remoteStaticPublicKey = PublicKey(bytes);
          } else {
            // The bytes are encrypted
            final n = publicKeyLength + 16;
            var bytes = message.sublist(
              messageStart,
              messageStart + n,
            );
            messageStart += n;
            bytes = await symmetricState.decryptAndHash(bytes);
            _remoteStaticPublicKey = PublicKey(bytes);
          }
          final onReceivedPublicKey = authenticator.onRemotePublicKey;
          if (onReceivedPublicKey != null) {
            await onReceivedPublicKey(this);
          }
          break;

        case MessageToken.ee:
          // ------------------------------------------------------------------
          // Mix key with DH(ephemeral, ephemeral)
          // ------------------------------------------------------------------
          final secretKey = await keyExchangeAlgorithm.sharedSecret(
            localPrivateKey: _localEphemeralKeyPair.privateKey,
            remotePublicKey: _remoteEphemeralPublicKey,
          );
          await symmetricState.mixKey(secretKey.extractSync());
          break;

        case MessageToken.es:
          // ------------------------------------------------------------------
          // Mix key with DH(ephemeral, static)
          // ------------------------------------------------------------------
          SecretKey secretKey;
          if (isInitiator) {
            secretKey = await keyExchangeAlgorithm.sharedSecret(
              localPrivateKey: _localEphemeralKeyPair.privateKey,
              remotePublicKey: _remoteStaticPublicKey,
            );
          } else {
            secretKey = await keyExchangeAlgorithm.sharedSecret(
              localPrivateKey: localStaticKeyPair.privateKey,
              remotePublicKey: _remoteEphemeralPublicKey,
            );
          }
          await symmetricState.mixKey(
            secretKey.extractSync(),
          );
          break;

        case MessageToken.se:
          // ------------------------------------------------------------------
          // Mix key with DH(static, ephemeral)
          // ------------------------------------------------------------------
          SecretKey secretKey;
          if (isInitiator) {
            secretKey = await keyExchangeAlgorithm.sharedSecret(
              localPrivateKey: localStaticKeyPair.privateKey,
              remotePublicKey: _remoteEphemeralPublicKey,
            );
          } else {
            secretKey = await keyExchangeAlgorithm.sharedSecret(
              localPrivateKey: localEphemeralKeyPair.privateKey,
              remotePublicKey: _remoteStaticPublicKey,
            );
          }
          await symmetricState.mixKey(
            secretKey.extractSync(),
          );
          break;

        case MessageToken.ss:
          // ------------------------------------------------------------------
          // Mix key with DH(static, static)
          // ------------------------------------------------------------------
          final secretKey = await keyExchangeAlgorithm.sharedSecret(
            localPrivateKey: localStaticKeyPair.privateKey,
            remotePublicKey: _remoteStaticPublicKey,
          );
          await symmetricState.mixKey(secretKey.extractSync());
          break;

        case MessageToken.psk:
          // ------------------------------------------------------------------
          // Mix key with psk
          // ------------------------------------------------------------------
          final presharedKey = await authenticator.presharedKey.extractSync();
          if (presharedKey.length != 32) {
            throw StateError('onPresharedKey must return 32 bytes');
          }
          await symmetricState.mixKey(presharedKey);
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
    return symmetricState.split(isInitiator: isInitiator);
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  ///
  /// If this is the last handshake message, the method returns
  /// [HandshakeResult] and you can discard the handshake state.
  /// Otherwise returns null.
  Future<HandshakeResult> writeMessage({
    @required List<int> messageBuffer,
    List<int> payload = const <int>[],
  }) async {
    if (_isSending == null) {
      throw StateError(
        'Handshake state is uninitialized',
      );
    }

    // Is it our turn to send?
    if (!_isSending) {
      throw StateError(
        'Expecting to read a message (not write)',
      );
    }

    // Get the message pattern
    final messagePattern = _messagePatterns.removeFirst();

    // Handle each token in the message pattern
    final keyExchangeAlgorithm = protocol.keyExchangeAlgorithm.implementation;
    for (var token in messagePattern.tokens) {
      switch (token) {
        case MessageToken.e:
          // ------------------------------------------------------------------
          // Write local ephemeral public key.
          // ------------------------------------------------------------------
          // In the specification, ephemeral key should be generated at this
          // point, but we have already generated it at initialize().
          final bytes = localEphemeralKeyPair.publicKey.bytes;
          messageBuffer.addAll(bytes);
          await symmetricState.mixHash(bytes);
          break;

        case MessageToken.s:
          // ------------------------------------------------------------------
          // Write static public key (possibly encrypted).
          // ------------------------------------------------------------------
          var bytes = localStaticKeyPair.publicKey.bytes;
          bytes = await symmetricState.encryptAndHash(bytes);
          messageBuffer.addAll(bytes);
          break;

        case MessageToken.ee:
          // ------------------------------------------------------------------
          // Mix key with DH(ephemeral, ephemeral)
          // ------------------------------------------------------------------
          final secretKey = await keyExchangeAlgorithm.sharedSecret(
            localPrivateKey: _localEphemeralKeyPair.privateKey,
            remotePublicKey: _remoteEphemeralPublicKey,
          );
          await symmetricState.mixKey(secretKey.extractSync());
          break;

        case MessageToken.es:
          // ------------------------------------------------------------------
          // Mix key with DH(ephemeral, static)
          // ------------------------------------------------------------------
          SecretKey secretKey;
          if (isInitiator) {
            secretKey = await keyExchangeAlgorithm.sharedSecret(
              localPrivateKey: _localEphemeralKeyPair.privateKey,
              remotePublicKey: _remoteStaticPublicKey,
            );
          } else {
            secretKey = await keyExchangeAlgorithm.sharedSecret(
              localPrivateKey: localStaticKeyPair.privateKey,
              remotePublicKey: _remoteEphemeralPublicKey,
            );
          }
          await symmetricState.mixKey(secretKey.extractSync());
          break;

        case MessageToken.se:
          // ------------------------------------------------------------------
          // Mix key with DH(static, ephemeral)
          // ------------------------------------------------------------------
          SecretKey secretKey;
          if (isInitiator) {
            secretKey = await keyExchangeAlgorithm.sharedSecret(
              localPrivateKey: localStaticKeyPair.privateKey,
              remotePublicKey: _remoteEphemeralPublicKey,
            );
          } else {
            secretKey = await keyExchangeAlgorithm.sharedSecret(
              localPrivateKey: _localEphemeralKeyPair.privateKey,
              remotePublicKey: _remoteStaticPublicKey,
            );
          }
          await symmetricState.mixKey(secretKey.extractSync());
          break;

        case MessageToken.ss:
          // ------------------------------------------------------------------
          // Mix key with DH(static, static)
          // ------------------------------------------------------------------
          final secretKey = await keyExchangeAlgorithm.sharedSecret(
            localPrivateKey: localStaticKeyPair.privateKey,
            remotePublicKey: _remoteStaticPublicKey,
          );
          await symmetricState.mixKey(secretKey.extractSync());
          break;

        default:
          throw UnimplementedError();
      }
    }

    // Do we have a payload?
    if (payload.isNotEmpty) {
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
    return symmetricState.split(isInitiator: isInitiator);
  }
}
