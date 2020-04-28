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

/// Our non-standard implementation for Noise connections.
class NoiseConnection extends Stream<List<int>> implements Sink<List<int>> {
  final NoiseProtocol protocol;
  final NoiseAuthenticator authenticator;
  final HandshakeState _handshakeState;
  Stream<List<int>> _stream;
  Sink<List<int>> _sink;
  Future<void> _sinkAvailableFuture;
  final Queue<List<int>> _queuedMessages = Queue<List<int>>();
  CipherState _decryptingState;
  CipherState _encryptingState;

  NoiseConnection({
    @required this.protocol,
    @required this.authenticator,
    @required Stream<List<int>> stream,
    @required Sink<List<int>> sink,
  })  : _sink = sink,
        _stream = stream,
        _handshakeState = HandshakeState(
          protocol: protocol,
          authenticator: authenticator,
        );

  /// Enables using TCP sockets and other continuous byte streams by prefixing
  /// each message with a 32-bit message length.
  NoiseConnection.messagePrefixing({
    @required this.protocol,
    @required this.authenticator,
    @required Stream<List<int>> stream,
    @required Sink<List<int>> sink,
  })  : _sink = _PrefixMessageSink(sink),
        _stream = stream.transform(const _PrefixMessageStreamTransformer()),
        _handshakeState = HandshakeState(
          protocol: protocol,
          authenticator: authenticator,
        );

  @override
  void add(List<int> message) {
    if (_sink == null) {
      throw StateError('The sink is closed');
    }
    final handshakeState = _handshakeState;
    if (handshakeState == null) {
      _queuedMessages.add(message);
      return;
    }
    _sinkAvailableFuture =
        (_sinkAvailableFuture ?? Future<void>.value()).then((_) {
      return _encryptingState.encrypt(message);
    }).then((encryptedMessage) {
      _sink.add(encryptedMessage);
    });
  }

  @override
  void close() {
    if (_sink == null) {
      return;
    }
    _sink.close();
    _sink = null;
    _sinkAvailableFuture = null;
  }

  @override
  StreamSubscription<List<int>> listen(void Function(List<int> event) onData,
      {Function onError, void Function() onDone, bool cancelOnError}) {
    // Transform stream
    final subscription = _transformStream(_stream).listen(
      onData,
      onError: onError,
      onDone: onDone,
      cancelOnError: cancelOnError,
    );

    // We don't need the reference anymore
    _stream = null;

    // Initiator?
    if (_handshakeState.isInitiator) {
      _initiate();
    }

    return subscription;
  }

  Future<void> _handleResult(HandshakeResult result) async {
    _encryptingState = result.encryptingState;
    _decryptingState = result.decryptingState;
    while (_queuedMessages.isNotEmpty) {
      final message = _queuedMessages.removeFirst();
      final encryptedMessage = await _encryptingState.encrypt(
        message,
      );
      _sink.add(encryptedMessage);
    }
  }

  void _initiate() {
    final buffer = Uint8Buffer();
    _handshakeState.writeMessage(messageBuffer: buffer).then((result) {
      _sink.add(buffer);
      if (result != null) {
        _handleResult(result);
      }
    });
  }

  Stream<List<int>> _transformStream(Stream<List<int>> stream) async* {
    try {
      await for (var message in _stream) {
        // Have we already done handshake?
        if (_handshakeState == null) {
          final decryptedMessage = await _decryptingState.decrypt(
            message,
          );
          yield (decryptedMessage);
          continue;
        }

        // Pass it to the handshake state
        final result = await _handshakeState.readMessage(
          message: message,
        );
        if (result == null) {
          // We need to reply
          final buffer = Uint8Buffer();
          await _handshakeState.writeMessage(
            messageBuffer: buffer,
          );
          _sink.add(buffer);
          return;
        }
        await _handleResult(result);
      }
    } catch (e) {
      // Ensure that we don't end in some unsafe state.
      close();
      rethrow;
    }
  }
}

class _PrefixMessageSink implements Sink<List<int>> {
  final Sink<List<int>> sink;

  _PrefixMessageSink(this.sink);

  @override
  void add(List<int> data) {
    final length = data.length;

    // Validate length
    if (0xFFFFFFFF & length != length) {
      throw ArgumentError('Too long message');
    }

    // Write big endian 32-bit length
    sink.add(<int>[
      0xFF & (length >> 24),
      0xFF & (length >> 16),
      0xFF & (length >> 8),
      0xFF & length,
    ]);

    // Write data
    sink.add(data);
  }

  @override
  void close() {
    sink.close();
  }
}

/// Cuts a stream into messages.
class _PrefixMessageStreamTransformer
    extends StreamTransformerBase<List<int>, List<int>> {
  const _PrefixMessageStreamTransformer();

  @override
  Stream<List<int>> bind(Stream<List<int>> stream) {
    Uint8Buffer buffer;
    return stream.expand((chunk) {
      // Write chunk to the buffer
      buffer ??= Uint8Buffer();
      buffer.addAll(chunk);

      // List of decoded messages
      final output = <List<int>>[];

      // While we have at least 4 bytes left
      var start = 0;
      while (buffer.length - start >= 4) {
        // Message has big endian 32-bit length prefix
        final messageLength = buffer[start] << 24 |
            buffer[start + 1] << 16 |
            buffer[start + 2] << 8 |
            buffer[start + 3];

        // Is the message incomplete?
        if (buffer.length - start < 4 + messageLength) {
          break;
        }

        // Return message
        final message = buffer.sublist(start, start + messageLength);
        output.add(message);
        start += 4 + messageLength;
      }

      // Move forward in buffer
      buffer = Uint8Buffer()..addAll(buffer.skip(start));

      return output;
    });
  }
}
