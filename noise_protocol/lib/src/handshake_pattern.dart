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

/// A handshake pattern defines pre-existing knowledge and instructions for
/// performing the handshake.
class HandshakePattern {
  /// _IK_ pattern.
  static const HandshakePattern ik = HandshakePattern(
    name: 'IK',
    isInitiatorKnown: false,
    isResponderKnown: true,
    messagePatterns: [
      MessagePattern([
        MessageToken.e,
        MessageToken.ee,
        MessageToken.s,
        MessageToken.se,
      ]),
      MessagePattern([
        MessageToken.e,
        MessageToken.es,
      ]),
    ],
  );

  /// _K_ pattern.
  static const HandshakePattern k = HandshakePattern(
    name: 'K',
    isInitiatorKnown: true,
    isResponderKnown: true,
    messagePatterns: [
      MessagePattern([
        MessageToken.e,
        MessageToken.es,
        MessageToken.ss,
      ]),
    ],
  );

  /// _KK_ pattern.
  static const HandshakePattern kk = HandshakePattern(
    name: 'KK',
    isInitiatorKnown: true,
    isResponderKnown: true,
    messagePatterns: [
      MessagePattern([
        MessageToken.e,
        MessageToken.es,
        MessageToken.ss,
      ]),
      MessagePattern([
        MessageToken.e,
        MessageToken.ee,
        MessageToken.es,
      ]),
    ],
  );

  /// _N_ pattern.
  static const HandshakePattern n = HandshakePattern(
    name: 'N',
    isInitiatorKnown: false,
    isResponderKnown: true,
    messagePatterns: [
      MessagePattern([
        MessageToken.e,
        MessageToken.es,
      ]),
    ],
  );

  /// _NK_ pattern.
  static const HandshakePattern nk = HandshakePattern(
    name: 'NK',
    isInitiatorKnown: false,
    isResponderKnown: true,
    messagePatterns: [
      MessagePattern([
        MessageToken.e,
        MessageToken.es,
      ]),
      MessagePattern([
        MessageToken.e,
        MessageToken.ee,
      ]),
    ],
  );

  /// _NK1_ pattern.
  static const HandshakePattern nk1 = HandshakePattern(
    name: 'NK1',
    isInitiatorKnown: false,
    isResponderKnown: true,
    messagePatterns: [
      MessagePattern([
        MessageToken.e,
      ]),
      MessagePattern([
        MessageToken.e,
        MessageToken.ee,
        MessageToken.es,
      ]),
    ],
  );

  /// _X_ pattern.
  static const HandshakePattern x = HandshakePattern(
    name: 'X',
    isInitiatorKnown: false,
    isResponderKnown: true,
    messagePatterns: [
      MessagePattern([
        MessageToken.e,
        MessageToken.es,
        MessageToken.s,
        MessageToken.ss,
      ]),
    ],
  );

  /// _XX_ pattern.
  static const HandshakePattern xx = HandshakePattern(
    name: 'XX',
    isInitiatorKnown: false,
    isResponderKnown: false,
    messagePatterns: [
      MessagePattern([
        MessageToken.e,
      ]),
      MessagePattern([
        MessageToken.e,
        MessageToken.ee,
        MessageToken.s,
        MessageToken.es,
      ]),
      MessagePattern([
        MessageToken.s,
        MessageToken.se,
      ]),
    ],
  );

  /// _X1X_ pattern.
  static const HandshakePattern x1x = HandshakePattern(
    name: 'X1X',
    isInitiatorKnown: false,
    isResponderKnown: false,
    messagePatterns: [
      MessagePattern([
        MessageToken.e,
      ]),
      MessagePattern([
        MessageToken.e,
        MessageToken.ee,
        MessageToken.s,
        MessageToken.es,
      ]),
      MessagePattern([
        MessageToken.s,
      ]),
      MessagePattern([
        MessageToken.se,
      ]),
    ],
  );

  /// Name of the handshake pattern.
  final String name;

  /// Does the responder know initiator's static public key?
  final bool isInitiatorKnown;

  /// Does the initiator know responder's static public key?
  final bool isResponderKnown;

  /// List of message patterns. The first one is sent by initiator, the second
  /// by the responder, and so on.
  final List<MessagePattern> messagePatterns;

  const HandshakePattern({
    @required this.name,
    @required this.isInitiatorKnown,
    @required this.isResponderKnown,
    @required this.messagePatterns,
  })  : assert(name != null),
        assert(isInitiatorKnown != null),
        assert(isResponderKnown != null),
        assert(messagePatterns != null);

  /// Tells whether the pattern has a [MessageToken.psk] token.
  bool get usesPresharedKey {
    return messagePatterns.any((p) => p.tokens.contains(MessageToken.psk));
  }

  @override
  int get hashCode =>
      const ListEquality<MessagePattern>().hash(messagePatterns);

  @override
  bool operator ==(other) =>
      other is HandshakePattern &&
      name == other.name &&
      isInitiatorKnown == other.isInitiatorKnown &&
      isResponderKnown == other.isResponderKnown &&
      const ListEquality<MessagePattern>()
          .equals(messagePatterns, other.messagePatterns);
}

class MessagePattern {
  final List<MessageToken> tokens;

  const MessagePattern(this.tokens);

  @override
  int get hashCode => const ListEquality<MessageToken>().hash(tokens);

  @override
  bool operator ==(other) =>
      other is MessagePattern &&
      const ListEquality<MessageToken>().equals(tokens, other.tokens);
}

/// A message token.
enum MessageToken {
  e,
  s,
  ee,
  es,
  se,
  ss,
  psk,
}
