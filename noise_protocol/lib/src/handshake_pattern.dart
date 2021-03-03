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
class NoiseHandshakePattern {
  /// _IK_ pattern.
  static const NoiseHandshakePattern ik = NoiseHandshakePattern(
    name: 'IK',
    isInitiatorKnown: false,
    isResponderKnown: true,
    noiseMessagePatterns: [
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.ee,
        NoiseMessageToken.s,
        NoiseMessageToken.se,
      ]),
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.es,
      ]),
    ],
  );

  /// _K_ pattern.
  static const NoiseHandshakePattern k = NoiseHandshakePattern(
    name: 'K',
    isInitiatorKnown: true,
    isResponderKnown: true,
    noiseMessagePatterns: [
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.es,
        NoiseMessageToken.ss,
      ]),
    ],
  );

  /// _KK_ pattern.
  static const NoiseHandshakePattern kk = NoiseHandshakePattern(
    name: 'KK',
    isInitiatorKnown: true,
    isResponderKnown: true,
    noiseMessagePatterns: [
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.es,
        NoiseMessageToken.ss,
      ]),
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.ee,
        NoiseMessageToken.es,
      ]),
    ],
  );

  /// _N_ pattern.
  static const NoiseHandshakePattern n = NoiseHandshakePattern(
    name: 'N',
    isInitiatorKnown: false,
    isResponderKnown: true,
    noiseMessagePatterns: [
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.es,
      ]),
    ],
  );

  /// _NK_ pattern.
  static const NoiseHandshakePattern nk = NoiseHandshakePattern(
    name: 'NK',
    isInitiatorKnown: false,
    isResponderKnown: true,
    noiseMessagePatterns: [
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.es,
      ]),
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.ee,
      ]),
    ],
  );

  /// _NK1_ pattern.
  static const NoiseHandshakePattern nk1 = NoiseHandshakePattern(
    name: 'NK1',
    isInitiatorKnown: false,
    isResponderKnown: true,
    noiseMessagePatterns: [
      NoiseMessagePattern([
        NoiseMessageToken.e,
      ]),
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.ee,
        NoiseMessageToken.es,
      ]),
    ],
  );

  /// _X_ pattern.
  static const NoiseHandshakePattern x = NoiseHandshakePattern(
    name: 'X',
    isInitiatorKnown: false,
    isResponderKnown: true,
    noiseMessagePatterns: [
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.es,
        NoiseMessageToken.s,
        NoiseMessageToken.ss,
      ]),
    ],
  );

  /// _XX_ pattern.
  static const NoiseHandshakePattern xx = NoiseHandshakePattern(
    name: 'XX',
    isInitiatorKnown: false,
    isResponderKnown: false,
    noiseMessagePatterns: [
      NoiseMessagePattern([
        NoiseMessageToken.e,
      ]),
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.ee,
        NoiseMessageToken.s,
        NoiseMessageToken.es,
      ]),
      NoiseMessagePattern([
        NoiseMessageToken.s,
        NoiseMessageToken.se,
      ]),
    ],
  );

  /// _X1X_ pattern.
  static const NoiseHandshakePattern x1x = NoiseHandshakePattern(
    name: 'X1X',
    isInitiatorKnown: false,
    isResponderKnown: false,
    noiseMessagePatterns: [
      NoiseMessagePattern([
        NoiseMessageToken.e,
      ]),
      NoiseMessagePattern([
        NoiseMessageToken.e,
        NoiseMessageToken.ee,
        NoiseMessageToken.s,
        NoiseMessageToken.es,
      ]),
      NoiseMessagePattern([
        NoiseMessageToken.s,
      ]),
      NoiseMessagePattern([
        NoiseMessageToken.se,
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
  final List<NoiseMessagePattern> noiseMessagePatterns;

  const NoiseHandshakePattern({
    required this.name,
    required this.isInitiatorKnown,
    required this.isResponderKnown,
    required this.noiseMessagePatterns,
  });

  /// Tells whether the pattern has a [NoiseMessageToken.psk] token.
  bool get usesPresharedKey {
    return noiseMessagePatterns
        .any((p) => p.tokens.contains(NoiseMessageToken.psk));
  }

  @override
  int get hashCode =>
      const ListEquality<NoiseMessagePattern>().hash(noiseMessagePatterns);

  @override
  bool operator ==(other) =>
      other is NoiseHandshakePattern &&
      name == other.name &&
      isInitiatorKnown == other.isInitiatorKnown &&
      isResponderKnown == other.isResponderKnown &&
      const ListEquality<NoiseMessagePattern>()
          .equals(noiseMessagePatterns, other.noiseMessagePatterns);

  @override
  String toString() => 'NoiseHandshakePattern.${name.toLowerCase()}';
}
