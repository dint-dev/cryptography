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

/// Authentication information for [HandshakeState].
///
/// The required information depends on the [NoiseHandshakePattern] that you
/// use.
class NoiseAuthenticationParameters {
  /// Optional fixed local static secret key pair.
  final SimpleKeyPair? localStaticKeyPair;

  /// Optional fixed remote static key pair.
  final SimplePublicKey? remoteStaticPublicKey;

  /// Optional fixed preshared key.
  final SecretKeyData? presharedKey;

  /// An optional function that rejects state or changes it depending when
  /// remote public key is received.
  final FutureOr<void> Function(HandshakeState state)?
      onValidateRemotePublicKey;

  const NoiseAuthenticationParameters({
    this.localStaticKeyPair,
    this.remoteStaticPublicKey,
    this.presharedKey,
    this.onValidateRemotePublicKey,
  });
}
