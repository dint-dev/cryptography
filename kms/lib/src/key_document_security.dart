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

import 'package:collection/collection.dart';

/// Describes how cryptographic key should be stored and used.
///
/// Examples:
///   * [KeyDocumentSecurity.highest] = Before cryptographic key can be used
///     (for digital signature, etc.), KMS should use biometric authentication
///     (such as fingerprint sensor or facial recognition) or password-based
///     authentication.
///   * [KeyDocumentSecurity.lowest] = Do not require any user interaction
///     before using the cryptographic key.
///
class KeyDocumentSecurity {
  /// List of supported authentication types in the order of preference.
  ///
  /// The KMS will choose the first authentication type that it supports
  /// (which may be [AuthenticationType.none]).
  final List<AuthenticationType> authenticationTypes;

  /// The highest security, the highest latency (usually many seconds),
  /// the request may be rejected by the user.
  static const KeyDocumentSecurity highest = KeyDocumentSecurity(
    authenticationTypes: [
      AuthenticationType.biometric,
      AuthenticationType.password,
      AuthenticationType.none,
    ],
  );

  /// The lowest security, the lowest latency (usually under a millisecond).
  static const KeyDocumentSecurity lowest = KeyDocumentSecurity(
    authenticationTypes: [
      AuthenticationType.none,
    ],
  );

  const KeyDocumentSecurity({
    this.authenticationTypes = const [AuthenticationType.none],
  }) : assert(authenticationTypes != null);

  /// Returns the first authentication type that is in the given set. Returns
  /// null if none matches.
  AuthenticationType getAuthenticationTypeFromSupported(
      Set<AuthenticationType> supported) {
    for (var item in authenticationTypes) {
      if (supported.contains(item)) {
        return item;
      }
    }
    return null;
  }

  @override
  int get hashCode =>
      const ListEquality<AuthenticationType>().hash(authenticationTypes);

  @override
  bool operator ==(other) =>
      other is KeyDocumentSecurity &&
      const ListEquality<AuthenticationType>()
          .equals(authenticationTypes, other.authenticationTypes);
}

/// Possible authentication types.
///
/// Currently these are:
///   * [AuthenticationType.biometric]
///   * [AuthenticationType.password]
///   * [AuthenticationType.none]
enum AuthenticationType {
  /// Biometric authentication such as fingerprint or facial recognition.
  biometric,

  /// Password.
  password,

  /// None.
  none,
}
