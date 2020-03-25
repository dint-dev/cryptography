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

import 'dart:math';

import 'package:meta/meta.dart';

/// A key stored by [Kms].
class KmsKey {
  /// Key ring ID.
  final String keyRingId;

  /// Key ID in the key ring.
  final String id;

  const KmsKey({
    @required this.keyRingId,
    @required this.id,
  })  : assert(keyRingId != null),
        assert(id != null);

  @override
  int get hashCode => id.hashCode ^ keyRingId.hashCode;

  @override
  bool operator ==(other) =>
      other is KmsKey && id == other.id && keyRingId == other.keyRingId;

  @override
  String toString() => 'CryptoKey(keyRingId:"$keyRingId", id:"$id")';

  static KmsKey random({String keyRingId}) {
    keyRingId ??= 'default';
    final id = _randomString(16);
    return KmsKey(keyRingId: keyRingId, id: id);
  }

  static String _randomString(int length) {
    final random = Random.secure();
    final sb = StringBuffer();
    for (; length > 0; length--) {
      sb.write(random.nextInt(256).toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }
}

class KmsKeyQuery {
  final String collectionId;
  const KmsKeyQuery({this.collectionId});

  bool matches(KmsKey kmsKey) {
    final collectionId = this.collectionId;
    if (collectionId != null) {
      final argumentCollectionId = kmsKey.keyRingId;
      if (argumentCollectionId == null ||
          argumentCollectionId != collectionId) {
        return false;
      }
    }
    return true;
  }

  @override
  bool operator ==(other) =>
      other is KmsKeyQuery && collectionId == other.collectionId;

  @override
  int get hashCode => collectionId.hashCode;
}
