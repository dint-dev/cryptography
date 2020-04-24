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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// _Ed25519_ ([RFC 8032](https://tools.ietf.org/html/rfc8032)) signature
/// algorithm.
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   // Only the private key holder can sign
///   final keyPair = await algorithm.newKeyPair();
///   final signature = await ed25519.sign(
///     message,
///     keyPair,
///   );
///
///   // Anyone can verify the signature
///   final isVerified = await ed25519.verify(
///     message,
///     signature,
///   );
/// }
/// ```
const SignatureAlgorithm ed25519 = _Ed25519();

class _Ed25519 extends SignatureAlgorithm {
  static final _constantP = BigInt.two.pow(255) - BigInt.from(19);

  static final _constantD = BigInt.from(-121665) *
      _modpInv(BigInt.from(121666)).remainder(_constantP);

  static final _constantQ = BigInt.two.pow(252) +
      BigInt.parse('27742317777372353535851937790883648493');

  static final _modp_sqrt_m1 = BigInt.two
      .modPow((_constantP - BigInt.one) ~/ BigInt.from(4), _constantP);

  static final _g_y = BigInt.from(4) * _modpInv(BigInt.from(5)) % _constantP;

  static final _g_x = _recoverX(_g_y, BigInt.zero);

  static final _constantG = _Point(
    _g_x,
    _g_y,
    BigInt.one,
    _g_x * _g_y % _constantP,
  );

  static final _byteMask = BigInt.from(255);

  const _Ed25519();

  @override
  String get name => 'ed25519';

  @override
  int get publicKeyLength => 32;

  @override
  KeyPair newKeyPairSync() {
    final privateKey = PrivateKey.randomBytes(32);
    final publicKey = PublicKey(
      _secretToPublic(privateKey.extractSync()),
    );
    return KeyPair(
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  @override
  Signature signSync(List<int> msg, KeyPair keyPair) {
    final expanded = _secretExpand(keyPair.privateKey.extractSync());
    final a = _pointCompress(_pointMul(expanded.a, _constantG));
    final r = _sha512_modq(<int>[...expanded.prefix, ...msg]);
    final pointR = _pointMul(r, _constantG);
    final pointRCompressed = _pointCompress(pointR);
    final h = _sha512_modq(<int>[...pointRCompressed, ...a, ...msg]);
    final s = (r + h * expanded.a) % _constantQ;
    final result = <int>[...pointRCompressed, ..._bytesFromBigInt(s)];
    return Signature(result, publicKey: keyPair.publicKey);
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    final publicKeyBytes = signature.publicKey.bytes;
    final signatureBytes = signature.bytes;
    if (publicKeyBytes.length != 32) {
      throw ArgumentError.value(signature);
    }
    if (publicKeyBytes.length != 32) {
      throw ArgumentError.value(signature);
    }
    if (signatureBytes.length != 64) {
      throw StateError('Bad signature length');
    }
    final a = _pointDecompress(publicKeyBytes);
    if (a == null) {
      return false;
    }
    final rS = signatureBytes.sublist(0, 32);
    final r = _pointDecompress(rS);
    if (r == null) {
      return false;
    }
    final s = _bytesToBigInt(signatureBytes.sublist(32));
    if (s >= _constantQ) {
      return false;
    }
    final h = _sha512_modq([...rS, ...publicKeyBytes, ...input]);
    final sB = _pointMul(s, _constantG);
    final hA = _pointMul(h, a);
    return _pointEqual(sB, _pointAdd(r, hA));
  }

  static BigInt _bytesToBigInt(List<int> bytes) {
    var result = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      result = (result << 8) + BigInt.from(bytes[i]);
    }
    return result;
  }

  static List<int> _bytesFromBigInt(BigInt value) {
    final result = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      result[i] = (_byteMask & value).toInt();
      value = value >> 8;
    }
    return result;
  }

  static BigInt _modpInv(BigInt x) {
    return x.modPow(_constantP - BigInt.two, _constantP);
  }

  static _Point _pointAdd(_Point p, _Point q) {
    final a = (p.v1 - p.v0) * (q.v1 - q.v0) % _constantP;
    final b = (p.v1 + p.v0) * (q.v1 + q.v0) % _constantP;
    final c = BigInt.two * p.v3 * q.v3 * _constantD % _constantP;
    final d = BigInt.two * p.v2 * q.v2 % _constantP;
    final e = b - a;
    final f = d - c;
    final g = d + c;
    final h = b + a;
    return _Point(
      e * f,
      g * h,
      f * g,
      e * h,
    );
  }

  static List<int> _pointCompress(_Point p) {
    final zinv = _modpInv(p.v2);
    final x = p.v0 * zinv % _constantP;
    final y = p.v1 * zinv % _constantP;
    return _bytesFromBigInt(y | ((x & BigInt.one) << 255));
  }

  static _Point _pointDecompress(List<int> s) {
    if (s.length != 32) {
      throw Exception('Invalid input length for decompression: ${s.length}');
    }
    var y = _bytesToBigInt(s);
    final sign = y >> 255;
    y &= (BigInt.one << 255) - BigInt.one;
    var x = _recoverX(y, sign);
    if (x == null) {
      return null;
    } else {
      return _Point(
        x,
        y,
        BigInt.one,
        x * y % _constantP,
      );
    }
  }

  static bool _pointEqual(_Point p, _Point q) {
    if ((p.v0 * q.v2 - q.v0 * p.v2).remainder(_constantP) != BigInt.zero) {
      return false;
    }
    if ((p.v1 * q.v2 - q.v1 * p.v2).remainder(_constantP) != BigInt.zero) {
      return false;
    }
    return true;
  }

  static _Point _pointMul(BigInt s, _Point pointP) {
    var q = _Point(
      BigInt.zero,
      BigInt.one,
      BigInt.one,
      BigInt.zero,
    );
    while (s > BigInt.zero) {
      if (s & BigInt.one == BigInt.one) {
        q = _pointAdd(q, pointP);
      }
      pointP = _pointAdd(pointP, pointP);
      s >>= 1;
    }
    return q;
  }

  static BigInt _recoverX(BigInt y, BigInt sign) {
    if (y >= _constantP) {
      return null;
    }
    var x2 = (y * y - BigInt.one) * _modpInv(_constantD * y * y + BigInt.one);
    if (x2 == BigInt.zero) {
      if (sign == BigInt.one) {
        return null;
      } else {
        return BigInt.zero;
      }
    }
    var x = x2.modPow(
      (_constantP + BigInt.from(3)) ~/ BigInt.from(8),
      _constantP,
    );
    if ((x * x - x2) % _constantP != BigInt.zero) {
      x = x * _modp_sqrt_m1 % _constantP;
    }
    if ((x * x - x2) % _constantP != BigInt.zero) {
      return null;
    }
    if ((x & BigInt.one) != sign) {
      x = _constantP - x;
    }
    return x;
  }

  static _ExpandedSecret _secretExpand(List<int> secret) {
    if (secret.length != 32) {
      throw Exception('Bad size of private key');
    }
    final hash = sha512.hashSync(secret).bytes;
    var a = _bytesToBigInt(hash.sublist(0, 32));
    a &= (BigInt.one << 254) - BigInt.from(8);
    a |= (BigInt.one << 254);
    return _ExpandedSecret(a, hash.sublist(32));
  }

  static List<int> _secretToPublic(List<int> secret) {
    final expanded = _secretExpand(secret);
    return _pointCompress(_pointMul(expanded.a, _constantG));
  }

  static BigInt _sha512_modq(List<int> s) {
    return _bytesToBigInt(sha512.hashSync(s).bytes) % _constantQ;
  }
}

class _ExpandedSecret {
  final BigInt a;
  final List<int> prefix;
  _ExpandedSecret(this.a, this.prefix);
}

class _Point {
  final BigInt v0;
  final BigInt v1;
  final BigInt v2;
  final BigInt v3;
  _Point(this.v0, this.v1, this.v2, this.v3);
}
