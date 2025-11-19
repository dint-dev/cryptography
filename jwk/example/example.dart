import 'package:jwk/jwk.dart';

void main() {
  final jwk = Jwk.fromJson({
    'kty': 'RSA',
    'n': '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86'
        'E3K3zV9zzTtmCGR2DhKNuNSZp2dHfvGZ1WLdqt4yW8c5C4OAI8kPpG6VfT1GXvQ'
        'r2Xi0VH6hM0axqaz0alG5jFT8H4qerLz6QvUOSgf3LT6rdzjvXSKyUsF86RLWvu'
        'oXFQrXeGsy3O3px4hi2TGMHhzwQK1YkYp6fEnY/zYI25G4b8iKXg2sr1m9T25Z4'
        'eOVBzEoU3pmMxMqYz1K0p0xX4mjU7vsfgQCIp9Zc3T8f7vfxn9pkOe7wOZyNxL'
        'g',
    'e': 'AQAB',
    'alg': 'RS256',
  });
  print('kty: ${jwk.kty}');
  print('n: ${jwk.n}');
  print('e: ${jwk.e}');
}
