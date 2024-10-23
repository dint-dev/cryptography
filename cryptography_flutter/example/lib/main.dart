// Copyright 2019-2020 Gohilla.
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

import 'dart:convert';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const MaterialApp(
    title: 'Cryptography demo',
    home: CipherPage(),
  ));
}

List<int> _fromHex(String s) {
  s = s.replaceAll(' ', '').replaceAll('\n', '');
  return List<int>.generate(s.length ~/ 2, (i) {
    var byteInHex = s.substring(2 * i, 2 * i + 2);
    if (byteInHex.startsWith('0')) {
      byteInHex = byteInHex.substring(1);
    }
    final result = int.tryParse(byteInHex, radix: 16);
    if (result == null) {
      throw StateError('Not valid hexadecimal bytes: $s');
    }
    return result;
  });
}

String _toHex(List<int> bytes) {
  return bytes.map((e) => e.toRadixString(16).padLeft(2, '0')).join(' ');
}

class CipherPage extends StatefulWidget {
  const CipherPage({Key? key}) : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return _CipherPageState();
  }
}

class _CipherPageState extends State<CipherPage> {
  static final _aesCbc128 = AesCbc.with128bits(macAlgorithm: Hmac.sha256());
  static final _aesCtr128 = AesCtr.with128bits(macAlgorithm: Hmac.sha256());
  static final _aesGcm128 = AesGcm.with128bits();
  static final _aesGcm256 = AesGcm.with256bits();
  static final _chacha20Poly1305 = Chacha20.poly1305Aead();
  static final _xchacha20Poly1305 = Xchacha20.poly1305Aead();

  Cipher _cipher = _aesGcm128;
  final _secretKeyController = TextEditingController();
  final _nonceController = TextEditingController();

  List<int> _clearText = [];
  final _cipherTextController = TextEditingController();
  final _macController = TextEditingController();
  Object? _error;
  String _decryptedText = '';

  @override
  Widget build(BuildContext context) {
    final error = _error;
    final cipher = _cipher;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: Container(
            constraints: const BoxConstraints(maxWidth: 500),
            padding: const EdgeInsets.all(20),
            child: ListView(
              children: [
                InputDecorator(
                  decoration: const InputDecoration(labelText: 'Cipher'),
                  child: DropdownButton<Cipher>(
                    value: _cipher,
                    onChanged: (newValue) {
                      setState(() {
                        _cipher = newValue ?? _aesGcm128;
                        _encrypt();
                      });
                    },
                    items: [
                      DropdownMenuItem(
                        value: _aesCbc128,
                        child: const Text('AES-CBC (128-bits) + HMAC-SHA256'),
                      ),
                      DropdownMenuItem(
                        value: _aesCtr128,
                        child: const Text('AES-CTR (128-bits) + HMAC-SHA256'),
                      ),
                      DropdownMenuItem(
                        value: _aesGcm128,
                        child: const Text('AES-GCM (128-bits)'),
                      ),
                      DropdownMenuItem(
                        value: _aesGcm256,
                        child: const Text('AES-GCM (256-bits)'),
                      ),
                      DropdownMenuItem(
                        value: _chacha20Poly1305,
                        child: const Text('ChaCha20 + Poly1305'),
                      ),
                      DropdownMenuItem(
                        value: _xchacha20Poly1305,
                        child: const Text('XChaCha20 + Poly1305'),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 10),
                Text('Class: ${cipher.runtimeType}'),
                const SizedBox(height: 10),
                Row(children: [
                  Expanded(
                    child: TextField(
                      controller: _secretKeyController,
                      onChanged: (value) {
                        _encrypt();
                      },
                      minLines: 1,
                      maxLines: 16,
                      enableInteractiveSelection: true,
                      decoration: InputDecoration(
                          labelText:
                              'Secret key  (${_cipher.secretKeyLength} bytes)'),
                    ),
                  ),
                  ElevatedButton(
                    onPressed: () async {
                      final secretKey = await _cipher.newSecretKey();
                      final bytes = await secretKey.extractBytes();
                      _secretKeyController.text = _toHex(bytes);
                      await _encrypt();
                    },
                    child: const Text('Generate'),
                  ),
                ]),
                const SizedBox(height: 10),
                Row(children: [
                  Expanded(
                    child: TextField(
                      controller: _nonceController,
                      onChanged: (value) {
                        _encrypt();
                      },
                      minLines: 1,
                      maxLines: 16,
                      enableInteractiveSelection: true,
                      decoration: InputDecoration(
                          labelText: 'Nonce (${_cipher.nonceLength} bytes)'),
                    ),
                  ),
                  ElevatedButton(
                    onPressed: () async {
                      _nonceController.text = _toHex(_cipher.newNonce());
                      await _encrypt();
                    },
                    child: const Text('Generate'),
                  ),
                ]),
                const SizedBox(height: 30),
                const Text('Encrypt'),
                TextField(
                  onChanged: (newValue) {
                    try {
                      _clearText = utf8.encode(newValue);
                      _encrypt();
                    } catch (error) {
                      setState(() {
                        _error = error;
                      });
                    }
                  },
                  minLines: 1,
                  maxLines: 16,
                  enableInteractiveSelection: true,
                  decoration:
                      const InputDecoration(labelText: 'Cleartext (text)'),
                ),
                const SizedBox(height: 10),
                const Text('Decrypted Text'),
                const SizedBox(height: 5),
                Container(
                  color: Colors.grey.shade500,
                  padding: const EdgeInsets.all(4),
                  child: Text(_decryptedText),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: _cipherTextController,
                  minLines: 1,
                  maxLines: 16,
                  enableInteractiveSelection: true,
                  decoration:
                      const InputDecoration(labelText: 'Ciphertext (hex)'),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: _macController,
                  minLines: 1,
                  maxLines: 16,
                  enableInteractiveSelection: true,
                  decoration: const InputDecoration(
                      labelText: 'Message Authentication Code (MAC)'),
                ),
                const SizedBox(height: 10),
                if (error != null) Text(error.toString()),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _encrypt() async {
    try {
      final cipher = _cipher;
      final secretBox = await cipher.encrypt(
        _clearText,
        secretKey: SecretKeyData(
          _fromHex(_secretKeyController.text),
        ),
        nonce: _fromHex(_nonceController.text),
      );
      _cipherTextController.text = _toHex(secretBox.cipherText);
      _macController.text = _toHex(secretBox.mac.bytes);

      _decrypt();

      setState(() {
        _error = null;
      });
    } catch (error, stackTrace) {
      setState(() {
        _error = '$error\n\n$stackTrace';
        _cipherTextController.text = '';
        _macController.text = '';
      });
      return;
    }
  }

  Future<void> _decrypt() async {
    final cipher = _cipher;

    _decryptedText = utf8.decode(await cipher.decrypt(
      SecretBox(
        _fromHex(_cipherTextController.text),
        nonce: _fromHex(_nonceController.text),
        mac: Mac(_fromHex(_macController.text)),
      ),
      secretKey: SecretKeyData(
        _fromHex(_secretKeyController.text),
      ),
    ));
  }
}
