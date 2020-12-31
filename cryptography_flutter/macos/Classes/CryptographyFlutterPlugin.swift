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

import Cocoa
import CryptoKit
import FlutterMacOS

public class SwiftCryptographyFlutterPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "cryptography_flutter", binaryMessenger: registrar.messenger())
        let instance = SwiftCryptographyFlutterPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        if #available(iOS 13.0, OSX 15.0, tvOS 13.0, watchOS 6.0, *) {
            switch call.method {
            case "ping":
                result("ok")
                return

            case "encrypt":
                let args = call.arguments as! [String: Any];
                let algorithm = args["algo"] as! String
                let clearText = [UInt8]((args["clearText"] as! FlutterStandardTypedData).data)
                let secretKey = [UInt8]((args["secretKey"] as! FlutterStandardTypedData).data)
                let nonce = [UInt8]((args["nonce"] as! FlutterStandardTypedData).data)
                encrypt(call:call, result:result, algorithm:algorithm, clearText:clearText, secretKey:secretKey, nonce:nonce)
                return

            case "decrypt":
                let args = call.arguments as! [String: Any];
                let algorithm = args["algo"] as! String
                let cipherText = [UInt8]((args["cipherText"] as! FlutterStandardTypedData).data)
                let secretKey = [UInt8]((args["secretKey"] as! FlutterStandardTypedData).data)
                let nonce = [UInt8]((args["nonce"] as! FlutterStandardTypedData).data)
                let mac = [UInt8]((args["mac"] as! FlutterStandardTypedData).data)
                decrypt(call:call, result:result, algorithm:algorithm, cipherText:cipherText, secretKey:secretKey, nonce:nonce, mac:mac)
                return

            default:
                result("Unsupported method: \(call.method)")
                return
            }
        } else {
            result("old_operating_system")
        }
    }

    func encrypt(call: FlutterMethodCall, result: @escaping FlutterResult, algorithm: String, clearText: [UInt8], secretKey: [UInt8], nonce: [UInt8]) -> Void {
        if #available(iOS 13.0, OSX 15.0, tvOS 13.0, watchOS 6.0, *) {
            let symmetricKey = SymmetricKey(data: secretKey)
            switch algorithm {
            case "AesGcm":
                let sealedBox = try! AES.GCM.seal(
                    clearText,
                    using: symmetricKey,
                    nonce: AES.GCM.Nonce(data: nonce))
                result([
                    "cipherText": FlutterStandardTypedData(bytes: sealedBox.ciphertext),
                    "mac": FlutterStandardTypedData(bytes: sealedBox.tag),
                ])
                return

            case "Chacha20.poly1305Aead":
                let sealedBox = try! ChaChaPoly.seal(
                    clearText,
                    using: symmetricKey,
                    nonce: ChaChaPoly.Nonce(data: nonce))
                result([
                    "cipherText": FlutterStandardTypedData(bytes: sealedBox.ciphertext),
                    "mac": FlutterStandardTypedData(bytes: sealedBox.tag),
                ])
                return

            default:
                break
            }
        }
        result(["error": "Unsupported algorithm: \(algorithm)"])
    }

    func decrypt(call: FlutterMethodCall, result: @escaping FlutterResult, algorithm: String, cipherText: [UInt8], secretKey: [UInt8], nonce: [UInt8], mac: [UInt8]) -> Void {
        if #available(iOS 13.0, OSX 15.0, tvOS 13.0, watchOS 6.0, *) {
            let symmetricKey = SymmetricKey(data: secretKey)
            switch algorithm {
            case "AesGcm":
                let sealedBox = try! AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: nonce),
                    ciphertext: cipherText,
                    tag: mac)
                let clearText = try! AES.GCM.open(sealedBox, using:symmetricKey)
                result(["clearText": FlutterStandardTypedData(bytes: clearText)])
                return

            case "Chacha20.poly1305Aead":
                let sealedBox = try! ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonce),
                    ciphertext: cipherText,
                    tag: mac)
                let clearText = try! ChaChaPoly.open(sealedBox, using:symmetricKey)
                result(["clearText": FlutterStandardTypedData(bytes: clearText)])
                return

            default:
                break
            }
        }
        result(["error": "Unsupported algorithm: \(algorithm)"])
    }
}