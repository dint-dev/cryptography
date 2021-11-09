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

import CryptoKit
import Flutter
import UIKit

public class SwiftCryptographyFlutterPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "cryptography_flutter", binaryMessenger: registrar.messenger())
        let instance = SwiftCryptographyFlutterPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "encrypt":
            propagateError(result: result){
                try self.encrypt(call:call, result:result)
            }

        case "decrypt":
            propagateError(result: result){
                try self.decrypt(call:call, result:result)
            }
            
        case "Ecdsa.newKeyPair":
            propagateError(result: result){
                try self.ecdsaNewKeyPair(call:call, result:result)
            }
            
        case "Ecdsa.sign":
            propagateError(result: result){
                try self.ecdsaSign(call:call, result:result)
            }
            
        case "Ecdsa.verify":
            propagateError(result: result){
                try self.ecdsaVerify(call:call, result:result)
            }
            
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    func propagateError<T>(result: @escaping FlutterResult, fn: @escaping () throws -> T ){
        do{
            try fn()
        }catch let error as NSError {
            result(FlutterError(code: "CATCHED_ERROR", message:"\(error.domain), \(error.code), \(error.description)", details: nil))
        }catch {
            result(FlutterError(code: "CATCHED_ERROR", message:"\(error)", details: nil))
        }
    }
    
    private func encrypt(call: FlutterMethodCall, result: @escaping FlutterResult) throws{
        let args = call.arguments as! [String: Any];
        let algorithm = args["algo"] as! String
        let clearText = [UInt8]((args["clearText"] as! FlutterStandardTypedData).data)
        let secretKey = [UInt8]((args["secretKey"] as! FlutterStandardTypedData).data)
        let nonce = [UInt8]((args["nonce"] as! FlutterStandardTypedData).data)
        if #available(iOS 13.0, OSX 15.0, tvOS 13.0, watchOS 6.0, *) {
            switch algorithm {
            case "AesGcm":
                let symmetricKey = SymmetricKey(data: secretKey)
                let sealedBox = try AES.GCM.seal(
                    clearText,
                    using: symmetricKey,
                    nonce: AES.GCM.Nonce(data: nonce))
                result([
                    "cipherText": FlutterStandardTypedData(bytes: sealedBox.ciphertext),
                    "mac": FlutterStandardTypedData(bytes: sealedBox.tag),
                ])
                return
                
            case "Chacha20.poly1305Aead":
                let symmetricKey = SymmetricKey(data: secretKey)
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
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }
    
    private func decrypt(call: FlutterMethodCall, result: @escaping FlutterResult) throws{
        let args = call.arguments as! [String: Any];
        let algorithm = args["algo"] as! String
        let cipherText = [UInt8]((args["cipherText"] as! FlutterStandardTypedData).data)
        let secretKey = [UInt8]((args["secretKey"] as! FlutterStandardTypedData).data)
        let nonce = [UInt8]((args["nonce"] as! FlutterStandardTypedData).data)
        let mac = [UInt8]((args["mac"] as! FlutterStandardTypedData).data)
        if #available(iOS 13.0, OSX 15.0, tvOS 13.0, watchOS 6.0, *) {
            switch algorithm {
            case "AesGcm":
                let symmetricKey = SymmetricKey(data: secretKey)
                let sealedBox = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: nonce),
                    ciphertext: cipherText,
                    tag: mac)
                let clearText = try AES.GCM.open(sealedBox, using:symmetricKey)
                result([
                    "clearText": FlutterStandardTypedData(bytes: clearText),
                ])
                return
                
            case "Chacha20.poly1305Aead":
                let symmetricKey = SymmetricKey(data: secretKey)
                let sealedBox = try! ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonce),
                    ciphertext: cipherText,
                    tag: mac)
                let clearText = try! ChaChaPoly.open(sealedBox, using:symmetricKey)
                result([
                    "clearText": FlutterStandardTypedData(bytes: clearText),
                ])
                return
                
            default:
                break
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }
    
    private func ecdsaNewKeyPair(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        let args = call.arguments as! [String: Any];
        let curve = args["curve"] as! String
        let seed = [UInt8]((args["seed"] as! FlutterStandardTypedData).data)
        if #available(iOS 13.0, OSX 15.0, tvOS 13.0, watchOS 6.0, *) {
            switch curve {
            case "P-256":
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: seed)
                let publicKey = privateKey.publicKey
                result([
                    "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                    "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
                    "publicKeyCompact": FlutterStandardTypedData(bytes: publicKey.compactRepresentation!),
                ])
                return
            case "P-384":
                let privateKey = try P384.Signing.PrivateKey(rawRepresentation: seed)
                let publicKey = privateKey.publicKey
                result([
                    "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                    "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
                    "publicKeyCompact": FlutterStandardTypedData(bytes: publicKey.compactRepresentation!),
                ])
                return
            case "P-521":
                let privateKey = try P521.Signing.PrivateKey(rawRepresentation: seed)
                let publicKey = privateKey.publicKey
                result([
                    "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                    "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
                    "publicKeyCompact": FlutterStandardTypedData(bytes: publicKey.compactRepresentation!),
                ])
                return
            default:
                break;
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }
    
    
    private func ecdsaSign(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 15.0, tvOS 13.0, watchOS 6.0, *) {
            let args = call.arguments as! [String: Any];
            let curve = args["curve"] as! String
            let data = [UInt8]((args["data"] as! FlutterStandardTypedData).data)
            let privateKeyBytes = [UInt8]((args["privateKey"] as! FlutterStandardTypedData).data)
            switch curve {
            case "P-256":
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
                let signature = try privateKey.signature(for: data)
                result([
                    "signature": FlutterStandardTypedData(bytes: signature.rawRepresentation),
                ])
                return
            case "P-384":
                let privateKey = try P384.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
                let signature = try privateKey.signature(for: data)
                result([
                    "signature": FlutterStandardTypedData(bytes: signature.rawRepresentation),
                ])
                return
            case "P-521":
                let privateKey = try P521.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
                let signature = try privateKey.signature(for: data)
                result([
                    "signature": FlutterStandardTypedData(bytes: signature.rawRepresentation),
                ])
                return
            default:
                break;
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }
    
    private func ecdsaVerify(call: FlutterMethodCall, result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 15.0, tvOS 13.0, watchOS 6.0, *) {
            let args = call.arguments as! [String: Any];
            let curve = args["curve"] as! String
            let data = [UInt8]((args["data"] as! FlutterStandardTypedData).data)
            let signatureBytes = [UInt8]((args["signature"] as! FlutterStandardTypedData).data)
            let publicKeyBytes = [UInt8]((args["publicKey"] as! FlutterStandardTypedData).data)
            var ok = false
            switch curve {
            case "P-256":
                let publicKey = try P256.Signing.PublicKey(rawRepresentation: publicKeyBytes)
                let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                ok = publicKey.isValidSignature(signature, for: data)
                result([
                    "ok": ok,
                ])
                return
            case "P-384":
                let publicKey = try P384.Signing.PublicKey(rawRepresentation: publicKeyBytes)
                let signature = try P384.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                ok = publicKey.isValidSignature(signature, for: data)
                result([
                    "ok": ok,
                ])
                return
            case "P-521":
                let publicKey = try P521.Signing.PublicKey(rawRepresentation: publicKeyBytes)
                let signature = try P521.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                ok = publicKey.isValidSignature(signature, for: data)
                result([
                    "ok": ok,
                ])
                return
            default:
                break
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }
}
