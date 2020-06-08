import Flutter
import UIKit
import CryptoKit

public class SwiftCryptographyFlutterPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "cryptography_flutter", binaryMessenger: registrar.messenger())
    let instance = SwiftCryptographyFlutterPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    if call.method == "ping" {
      result("ok")
      return
    }

    let args = call.arguments as! [String: Any];
    if #available(iOS 13.0, OSX 15.0, tvOS 13.0, watchOS 6.0, *) {
    switch call.method {
      case "aes_gcm_encrypt":
        let input = (args["data"] as! FlutterStandardTypedData).data
        let symmetricKeyBytes = (args["key"] as! FlutterStandardTypedData).data
        let symmetricKey = SymmetricKey(data: symmetricKeyBytes)
        let nonceBytes = (args["nonce"] as! FlutterStandardTypedData).data
        let nonce = try! AES.GCM.Nonce(data: nonceBytes)
        let sealedBox = try! AES.GCM.seal(input, using:symmetricKey, nonce:nonce)
        let response: [String: Any] = [
          "cipherText": sealedBox.ciphertext,
          "tag": sealedBox.tag,
        ]
        result(response)

      case "aes_gcm_decrypt":
        let input = (args["data"] as! FlutterStandardTypedData).data
        let symmetricKeyBytes = (args["key"] as! FlutterStandardTypedData).data
        let symmetricKey = SymmetricKey(data: symmetricKeyBytes)
        let nonceBytes = (args["nonce"] as! FlutterStandardTypedData).data
        let nonce = try! AES.GCM.Nonce(data: nonceBytes)
        let tag = (args["tag"] as! FlutterStandardTypedData).data
        let sealedBox = try! AES.GCM.SealedBox(nonce:nonce, ciphertext:input, tag:tag)
        let output = try! AES.GCM.open(sealedBox, using:symmetricKey)
        result(output)

      case "chacha20_poly1305_encrypt":
        let input = (args["data"] as! FlutterStandardTypedData).data
        let symmetricKeyBytes = (args["key"] as! FlutterStandardTypedData).data
        let symmetricKey = SymmetricKey(data: symmetricKeyBytes)
        let nonceBytes = (args["nonce"] as! FlutterStandardTypedData).data
        let nonce = try! ChaChaPoly.Nonce(data: nonceBytes)
        let sealedBox = try! ChaChaPoly.seal(input, using:symmetricKey, nonce:nonce)
        let response: [String: Any] = [
          "cipherText": sealedBox.ciphertext,
          "tag": sealedBox.tag,
        ]
        result(response)

      case "chacha20_poly1305_decrypt":
        let input = (args["data"] as! FlutterStandardTypedData).data
        let symmetricKeyBytes = (args["key"] as! FlutterStandardTypedData).data
        let symmetricKey = SymmetricKey(data: symmetricKeyBytes)
        let nonceBytes = (args["nonce"] as! FlutterStandardTypedData).data
        let nonce = try! ChaChaPoly.Nonce(data: nonceBytes)
        let tag = (args["tag"] as! FlutterStandardTypedData).data
        let sealedBox = try! ChaChaPoly.SealedBox(nonce:nonce, ciphertext:input, tag:tag)
        let output = try! ChaChaPoly.open(sealedBox, using:symmetricKey)
        result(output)

      default:
        result("Unsupported method: \(call.method)")
      }
    } else {
      result("old_operating_system")
    }
  }
}
