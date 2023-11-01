import Clibautograph
import Foundation

public typealias Bytes = [UInt8]

public class KeyPair {
  public var privateKey: Bytes
  public var publicKey: Bytes

  init(privateKey: Bytes, publicKey: Bytes) {
    self.privateKey = privateKey
    self.publicKey = publicKey
  }
}

public class KeyPairResult {
  public var success: Bool
  public var keyPair: KeyPair

  init(success: Bool, keyPair: KeyPair) {
    self.success = success
    self.keyPair = keyPair
  }
}

public class SignResult {
  public var success: Bool
  public var signature: Bytes

  init(success: Bool, signature: Bytes) {
    self.success = success
    self.signature = signature
  }
}

public class DecryptionResult {
  public var success: Bool
  public var index: UInt64
  public var data: Bytes

  init(success: Bool, index: UInt64, data: Bytes) {
    self.success = success
    self.index = index
    self.data = data
  }
}

internal class DecryptionState {
  var decryptIndex: Bytes
  var messageIndex: Bytes
  var plaintextSize: Bytes
  var secretKey: Bytes
  var skippedKeys: Bytes

  init(secretKey: inout Bytes) {
    decryptIndex = createIndexBytes()
    messageIndex = createIndexBytes()
    plaintextSize = createSizeBytes()
    self.secretKey = secretKey
    skippedKeys = createSkippedKeysBytes()
  }

  func readMessageIndex() -> UInt64 {
    autograph_read_uint64(&messageIndex)
  }

  func readPlaintextSize() -> Int {
    Int(autograph_read_uint32(&plaintextSize))
  }

  func resizeData(_ plaintext: inout Bytes) -> Bytes {
    Array(plaintext[0 ..< readPlaintextSize()])
  }
}

public class EncryptionResult {
  public var success: Bool
  public var index: UInt64
  public var message: Bytes

  init(success: Bool, index: UInt64, message: Bytes) {
    self.success = success
    self.index = index
    self.message = message
  }
}

internal class EncryptionState {
  var messageIndex: Bytes
  var secretKey: Bytes

  init(secretKey: inout Bytes) {
    messageIndex = createIndexBytes()
    self.secretKey = secretKey
  }

  func readMessageIndex() -> UInt64 {
    autograph_read_uint64(&messageIndex)
  }
}

public typealias DecryptFunction = (Bytes) -> DecryptionResult
public typealias EncryptFunction = (Bytes) -> EncryptionResult
public typealias SignDataFunction = (Bytes) -> SignResult
public typealias SignIdentityFunction = () -> SignResult
public typealias VerifyDataFunction = (Bytes, Bytes) -> Bool
public typealias VerifyIdentityFunction = (Bytes) -> Bool

public class SafetyNumberResult {
  public var success: Bool
  public var safetyNumber: Bytes

  init(success: Bool, safetyNumber: Bytes) {
    self.success = success
    self.safetyNumber = safetyNumber
  }
}

public typealias SafetyNumberFunction = (Bytes) -> SafetyNumberResult

public class Session {
  public var encrypt: EncryptFunction
  public var decrypt: DecryptFunction
  public var signData: SignDataFunction
  public var signIdentity: SignIdentityFunction
  public var verifyData: VerifyDataFunction
  public var verifyIdentity: VerifyIdentityFunction

  init(
    decrypt: @escaping DecryptFunction,
    encrypt: @escaping EncryptFunction,
    signData: @escaping SignDataFunction,
    signIdentity: @escaping SignIdentityFunction,
    verifyData: @escaping VerifyDataFunction,
    verifyIdentity: @escaping VerifyIdentityFunction
  ) {
    self.decrypt = decrypt
    self.encrypt = encrypt
    self.signData = signData
    self.signIdentity = signIdentity
    self.verifyData = verifyData
    self.verifyIdentity = verifyIdentity
  }
}

public class KeyExchangeVerificationResult {
  public var success: Bool
  public var session: Session

  init(success: Bool, session: Session) {
    self.success = success
    self.session = session
  }
}

public typealias KeyExchangeVerificationFunction = (Bytes)
  -> KeyExchangeVerificationResult

public class KeyExchange {
  public var handshake: Bytes
  public var verify: KeyExchangeVerificationFunction

  init(handshake: Bytes, verify: @escaping KeyExchangeVerificationFunction) {
    self.handshake = handshake
    self.verify = verify
  }
}

public class KeyExchangeResult {
  public var success: Bool
  public var keyExchange: KeyExchange

  init(success: Bool, keyExchange: KeyExchange) {
    self.success = success
    self.keyExchange = keyExchange
  }
}

public typealias KeyExchangeFunction = (inout KeyPair, Bytes, Bytes)
  -> KeyExchangeResult

public typealias SignFunction = (Bytes) -> SignResult

public class Party {
  public var calculateSafetyNumber: SafetyNumberFunction
  public var performKeyExchange: KeyExchangeFunction

  init(
    calculateSafetyNumber: @escaping SafetyNumberFunction,
    performKeyExchange: @escaping KeyExchangeFunction
  ) {
    self.calculateSafetyNumber = calculateSafetyNumber
    self.performKeyExchange = performKeyExchange
  }
}
