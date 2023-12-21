#[derive(Debug)]
pub enum Error {
    Certification,
    Decryption,
    Encryption,
    KeyExchange,
    KeyPair,
    SafetyNumber,
    Session,
    Verification,
}
