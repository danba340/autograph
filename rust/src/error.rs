#[derive(Debug)]
pub enum Error {
    Authentication,
    Certification,
    Decryption,
    Encryption,
    Initialization,
    KeyExchange,
    KeyPair,
    Session,
}
