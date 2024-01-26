use crate::{
    constants::{INFO, SALT_SIZE},
    external::hkdf,
    types::{Ikm, Okm, Salt},
};

pub fn kdf(okm: &mut Okm, ikm: &Ikm) -> bool {
    let salt: Salt = [0; SALT_SIZE];
    hkdf(okm, ikm, &salt, &INFO)
}
