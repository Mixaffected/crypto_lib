use crate::password::Password;
use sha256;

pub struct SHA256 {}
// SHA256
impl SHA256 {
    pub fn new() -> SHA256 {
        SHA256 {}
    }

    pub fn sha256(val: &String) -> String {
        sha256::digest(val)
    }

    pub fn sha256_salt(val: String, salt: String) -> String {
        let salted = Password::new(val, salt);

        sha256::digest(salted.salted)
    }
}
