use argon2::{self, Config};

pub struct ARGON2 {}
impl ARGON2 {
    pub fn new() -> ARGON2 {
        ARGON2 {}
    }

    pub fn argon2(val: String, config: Config) -> String {
        argon2::hash_encoded(val.as_bytes(), b"", &config).expect("Could not hash value!")
    }

    pub fn argon2_salt(val: String, salt: String, config: Config) -> String {
        argon2::hash_encoded(val.as_bytes(), salt.as_bytes(), &config)
            .expect("Could not hash value!")
    }
}
