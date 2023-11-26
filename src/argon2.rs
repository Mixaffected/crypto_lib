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

pub struct ARGON2ConfWizard {}
impl<'a> ARGON2ConfWizard {
    pub fn new(hash_length: u32, lanes: u32, mem_cost: u32, time_cost: u32) -> Config<'a> {
        Config {
            ad: &[],
            hash_length,
            lanes,
            mem_cost,
            secret: &[],
            time_cost,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
        }
    }
}
