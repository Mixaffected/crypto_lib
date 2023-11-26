use argon2::{self, Config, Variant, Version};
use rand::{self, rngs::ThreadRng};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::LineEnding,
    Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use sha256;
use std::{
    fs::{self, File},
    io::{Read, Write},
    os,
    path::Path,
};
use std::{io, thread};

pub struct Salter {
    pub val: String,
    pub salt: String,
    pub salted: String,
}
impl Salter {
    pub fn new(val: String, salt: String) -> Salter {
        let mut salted = val.clone();
        let prep_salt = Salter::prepare_salt(&salt);
        salted.push_str(&prep_salt);

        Salter { val, salt, salted }
    }

    fn prepare_salt(salt: &String) -> String {
        let mut salt = salt.clone();

        salt.insert(0, ':');

        salt
    }
}

pub struct ARGON2 {}
// ARGON2
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
        let salted = Salter::new(val, salt);

        sha256::digest(salted.salted)
    }
}

pub struct RSA {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}
impl RSA {
    pub fn new() -> RSA {
        let mut rng = RSA::get_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, 4096).expect("Could not generate private key!");
        let public_key = RsaPublicKey::from(&private_key);

        RSA {
            private_key,
            public_key,
        }
    }

    pub fn from_save(
        priv_file_path: Option<&str>,
        pub_file_path: Option<&str>,
    ) -> Result<RSA, io::Error> {
        let priv_file_path = match priv_file_path {
            Some(priv_file_path) => priv_file_path,
            None => "private.key",
        };

        let pub_file_path = match pub_file_path {
            Some(pub_file_path) => pub_file_path,
            None => "public.key",
        };

        let priv_file = File::open(priv_file_path);
        let mut priv_file = match priv_file {
            Ok(priv_file) => priv_file,
            Err(e) => return Result::Err(e),
        };

        let mut priv_key_pem = String::new();
        let result = priv_file.read_to_string(&mut priv_key_pem);
        match result {
            Ok(_) => (),
            Err(e) => return Result::Err(e),
        }

        let priv_key = rsa::RsaPrivateKey::from_pkcs1_pem(&priv_key_pem);
        let priv_key = match priv_key {
            Ok(priv_key) => priv_key,
            Err(e) => panic!("{}", e),
        };

        let pub_file = File::open(pub_file_path);
        let mut pub_file = match pub_file {
            Ok(pub_file) => pub_file,
            Err(e) => return Result::Err(e),
        };

        let mut pub_key_pem = String::new();
        let result = pub_file.read_to_string(&mut pub_key_pem);
        match result {
            Ok(_) => (),
            Err(e) => return Result::Err(e),
        };

        let pub_key = rsa::RsaPublicKey::from_pkcs1_pem(&pub_key_pem);
        let pub_key = match pub_key {
            Ok(pub_key) => pub_key,
            Err(e) => panic!("{}", e),
        };

        Result::Ok(RSA {
            private_key: priv_key,
            public_key: pub_key,
        })
    }

    pub fn save_keys(
        &self,
        priv_file_path: Option<&str>,
        pub_file_path: Option<&str>,
    ) -> Result<(), io::Error> {
        let priv_file_path = match priv_file_path {
            Some(priv_file_path) => priv_file_path,
            None => "private.key",
        };

        let pub_file_path = match pub_file_path {
            Some(pub_file_path) => pub_file_path,
            None => "public.key",
        };

        let priv_file = File::create(priv_file_path);
        let mut priv_file = match priv_file {
            Ok(priv_file) => priv_file,
            Err(e) => return Result::Err(e),
        };

        let priv_pem = RSA::get_private_key(&self);

        let result = priv_file.write_all(priv_pem.as_bytes());
        match result {
            Ok(_) => (),
            Err(e) => return Result::Err(e),
        }

        let pub_file = File::create(pub_file_path);
        let mut pub_file = match pub_file {
            Ok(pub_file) => pub_file,
            Err(e) => return Result::Err(e),
        };

        let pub_pem = RSA::get_public_key(&self);

        let result = pub_file.write_all(pub_pem.as_bytes());
        match result {
            Ok(_) => (),
            Err(e) => return Result::Err(e),
        }

        Result::Ok(())
    }

    pub fn get_public_key(&self) -> String {
        self.public_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("Could not get public pem!")
    }

    pub fn get_private_key(&self) -> String {
        self.private_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("Could not get private pem!")
            .to_string()
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut rng = RSA::get_rng();
        self.public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .expect("Could not encrypt!")
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.private_key
            .decrypt(Pkcs1v15Encrypt, data)
            .expect("Could not decript!")
    }

    fn get_rng() -> ThreadRng {
        rand::thread_rng()
    }
}
