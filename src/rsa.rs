use rand::rngs::ThreadRng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::LineEnding,
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use std::{
    fs::File,
    io::{self, Read, Write},
};

pub struct RSA {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}
impl RSA {
    pub fn new(bit_size: Option<usize>) -> RSA {
        // bit_size standart = 2048
        let bit_size = match bit_size {
            Some(bit_size) => bit_size,
            None => 2048,
        };

        // RSA
        let mut rng = RSA::get_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, bit_size).expect("Could not generate private key!");
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

        let priv_pem = RSA::get_private_key_pem(&self);

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

        let pub_pem = RSA::get_public_key_pem(&self);

        let result = pub_file.write_all(pub_pem.as_bytes());
        match result {
            Ok(_) => (),
            Err(e) => return Result::Err(e),
        }

        Result::Ok(())
    }

    pub fn get_public_key_pem(&self) -> String {
        self.public_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("Could not get public pem!")
    }

    pub fn get_private_key_pem(&self) -> String {
        self.private_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("Could not get private pem!")
            .to_string()
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut rng = RSA::get_rng();
        self.public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .expect("Could not encrypt data!")
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.private_key
            .decrypt(Pkcs1v15Encrypt, data)
            .expect("Could not decript data!")
    }

    fn get_rng() -> ThreadRng {
        rand::thread_rng()
    }
}

pub struct RSAConnection {
    public_key: RsaPublicKey,
}
impl RSAConnection {
    pub fn new(pub_key_pem: &str) -> RSAConnection {
        let pub_key = RsaPublicKey::from_pkcs1_pem(pub_key_pem)
            .expect("Could not create public key from pem!");

        RSAConnection {
            public_key: pub_key,
        }
    }

    pub fn from_file_pem(path: &str) -> RSAConnection {
        let mut pub_file = File::open(path).expect("Could not open public key pem file!");

        let mut pub_key_pem = String::new();
        pub_file
            .read_to_string(&mut pub_key_pem)
            .expect("Could not read public pem file!");

        let public_key = RsaPublicKey::from_pkcs1_pem(&pub_key_pem).expect("Could not get ");

        RSAConnection { public_key }
    }

    pub fn save_connection_pem(&self, file_path: &str) -> Result<(), io::Error> {
        let connection_file = File::create(file_path);
        let mut connection_file = match connection_file {
            Ok(connection_file) => connection_file,
            Err(e) => return Result::Err(e),
        };

        let connection_key_pem = self
            .public_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("Could not get pem from connection key!");
        let result = connection_file.write_all(connection_key_pem.as_bytes());
        match result {
            Ok(_) => return Result::Ok(()),
            Err(e) => return Result::Err(e),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut rng = RSAConnection::get_rng();
        self.public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .expect("Could not encrypt data!")
    }

    fn get_rng() -> ThreadRng {
        rand::thread_rng()
    }
}
