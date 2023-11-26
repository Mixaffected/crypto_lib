pub struct Password {
    pub password: String,
    pub salt: String,
    pub salted: String,
}
impl Password {
    pub fn new(password: String, salt: String) -> Password {
        let mut pw = password.clone();
        let prep_salt = Password::prepare_salt(&salt);
        pw.push_str(&prep_salt);

        Password {
            password: password,
            salt,
            salted: pw,
        }
    }

    fn prepare_salt(salt: &String) -> String {
        let mut salt = salt.clone();

        salt.insert(0, ':');

        salt
    }
}
