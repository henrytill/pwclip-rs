extern crate hmac_drbg;
extern crate sha2;
extern crate typenum;

use hmac_drbg::HmacDRBG;
use sha2::Sha512;
use typenum::U64;

pub struct PWM<'a> {
    pub url: &'a str,
    pub username: &'a str,
    pub extra: Option<&'a str>,
    pub prefix: &'a str,
    pub charset: &'a str,
    pub length: usize,
}

pub static CHARSET_ALPHANUMERIC: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

impl<'a> PWM<'a> {
    pub fn get_password(&self, key: &[u8]) -> String {
        let mut rng = HmacDRBG::<Sha512>::new(key, &[], &[]);
        rng.reseed(self.url.as_bytes(), None);
        rng.reseed(self.username.as_bytes(), None);
        if let Some(extra) = self.extra {
            rng.reseed(extra.as_bytes(), None);
        }

        let charset_len: usize = self.charset.len();

        let m: usize = 256 % charset_len;

        let chars: String = rng.generate::<U64>(None)
            .into_iter()
            .filter(|r| (*r as usize) < 256 - m)
            .filter_map(|r| self.charset.chars().nth(r as usize % charset_len))
            .take(self.length)
            .collect();

        let mut password: String = self.prefix.to_owned();
        password.push_str(&chars);
        password
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simple_test() {
        let pwm = PWM {
            url: "example.com",
            username: "example@example.com",
            extra: None,
            prefix: "",
            charset: CHARSET_ALPHANUMERIC,
            length: 32,
        };

        let password = pwm.get_password("secret key".as_bytes());

        assert_eq!("f67RwXJIQ9DtCTUcXyUogCzjO43TaY4V", &password)
    }
}
