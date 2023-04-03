#[cfg(test)]
extern crate anyhow;
extern crate clear_on_drop;
#[cfg(test)]
extern crate data_encoding;
extern crate hmac_drbg;
extern crate rust_scrypt;
extern crate serde;
extern crate sha2;
extern crate toml;
extern crate typenum;
extern crate unicode_segmentation;

use clear_on_drop::clear::Clear;
use hmac_drbg::HmacDRBG;
use rust_scrypt::{scrypt, ScryptParams};
use serde::Deserialize;
use sha2::Sha512;
use typenum::U64;
use unicode_segmentation::UnicodeSegmentation;

const CHARSET_ALPHANUMERIC: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const DEFAULT_LENGTH: usize = 24;

#[derive(Debug, PartialEq)]
pub struct Password(String);

impl Drop for Password {
    fn drop(&mut self) {
        self.0.clear();
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct PWM {
    url: String,
    username: String,
    extra: Option<String>,
    prefix: String,
    charset: String,
    length: usize,
}

impl Default for PWM {
    fn default() -> Self {
        PWM {
            url: Default::default(),
            username: Default::default(),
            extra: None,
            prefix: Default::default(),
            charset: CHARSET_ALPHANUMERIC.to_string(),
            length: DEFAULT_LENGTH,
        }
    }
}

impl PWM {
    fn password_raw(&self, key: &[u8]) -> Password {
        let mut drbg = HmacDRBG::<Sha512>::new(key, &[], &[]);
        drbg.reseed(self.url.as_bytes(), None);
        drbg.reseed(self.username.as_bytes(), None);
        if let Some(ref extra) = self.extra {
            drbg.reseed(extra.as_bytes(), None);
        }

        let chars: String = {
            let charset_graphemes: Vec<&str> = self.charset.graphemes(true).collect();
            let charset_len: usize = charset_graphemes.len();
            drbg.generate::<U64>(None)
                .into_iter()
                .filter(|r| (*r as usize) < 256 - (256 % charset_len))
                .map(|r| charset_graphemes[r as usize % charset_len])
                .take(self.length - self.prefix.len())
                .collect()
        };

        let mut password: String = self.prefix.to_owned();
        password.push_str(&chars);
        Password(password)
    }

    pub fn password(&self, key: Key) -> Password {
        self.password_raw(&key.0)
    }
}

#[derive(Debug)]
pub struct Key([u8; 32]);

impl Key {
    pub fn new(passphrase: &[u8]) -> Key {
        let params = ScryptParams::new(2 << 15, 8, 1);
        let mut buf = [0u8; 32];
        scrypt(passphrase, b"pwclip", &params, &mut buf);
        Key(buf)
    }
}

impl From<Key> for [u8; 32] {
    fn from(key: Key) -> [u8; 32] {
        key.0
    }
}

impl From<Key> for Vec<u8> {
    fn from(key: Key) -> Vec<u8> {
        key.0.to_vec()
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
mod test {
    use anyhow::{anyhow, Result};
    use data_encoding::HEXLOWER;
    use toml::Value::{self, Table};

    use super::*;

    const EXTRA: &str = "extra data";

    const PASSWORD_TEST_KEYS: [&str; 2] = ["", "secret key"];

    macro_rules! test_url {
        () => {
            "example.com".to_string()
        };
    }

    macro_rules! test_username {
        () => {
            "example@example.com".to_string()
        };
    }

    struct Test<'a> {
        pwm: PWM,
        pws: [&'a str; 2],
    }

    struct KeyTest<'a> {
        passphrase: &'a [u8],
        keyhex: &'a [u8],
    }

    #[test]
    fn test_passwords() {
        let password_tests = [
            Test {
                pwm: PWM {
                    length: 32,
                    ..Default::default()
                },
                pws: [
                    "8aRyuJhRGXAQFSlyngeSHpoVwjvKEBD9",
                    "TxuEPdxmb4ps3KMFFm7K9YpCsLn1Yati",
                ],
            },
            Test {
                pwm: PWM {
                    url: test_url!(),
                    username: test_username!(),
                    length: 32,
                    ..Default::default()
                },
                pws: [
                    "2b8CMXZJYVDGqEq8cjJLeI7Vd1tDiVbR",
                    "f67RwXJIQ9DtCTUcXyUogCzjO43TaY4V",
                ],
            },
            Test {
                pwm: PWM {
                    url: test_url!(),
                    username: test_username!(),
                    length: 48,
                    ..Default::default()
                },
                pws: [
                    "2b8CMXZJYVDGqEq8cjJLeI7Vd1tDiVbRRcmwf9gkjWIhdhgW",
                    "f67RwXJIQ9DtCTUcXyUogCzjO43TaY4VvonXCxjapWXiM9vW",
                ],
            },
            Test {
                pwm: PWM {
                    url: test_url!(),
                    username: test_username!(),
                    prefix: "foobar!".to_string(),
                    length: 32,
                    ..Default::default()
                },
                pws: [
                    "foobar!2b8CMXZJYVDGqEq8cjJLeI7Vd",
                    "foobar!f67RwXJIQ9DtCTUcXyUogCzjO",
                ],
            },
            Test {
                pwm: PWM {
                    url: test_url!(),
                    username: test_username!(),
                    extra: Some(EXTRA.to_string()),
                    length: 32,
                    ..Default::default()
                },
                pws: [
                    "3UIXCUj9Lme0f17aNJI5sMBa6l0DzKi9",
                    "U1CdUb3gMyl2hpmIXZYLTQjQp16Sg9oX",
                ],
            },
            Test {
                pwm: PWM {
                    url: test_url!(),
                    username: test_username!(),
                    extra: None,
                    charset: "αβγδεζηθικλμνξοπρστυφχψω".to_string(),
                    length: 32,
                    ..Default::default()
                },
                pws: [
                    "ηθγρηωυδεχδλνινρψπδβηψμβυζπθαβσθ",
                    "μβχτσξγηδσχφκφιωγολιφχβονθωρονμσ",
                ],
            },
            Test {
                pwm: PWM {
                    url: test_url!(),
                    username: test_username!(),
                    charset: "0⌘1".to_string(),
                    length: 32,
                    ..Default::default()
                },
                pws: [
                    "0⌘1⌘01⌘0⌘00⌘010⌘⌘00⌘00⌘1⌘⌘10⌘0⌘1",
                    "1⌘⌘001⌘1001010111111⌘110⌘10⌘1⌘10",
                ],
            },
        ];

        for test in password_tests.iter() {
            for (k, pw) in test.pws.iter().enumerate() {
                let expected = Password(pw.to_string());
                let actual = test.pwm.password_raw(PASSWORD_TEST_KEYS[k].as_bytes());
                assert_eq!(expected, actual);
            }
        }
    }

    #[test]
    fn test_keys() -> Result<()> {
        let key_tests = [
            KeyTest {
                passphrase: &[],
                keyhex: b"cf4b3589438e51bfc0f942ca1f2b108d5a9e5a9238c15a2e76ab764484e636bd",
            },
            KeyTest {
                passphrase: &[0u8],
                keyhex: b"cf4b3589438e51bfc0f942ca1f2b108d5a9e5a9238c15a2e76ab764484e636bd",
            },
            KeyTest {
                passphrase: &[1u8],
                keyhex: b"cdbc42a4bf57aad0b0a4a86d3bb654e57bc356bd08d5de88a6548a3a031fc87e",
            },
            KeyTest {
                passphrase: &[1u8, 0u8],
                keyhex: b"cdbc42a4bf57aad0b0a4a86d3bb654e57bc356bd08d5de88a6548a3a031fc87e",
            },
            KeyTest {
                passphrase: &[1u8, 0u8, 1u8],
                keyhex: b"aac60e84780340d5e7065a27a7189e240f8777b1b7ac2144e9d9e4d93a599c53",
            },
            KeyTest {
                passphrase: &[0u8, 1u8],
                keyhex: b"a35b6569ec9ac21d16c43db825436e92b5a23b6288e17503664962f148e72101",
            },
            KeyTest {
                passphrase: &[0u8, 0u8, 1u8],
                keyhex: b"df71d36f29d13211d9f74e77828cdc1c83e41a3a5407bc231bdca2d1504b1544",
            },
            KeyTest {
                passphrase: b"passphrase",
                keyhex: b"40f2dacf5fdb770dc6e047f41883ff71ec3972aa7ac92d1792dd2909f2453324",
            },
            KeyTest {
                passphrase: b"another passphrase",
                keyhex: b"2aaf56826d42fdcbe6ae5653f50b10fc47748d8c2b3e36515bb01078c7c8f535",
            },
        ];

        for test in key_tests.iter() {
            let expected = HEXLOWER.decode(test.keyhex)?;
            let actual: Vec<u8> = Key::new(test.passphrase).into();
            assert_eq!(expected, actual);
        }

        return Ok(());
    }

    #[test]
    fn construct_pwm_test() -> Result<()> {
        let config = r#"
            [example]
            url = 'example.com'
            username = 'example@example.com'

            [server]
            url = 'server.com'
            username = 'server@server.com'
            prefix = 'quux'
        "#;

        if let Table(parsed) = config.parse::<Value>()? {
            for (key, value) in parsed {
                let pwm: PWM = value.try_into()?;
                println!("{}: {:?}", key, pwm);
            }
            Ok(())
        } else {
            Err(anyhow!("config is not a table"))
        }
    }
}
