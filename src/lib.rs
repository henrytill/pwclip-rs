extern crate data_encoding;
extern crate hmac_drbg;
extern crate rust_scrypt;
extern crate sha2;
extern crate typenum;
extern crate unicode_segmentation;

use hmac_drbg::HmacDRBG;
use rust_scrypt::*;
use sha2::Sha512;
use typenum::U64;
use unicode_segmentation::UnicodeSegmentation;

pub struct PWM<'a> {
    pub url: &'a str,
    pub username: &'a str,
    pub extra: Option<&'a str>,
    pub prefix: &'a str,
    pub charset: &'a str,
    pub length: usize,
}

pub const CHARSET_ALPHANUMERIC: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

impl<'a> PWM<'a> {
    pub fn get_password(&self, key: &[u8]) -> String {
        let mut drbg = HmacDRBG::<Sha512>::new(key, &[], &[]);
        drbg.reseed(self.url.as_bytes(), None);
        drbg.reseed(self.username.as_bytes(), None);
        if let Some(extra) = self.extra {
            drbg.reseed(extra.as_bytes(), None);
        }

        let charset_graphemes: Vec<&str> = self.charset.graphemes(true).collect();
        let charset_len: usize = charset_graphemes.len();
        let m: usize = 256 % charset_len;

        let chars: String = drbg.generate::<U64>(None)
            .into_iter()
            .filter(|r| (*r as usize) < 256 - m)
            .map(|r| charset_graphemes[r as usize % charset_len])
            .take(self.length - self.prefix.len())
            .collect();

        let mut password: String = self.prefix.to_owned();
        password.push_str(&chars);
        password
    }
}

pub fn key(passphrase: &[u8]) -> [u8; 32] {
    let params = ScryptParams::new(2 << 15, 8, 1);
    let mut buf = [0u8; 32];
    scrypt(passphrase, b"pwclip", &params, &mut buf);
    buf
}

#[cfg(test)]
mod test {
    use super::*;
    use data_encoding::HEXLOWER;

    struct Test<'a> {
        pwm: PWM<'a>,
        pws: [&'a str; 2],
    }

    const EXTRA: &str = "extra data";

    const PASSWORD_TEST_KEYS: [&str; 2] = ["", "secret key"];

    const PASSWORD_TESTS: [Test; 7] = [
        Test {
            pwm: PWM {
                url: "",
                username: "",
                extra: None,
                prefix: "",
                charset: CHARSET_ALPHANUMERIC,
                length: 32,
            },
            pws: [
                "8aRyuJhRGXAQFSlyngeSHpoVwjvKEBD9",
                "TxuEPdxmb4ps3KMFFm7K9YpCsLn1Yati",
            ],
        },
        Test {
            pwm: PWM {
                url: "example.com",
                username: "example@example.com",
                extra: None,
                prefix: "",
                charset: CHARSET_ALPHANUMERIC,
                length: 32,
            },
            pws: [
                "2b8CMXZJYVDGqEq8cjJLeI7Vd1tDiVbR",
                "f67RwXJIQ9DtCTUcXyUogCzjO43TaY4V",
            ],
        },
        Test {
            pwm: PWM {
                url: "example.com",
                username: "example@example.com",
                extra: None,
                prefix: "",
                charset: CHARSET_ALPHANUMERIC,
                length: 48,
            },
            pws: [
                "2b8CMXZJYVDGqEq8cjJLeI7Vd1tDiVbRRcmwf9gkjWIhdhgW",
                "f67RwXJIQ9DtCTUcXyUogCzjO43TaY4VvonXCxjapWXiM9vW",
            ],
        },
        Test {
            pwm: PWM {
                url: "example.com",
                username: "example@example.com",
                extra: None,
                prefix: "foobar!",
                charset: CHARSET_ALPHANUMERIC,
                length: 32,
            },
            pws: [
                "foobar!2b8CMXZJYVDGqEq8cjJLeI7Vd",
                "foobar!f67RwXJIQ9DtCTUcXyUogCzjO",
            ],
        },
        Test {
            pwm: PWM {
                url: "example.com",
                username: "example@example.com",
                extra: Some(EXTRA),
                prefix: "",
                charset: CHARSET_ALPHANUMERIC,
                length: 32,
            },
            pws: [
                "3UIXCUj9Lme0f17aNJI5sMBa6l0DzKi9",
                "U1CdUb3gMyl2hpmIXZYLTQjQp16Sg9oX",
            ],
        },
        Test {
            pwm: PWM {
                url: "example.com",
                username: "example@example.com",
                extra: None,
                prefix: "",
                charset: "αβγδεζηθικλμνξοπρστυφχψω",
                length: 32,
            },
            pws: [
                "ηθγρηωυδεχδλνινρψπδβηψμβυζπθαβσθ",
                "μβχτσξγηδσχφκφιωγολιφχβονθωρονμσ",
            ],
        },
        Test {
            pwm: PWM {
                url: "example.com",
                username: "example@example.com",
                extra: None,
                prefix: "",
                charset: "0⌘1",
                length: 32,
            },
            pws: [
                "0⌘1⌘01⌘0⌘00⌘010⌘⌘00⌘00⌘1⌘⌘10⌘0⌘1",
                "1⌘⌘001⌘1001010111111⌘110⌘10⌘1⌘10",
            ],
        },
    ];

    #[test]
    fn test_passwords() {
        for test in PASSWORD_TESTS.iter() {
            for (k, expected) in test.pws.iter().enumerate() {
                let actual = test.pwm.get_password(PASSWORD_TEST_KEYS[k].as_bytes());
                assert_eq!(expected, &actual);
            }
        }
    }

    struct KeyTest<'a> {
        passphrase: &'a [u8],
        keyhex: &'a [u8],
    }

    const KEY_TESTS: [KeyTest; 9] = [
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

    #[test]
    fn test_keys() {
        for test in KEY_TESTS.iter() {
            let actual = key(test.passphrase);
            let expected = HEXLOWER.decode(test.keyhex).unwrap();
            assert_eq!(expected, actual);
        }
    }
}
