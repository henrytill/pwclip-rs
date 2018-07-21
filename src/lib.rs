extern crate hmac_drbg;
extern crate sha2;
extern crate typenum;
extern crate unicode_segmentation;

use hmac_drbg::HmacDRBG;
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

#[cfg(test)]
mod test {
    use super::*;

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
}
