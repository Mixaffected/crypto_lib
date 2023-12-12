mod argon2;
mod password;
mod rsa;
mod sha256;

pub use argon2::{ARGON2ConfWizard, ARGON2};
pub use password::Password;
pub use rsa::{RSAConnection, RSA};
pub use sha256::SHA256;

#[cfg(test)]
mod tests {
    use crate::argon2::{ARGON2ConfWizard, ARGON2};
    use crate::password::Password;
    use crate::rsa::{RSAConnection, RSA};
    use crate::sha256::SHA256;

    #[test]
    fn argon2() {
        let argon2_conf = ARGON2ConfWizard::new(2048, 4, 8192, 12);
        let hash = ARGON2::hash("Test".to_string(), argon2_conf);
        println!("{}", hash);
        assert_eq!(hash, "$argon2id$v=19$m=8192,t=12,p=4$eHh4eHh4eHg$FgiaKcX1gG1D/ip9OuLwoW6XFS9SmuKoxt2pO95imZho5fmfD9lgb1h0Wckgk/6nHG93ytyVKiLJQbnyyRi0vLhRsN2YJEOfZasDhkWO1KS5EK8PpoWFQImfo25m1RfQHU8BpVMMuF1j1TxEOazeh4z8+kXvQlz2cPE6nvaBw++2A/ZJAan/4Hnbqi3LpK3pYaa9Hfl+XY3gO495b7NckT/bgNd8mmX6hp6z3kMIfkSBf50f5Q0Y5fT+jTYEvvZahdVO+dJB4S7s6TxS/jwPjLnDEuOfkldA4Pf2hXIvSIYkzQGLlaZQyb1Z4stYq1ScdeqPFhG0/brZAcGt+qrrm0w45JR2KTvid/e+QlnPn9Zjf0sxxyYtiLQHkCfSiTNYec+yyEX7K3/sAPuohzhiF9GgHmAgBUiQ0aAhd4qWnDv4mJY1yzQ2vgVAKaBCJIqG+4LeTCdBQpLtwMV+e7ZECJSp98zdscejN3oa13P+VUfAa13+OM4JhuMuXFxFBn5u5w09xKen+qbR8mCgOGXtp7N12d7duXKJe894JUvXTZ0juXFeSiA6SSrV49Hz4xoQUSVQ++KCss0oJXVzNVc52KPi1TuQBmQDu+MPhBsE8d+c/9J8OEDyF0OiPgWKPdKdJrak7u/clj9BbcuRTzbMPbs8f1TAzDG3IO35W6XMgTm8Z3CTqYIM+Fm7qPZRi+BFU8Pa9HnXzLRmAXiA11X0/UkWwhF6ZgRlOFu5luvdzwWGsi8RFUDtVP12opq2OAa3GFjdML9y361yLIpcn7fGHLikU3Gppmz+VOP2ZhkZNSELr9i1qZelq07vu2WDFqu0EdqyA+c94aiET9BPPq6kSntwv+ZdPDCbLowKLL6GXGafU9u5v8OKamoV/CHmKFirvLWxUXR+2LqAxTi88N6kVNGWFovfY3GBJAHgKpMtluRi1PEViGNGB+r0h2wIvCyQQWGX3SxrHO5I4Dk0LHU8m++pgZRCc7oIZcTVJ5wh09hWJLd/8K+LfQ3lw7Xmv9hf6iaRJ7sNwjLizseFPE07ZEYTNMBX0CrNLXivN5U9OWYcMZcBYM6pinxgTfDVLT0SWAJTvr8Ka060Tqfqt9UYNTrvnZOVvNuRtPzSqlGVdPrdxyQPTNdqET47mVIdkif4lQYlQQ9GXVA4qwXFdCuB6Q7AB4V46mV7cfl6azPQwjqkyGegj7Ye9N52DHLpAGkRdfeA2/41/BGBbQFucq+4X/MraEKn4E3AH49W8SZBk0o8gB8ypi1ltJrm/soBP47Vw+leVwk6gaWPyQYfRRNX7ImxLV3bIJXRrd5qQE3zlc+vF7FehQ7ldwg7MpOL5HcyI7O9zD9mokOVjCPrVrvqwdnbMEHSC1tH8wLnhIrHclOqJipeavfMj52JkrOI/ShRVzIiCqzWO08MiJADGDKmOFjMSRR4JzGpMhm6v1hANL4ywqohZQXsi/k5VXuGd7A9Pr437JeP/QydPNCXlgStP8ZSaAycxYIepaly4I+RljEnOmWDo1WBxdUXGoxvhkuU4lvFz6UpbSQYlk9ZBeYuEjn37qUAPtfpZ2h/7InKsYKUwaeWVi/84rK9r9AtlF+j2UmvXZLoVMYFGBOX3Zv7dr2P2UeM2G+WaodIgWDeN5sWo3wW62BNpwgAJ6t761EjnreoMopihATX2tfS1QfQB0X/SaGgRm4RR4klawxF+EhilfOJ6z+T97iGIjAborRUYQ9v7m7m+vVJmqOHAConypLxitCAyxZ2K+UqjkolCYRRk0zYj1nbcEHYRlvR66o51h8ucTCAlwspnXbKYUM+4cF3nk6RCa3RrU8tptlCoU7VSabtBDu2aIyo7mmYakMikKalTWTruYEacH9ez+6cvMBaldssLip1dh1IW7KtRbzeSZBnmZ8hpjD0FLd712tSt7FPB0yyKX/rBPb2bxfCion7yONRi7lDuBeYTOvFlT9gjpjhQMTEs0lNFgrI/v9Ag3hry8pz2kyosewpQxP+MIOkYc3cC39lrCTQf4ynd0553nSEXoLqX+IN89qupO8cVfofJPhYHp89QvO8jFRy5IJ4OaTlkWYr2uDzxeF3fDsbOSmordaoSoAglzGityItLHJMwR2NQKp4QZJooKLOGhHWKin+1OpIrWRjVgzs+fNdJq0ooD9CKgP90i+EFz3A4ypLV7YTd1RlMBIBihpBY8dNOZBkO+3xKgOEWeMkGHevXxEKeHzNcyEt/LPLHf6RbJU+iP1uM7+Le2n7GVQ5rZqFCNlgR5A/XrZHrejOH278uJHcqq7N/tB+NOTDjfYXy93l3Oi0GFqUP1Ku4AS8zXQwG2wCXEm7SVGecity3XX2lQY2lsHKKRC9z3WI6PS4G+Vlz1u8KfwYtOoJ/nN4fzevjKVoHk4A4dLgdcMQYwdMI8lmTaWfLWijQ+A3W94C2xsusJbWPLEO/Oew8Lnnhn0rL/7A9nPX9N1zYNlOsRP89njtd+r4xddThBMZFSq3ToZkVmVxknkny4obOaoxRMvccTDDItZ2bnHb0McHMfL1FLZ0TTuEpWgIjmvk+gC2FoXS8aJDLPYwqnarkTfL++d3JFOYili53KWDYSeybn9VYlalaD0LVFRedacZwSsUNHdD6/DQLddq+tRuWNHRnqOkJgM1egZIc2gdzU43BZPGcP7YFcw4DA0HPOz4TGxcoD5BACnPM7PoNHLJgVBNbeoQDiJhlyyPvXTjtXlPL+g".to_string())
    }

    #[test]
    fn argon2_salted() {}
}
