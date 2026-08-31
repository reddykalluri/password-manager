//! Password and passphrase generation, plus strength rating.
//!
//! All randomness comes from the OS CSPRNG via [`crate::crypto::rng`]. The
//! passphrase generator uses the official EFF long wordlist (7,776 words),
//! vendored at `data/eff_large_wordlist.txt`.

use crate::crypto::rng::uniform_below;
use crate::error::{Error, Result};

/// The EFF large wordlist, one word per line, embedded at build time.
static EFF_WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

fn wordlist() -> Vec<&'static str> {
    EFF_WORDLIST.lines().filter(|l| !l.is_empty()).collect()
}

/// Character classes selectable for password generation.
#[derive(Debug, Clone, Copy)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Exclude visually ambiguous characters (O/0, l/1/I, etc.).
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        // Spec default: 20-character mixed-class password.
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?";
const AMBIGUOUS: &str = "O0oIl1|`'\"{}[]()/\\B8S5Z2";

/// Generate a password per `opts`. Guarantees at least one character from each
/// enabled class (when length permits) and draws uniformly without modulo bias.
pub fn generate_password(opts: &PasswordOptions) -> Result<String> {
    if !(8..=128).contains(&opts.length) {
        return Err(Error::Invalid("password length must be 8..=128".into()));
    }
    let mut classes: Vec<Vec<char>> = Vec::new();
    let push = |src: &str, on: bool, classes: &mut Vec<Vec<char>>| {
        if on {
            let chars: Vec<char> = src
                .chars()
                .filter(|c| !opts.exclude_ambiguous || !AMBIGUOUS.contains(*c))
                .collect();
            if !chars.is_empty() {
                classes.push(chars);
            }
        }
    };
    push(LOWER, opts.lowercase, &mut classes);
    push(UPPER, opts.uppercase, &mut classes);
    push(DIGITS, opts.digits, &mut classes);
    push(SYMBOLS, opts.symbols, &mut classes);

    if classes.is_empty() {
        return Err(Error::Invalid(
            "at least one character class must be enabled".into(),
        ));
    }

    // Pool of all allowed characters.
    let pool: Vec<char> = classes.iter().flatten().copied().collect();

    let mut out: Vec<char> = Vec::with_capacity(opts.length);
    // Guarantee one from each class where the length allows.
    for class in &classes {
        if out.len() < opts.length {
            out.push(class[uniform_below(class.len() as u32) as usize]);
        }
    }
    while out.len() < opts.length {
        out.push(pool[uniform_below(pool.len() as u32) as usize]);
    }
    // Shuffle so the guaranteed characters are not positionally predictable.
    fisher_yates(&mut out);
    Ok(out.into_iter().collect())
}

/// Passphrase options.
#[derive(Debug, Clone)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    /// Capitalise the first letter of each word.
    pub capitalize: bool,
    /// Insert a random digit somewhere for sites demanding one.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 4,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Generate an EFF-wordlist passphrase.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<String> {
    if !(3..=10).contains(&opts.words) {
        return Err(Error::Invalid("passphrase words must be 3..=10".into()));
    }
    let list = wordlist();
    let mut words: Vec<String> = (0..opts.words)
        .map(|_| {
            let w = list[uniform_below(list.len() as u32) as usize];
            if opts.capitalize {
                capitalize_first(w)
            } else {
                w.to_string()
            }
        })
        .collect();

    if opts.include_number {
        let digit = char::from(b'0' + uniform_below(10) as u8);
        let idx = uniform_below(words.len() as u32) as usize;
        words[idx].push(digit);
    }
    Ok(words.join(&opts.separator))
}

/// A zxcvbn-equivalent 0–4 strength score with a human label.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Strength {
    /// 0 (very weak) .. 4 (very strong).
    pub score: u8,
    /// Estimated entropy in bits.
    pub entropy_bits: f64,
}

impl Strength {
    pub fn label(&self) -> &'static str {
        match self.score {
            0 => "very weak",
            1 => "weak",
            2 => "fair",
            3 => "strong",
            _ => "very strong",
        }
    }
}

/// Estimate password strength. This is a zxcvbn-*equivalent* estimator: it
/// scores by character-class entropy with penalties for short length, single
/// class, sequences, and repeats — not a full dictionary attack model, but a
/// self-contained rating suitable for every client target.
pub fn rate_strength(password: &str) -> Strength {
    if password.is_empty() {
        return Strength {
            score: 0,
            entropy_bits: 0.0,
        };
    }
    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 32;
    }
    let len = password.chars().count() as f64;
    let mut entropy = len * (pool.max(1) as f64).log2();

    // Penalties.
    entropy -= repeat_penalty(password);
    entropy -= sequence_penalty(password);
    if entropy < 0.0 {
        entropy = 0.0;
    }

    let score = match entropy as u32 {
        0..=27 => 0,
        28..=45 => 1,
        46..=59 => 2,
        60..=79 => 3,
        _ => 4,
    };
    Strength {
        score,
        entropy_bits: entropy,
    }
}

fn repeat_penalty(s: &str) -> f64 {
    let chars: Vec<char> = s.chars().collect();
    let mut run = 1;
    let mut penalty = 0.0;
    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            run += 1;
            if run >= 3 {
                penalty += 2.0;
            }
        } else {
            run = 1;
        }
    }
    penalty
}

fn sequence_penalty(s: &str) -> f64 {
    let chars: Vec<char> = s.chars().collect();
    let mut penalty = 0.0;
    for w in chars.windows(3) {
        let (a, b, c) = (w[0] as i32, w[1] as i32, w[2] as i32);
        if b - a == 1 && c - b == 1 {
            penalty += 3.0;
        }
    }
    penalty
}

fn capitalize_first(w: &str) -> String {
    let mut chars = w.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn fisher_yates<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = uniform_below((i + 1) as u32) as usize;
        v.swap(i, j);
    }
}
