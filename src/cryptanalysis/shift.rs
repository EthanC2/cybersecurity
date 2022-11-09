use std::collections::HashMap;
use std::iter::zip;
use crate::cryptography::caesar::{self, ALPHABET};

/*
    SECTION 1 of 4: CIPHERTEXT-ONLY ATTACK
*/
lazy_static! {
    ///A mapping of the percent frequency of each letter in the English language,
    /// bast on D. Denning, S. Akl, M. Heckman, T. Lunt, M. Morgenstern, P. Neumann, 
    /// and R. Schell, “Views for Multilevel Database Security,” IEEE Transactions 
    /// on Software Engineering 13 (2), pp. 129–140 (Feb. 1987).
    static ref ENGLISH_MODEL: HashMap<char,f32> = HashMap::from([
        ('a',0.080),
        ('b',0.015),
        ('c',0.030),
        ('d',0.040),
        ('e',0.130),
        ('f',0.020),
        ('g',0.015),
        ('h',0.060),
        ('i',0.065),
        ('j',0.005),
        ('k',0.005),
        ('l',0.035),
        ('m',0.030),
        ('n',0.070),
        ('o',0.080),
        ('p',0.020),
        ('q',0.002),
        ('r',0.065),
        ('s',0.060),
        ('t',0.090),
        ('u',0.030),
        ('v',0.010),
        ('w',0.015),
        ('x',0.005),
        ('y',0.020),
        ('z',0.002),
    ]);
}

///Performs a ciphertext-only attack on a Caesarian cipher using letter frequency analysis,
///returning the a sorted list of tuples containing the shift value (i) and φ(i), the percent likihood that 'i'
///was the shift value used to encipher the text. The smaller φ(i), closer the deciphered text was
///to English (and is more likely to be the original plaintext).
/// 
/// Internally uses the English model proposed in “Views for Multilevel Database Security,” 
/// IEEE Transactions on Software Engineering 13 (2), pp. 129–140 (Feb. 1987).
pub fn frequency_analysis<S>(ciphertext: S) -> Vec<(i32,f32)>
where S: AsRef<str> {
    let mut plaintexts = (0..26).map(|i|(i, phi(letter_frequency(caesar::decrypt(ciphertext.as_ref(), i)))))
                                            .collect::<Vec<(i32,f32)>>();

    plaintexts.sort_by(|a,b| a.1.partial_cmp(&b.1).unwrap());

    plaintexts
}

///Analyzes a string 'ciphertext', returning mapping of each alphabetic ASCII character
///to the percent of the text that the character makes up (discluding alphabetic ASCII characters).
fn letter_frequency<S: AsRef<str>>(ciphertext: S) -> HashMap<char,f32> {
    let mut count: HashMap<char,f32> = HashMap::new();

    for ch in ciphertext.as_ref().chars() {
        if ch.is_ascii_alphabetic() {
            count.entry(ch.to_ascii_lowercase()).and_modify(|curr| *curr += 1.0f32).or_insert(1.0f32);
        }
    }

    let total_letters: f32 = count.values().sum();
    for frequency in count.values_mut() {
        *frequency /= total_letters;
    }

    count
}

///In statistics, φ represents the correlation between two binary variables.
///Here, we are measuring φ(i), the correlation between our model of the English language
///and the decrypted ciphertext for each shift value (0..=25). The smaller the difference,
///the closer the decrypted ciphertext is to English
fn phi(ciphertext: HashMap<char,f32>) -> f32 {
    let mut phi = 0f32;

    for (ch, cipher_freq) in ciphertext.iter() {
        let english_freq = ENGLISH_MODEL.get(ch).expect("ciphertext only contains lowercase alphabetic ASCII");
        phi += cipher_freq - english_freq;
    }

    phi
}


/*
    SECTION 2 of 4: KNOWN-PLAINTEXT ATTACK
*/

///If even one letter of the plaintext is known, then the key of a shift cipher
///can be deduced by taking the difference between the indices of any character in
///the ciphertext and the plaintext mod 26.
/// 
///Returns [`None`] if one or both of the strings are empty or the lengths of the strings do not match, else [`Some`]
pub fn deduce_key<S>(plaintext: S, ciphertext: S) -> Option<usize>
where S: AsRef<str> {
    // let plaintext_chars = plaintext.as_ref().chars().filter(|ch| ch.is_alphabetic()).collect::<Vec<char>>();
    // let ciphertext_chars = ciphertext.as_ref().chars().filter(|ch| ch.is_alphabetic()).collect::<Vec<char>>();

    // if let (Some(original_char), Some(final_char)) = (plaintext_chars.first(), ciphertext_chars.first()) {
    //     println!("{original_char} - {final_char}");

    //     let original_idx = caesar::ALPHABET.iter().position(|&ch| ch == original_char.to_ascii_lowercase()).expect("") as i32;
    //     let final_idx = caesar::ALPHABET.iter().position(|&ch| ch == final_char.to_ascii_lowercase()).expect("") as i32;

    //     let mut shift  = final_idx - original_idx;

    //     if shift > 26 {
    //         shift -= 26;
    //     } else if shift < 26 {
    //         shift += 26;
    //     }

    //     return Some(shift as usize);
    // }

    // None
    let plaintext = plaintext.as_ref();
    let ciphertext = ciphertext.as_ref();

    if plaintext.is_empty() || ciphertext.is_empty() || plaintext.len() != ciphertext.len() {
        return None
    }

    let mut avg_key = 0.0;
    for (plain_char, shifted_char) in zip(plaintext.chars(), ciphertext.chars()) {
        //let difference = (shifted_char as i32) - (plain_char as i32);
        let original_idx = caesar::ALPHABET.iter().position(|&ch| ch == plain_char.to_ascii_lowercase());
        let shifted_idx = caesar::ALPHABET.iter().position(|&ch| ch == shifted_char.to_ascii_lowercase());
        
        if let (Some(original_idx), Some(shifted_idx)) = (original_idx, shifted_idx) {
            println!("{plain_char} ({original_idx}), {shifted_char} ({shifted_idx})");
            let diff= (shifted_idx as isize - original_idx as isize);
            println!("{shifted_idx} - {original_idx} = {diff}");
            avg_key += diff as f32;
            println!("avg_key: {avg_key}");
        } else {
            println!("{plain_char} or {shifted_char} is not in ALPHABET");
        }
    }

    println!("Before division: {avg_key}");
    avg_key = avg_key / plaintext.chars().count() as f32;
    println!("After division + before mod: {avg_key}");
    avg_key = avg_key % ALPHABET.len() as f32;
    println!("After mod: {avg_key}");
    Some(avg_key.round() as usize)
}