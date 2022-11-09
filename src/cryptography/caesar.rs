pub static ALPHABET: [char; 26] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

pub fn encrypt<S: AsRef<str>>(plaintext: S, shift: i32) -> String {
    rotn(plaintext, shift)
}

pub fn decrypt<S: AsRef<str>>(plaintext: S, shift: i32) -> String {
    rotn(plaintext, -shift)
}

fn rotn<S: AsRef<str>>(ciphertext: S, shift: i32) -> String {
    let iter = ciphertext.as_ref()
            .chars()
            .map(|c| if c.is_ascii_alphabetic() {
                    shift_n(&c.to_ascii_lowercase(), shift)
                } else {
                    c
                }
            );

    String::from_iter(iter)
}


fn shift_n(c: &char, rot: i32) -> char {
    let idx = ALPHABET.iter().position(|&ch| *c == ch).expect("casted to lowercase") as i32;
    let mut shifted_idx = idx + rot;
    
    //mod wasn't working for some reason, so basic addition it is.
    if shifted_idx < 0 {
        shifted_idx += 26;
    } else if shifted_idx > 26 {
        shifted_idx -= 26;
    }

    ALPHABET[shifted_idx as usize]
}