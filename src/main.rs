#[macro_use]
extern crate lazy_static;

mod cryptography;
mod cryptanalysis;

use cryptanalysis::shift::{frequency_analysis, deduce_key};
use cryptography::caesar::decrypt;

fn main() {
    let plaintext = String::from("the car jerked off the monkey");
    let ciphertext = String::from("sgd bzq idqjdc nee sgd lnmjdx");
   
    let key = deduce_key(&plaintext, &ciphertext);
    
    match key {
        Some(key) => println!("The key is likely {key}"),
        None => eprintln!("Could not deduce the key"),
    }

    // for (i, phi) in frequency_analysis(&ciphertext).iter() {
    //     println!("{i:02} ({phi:.3}): {}", decrypt(&ciphertext, *i));
    // }
}
