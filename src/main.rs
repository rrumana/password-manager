mod args;
mod crypto;
mod password;

use read_input::prelude::*;

use rpassword::read_password;
use args::*;
use password::*;
use clap::Parser;
use std::io::Write;
use std::fs;
use std::io;
use std::env;
use anyhow::{anyhow, Result};
use aes_gcm_siv::Nonce;

//  TODO List:
//  - Turn this proof of concept into client-server model
//    - The client side must have accesible API for chrome to use as extension
//    - The server side must be always running
//      - Look into hosting small server in the future when this is finished.
//
//  - Create a map to store master password hashes and the corresponding symmetric keys
//    - The map should be stored in memory while running
//    - The map should be saved to disk when the program is closed
//    - The map is the responsibility of the server when implemented
//
//  - Create a flag and database to store the current user session
//    - The session should be stored in memory while running
//    - The session is cleared upon logout or program close
//    - The session is the responsibility of the client when implemented
//
//  - Implement client side experience into browser extension

//////////////////////////////////////////////////////////////////////////////////////////////////
// start input parsing






// end input parsing
//////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////
// start logging setup






// end logging setup
//////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////
// start password manager functions

// signup function
fn signup_input() -> Result<()> {
    // get username
    // ensure it is long enough (8 characters)
    // ensure it does not contain whitespace
    let username = input::<String>()
        .repeat_msg("Enter username: ")
        .add_err_test(|x| x.len() >= 8, "Username must be at least 8 characters")
        .add_err_test(|x| x.chars().any(|c| c.is_whitespace()), "Username must not contain whitespace")
        .try_get()?;

    // get password and force user to repeat it
    // ensure it is long enough (10 characters)
    // ensure it contains at least one digit
    let mut password: String;
    let mut password_confirm: String;

    loop {
        password = input::<String>()
            .repeat_msg("Enter master password: ")
            .add_err_test(|x| x.len() >= 10, "Master password must contain at least 10 characters")
            .add_err_test(|x| x.chars().any(|c| c.is_digit(10)), "Master password must contain at least one digit")
            .try_get()?;

        password_confirm = input::<String>()
            .repeat_msg("Confirm master password: ")
            .try_get()?;

        if password == password_confirm {
            break;
        } else {
            println!("Error: Passwords do not match");
        }
    }

    // pass username and password value onto the signup function
    signup_handler(username, password)?;

    // reutrn Ok if signup is successful
    Ok(())
}

fn signup_handler(username: String, password: String) -> Result<()> {
    // generate master key from user input using Argon2 kdf
    let master_key = crypto::kdf(&username, &password)?;
    
    // stretch master key using HKDF
    let stretched_master_key = crypto::hkdf(&master_key)?;

    // generate a random symmetric key and iv, use the IV to seed a nonce for AES-GCM
    let symmetric_key = crypto::csprng::<32>();
    let iv = crypto::csprng::<12>(); 
    let nonce = Nonce::from_slice(&iv);

    // encrypt the symmetric key using the stretched master key
    let protected_symmetric_key = crypto::encrypt_aes_gcm(&symmetric_key, &stretched_master_key, &nonce)?;

    // pass the stretched master key, encryted key, and nonce to be stored for retrieval upon login
    assign_key(&stretched_master_key, protected_symmetric_key.as_slice(), &nonce)?;
    Ok(())
}

fn assign_key(stretched_master_key: &[u8; 32], protected_symmetric_key: &[u8], nonce: &Nonce) -> Result<()> {
    Ok(())
}


// end password manager functions
//////////////////////////////////////////////////////////////////////////////////////////////////

fn main() -> Result<()> {
    println!("Welcome to Password Manager");

    loop{
        let command: String = match input().msg("Enter a command: ").try_get() {
            Ok(input) => {
                println!("You entered: {}", input);
                input
            }
            Err(err) => {
                println!("Error: Invalid input {}", err);
                continue;
            }
        };

        match command.as_str() {
            "signup" => signup_input()?,
            "login" => println!("You entered: login"),
            _ => println!("Error: Invalid command"),
        };
    }
}
