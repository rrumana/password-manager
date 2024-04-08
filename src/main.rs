mod args;

use args::*;
use clap::Parser;
use std::io::Write;
use anyhow::{anyhow, Result};
use std::env;

use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};


// TODO: make a database to store all of this stuff

fn check_credentials(_username: &String, _password: &String) -> Result<()> {
    // check if user exists
    // if user exists, check if password is correct
    // if password is correct, return Ok(())
    // else return Err("Incorrect password")
    // else return Err("User does not exist")
    Ok(())
}

fn decrypt_database(_username: &String, _password: &String) -> Result<()> {
    // decrypt the database
    // return the decrypted database
    Ok(())
}

fn key_derivation_function(salt: &String, payload: &String) -> Result<[u8; 32], argon2::Error> {
    let argon2 = Argon2::default();
    let mut output_key_material = [0u8; 32];
    argon2.hash_password_into(payload.as_bytes(), salt.as_bytes(), &mut output_key_material)?;
    Ok(output_key_material)
}

//Argon2 Rust Crypto
//    username + Master password -> master key
//    master password + master key -> master password hash
//
//HKDF Rust Crypto
//    master key -> stretched master key
//
//CSPRNG Rust Crypto
//    generate 512-bit Generated Symmetric Key
//    generate 128 bit Initialization Vector (IV)
//
//AES-256-GCM Rust Crypto
//    Stretched Master Key + Generated Symmetric Key + IV -> Protected Symmetric Key
//    Stretched Master Key + Protected Symmetric Key -> Symmetric Key
//
//RSA Rust Crypto
//    generate 2048-bit RSA Key Pair

fn login(username: &String, password: &String) -> Result<()> {
    //check_credentials(username, password)?;
    let master_key = match key_derivation_function(username, password){
        Ok(key) => hex::encode(key),
        Err(e) => return Err(anyhow!("Error deriving master key using Argon2: {}", e)),
    };
    println!("Master Key: {}", master_key);
    let master_password_hash = match key_derivation_function(password, &master_key){
        Ok(key) => hex::encode(key),
        Err(e) => return Err(anyhow!("Error deriving master password hash using Argon2: {}", e)),
    };
    println!("Master Password Hash: {}", master_password_hash);
    //decrypt_database(username, password)?;
    Ok(())
}

fn audit_session(_username: &String) -> Result<()> {
    // decrypt the database
    // print out all of the services and passwords
    Ok(())
}

fn logout(_username: &String, _password: &String) -> Result<()> {
    // remove the decrypted database
    // return Ok(())
    Ok(())
}

fn main() -> Result<()> {
    let env_key = "current_user";
    
    let mut current_user = String::new();
    if !env::var(env_key).is_err() {
        current_user = env::var(env_key)?;
    }

    let args = PwmParse::parse();

    let _ = match args.command {
        Command::Login(args) => {
            print!("Enter {}'s master password: ", args.username);
            std::io::stdout().flush()?;
            let password = rpassword::read_password()?;
            login(&args.username, &password)?;
            current_user = args.username;
            println!("Logged in as {}", current_user);
        },
        Command::Session(args) => {
            if current_user.is_empty() { return Err(anyhow!("You must be logged in to audit a session")); }
            print!("Enter {}'s master password: ", current_user);
            std::io::stdout().flush()?;
            let _password = rpassword::read_password()?;
            if args.audit == Some(true) { audit_session(&current_user)?; }
            else { println!("Logged in as {}", current_user); }
        },
        Command::Logout(args) => {
            print!("Enter {}'s master password: ", args.username);
            std::io::stdout().flush()?;
            let _password = rpassword::read_password()?;
            // TODO: handle logout request
            println!("Logging out user {}", args.username);
        },
        Command::Add(add)  => {
            println!("Command: {:?}", add);
            let service = add.service_name;
            let password = add.password;
            println!("Service: {}", service);
            println!("Password: {}", password);
            // ask user for master key
            // if not authenticated:
                // inform user of incorrect password, quit
            // else:
                // search for service in database
                // if found
                    // inform user that service already exists
                    // Display existing password
                    // if they decide to keep existing password
                        // acknowledge, then quit 
                    // else:
                        // acknowledge, update password, then quit
                // else:
                    // add service and password to database
                // inform user of the result
        },
        Command::Get(get) => {
            println!("Command: {:?}", get);
            // ask user for master key
            // if not authenticated, inform user of incorrect password, quit
            // if authenticated:
            // search for service in database
            // if found, decrypt and display password
            // else inform user that service was not found
        },
        Command::Delete(delete) => {
            println!("Command: {:?}", delete);
        },
        Command::List(list) => {
            println!("Command: {:?}", list);
        },
    };

    env::set_var(env_key, current_user);
    if !env::var(env_key).is_err() {
        println!("Current user: {}", env::var(env_key)?);
    }
 
    //println!("Enter in a string below:");
    //let line: String = read!("{}\n");
    //println!("You entered: {}", line);

    // parse command line arguments
    // pwm --version
    // pwm --help
    // pwm login <username>
    // pwm session <audit>
    // pwm logout <username>
    // pwm list <include_password>
    // pwm add <service name> <password>
    // pwm get <service name>
    // pwm remove <service name>
    Ok(())
} 
