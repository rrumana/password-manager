mod args;
mod crypto;
mod password;

use args::*;
use password::*;
use clap::Parser;
use std::io::Write;
use std::fs;
use anyhow::{anyhow, Result};
use std::env;
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

fn _check_credentials(_username: &String, _password: &String) -> Result<()> {
    // generate master password hash
    //let master_key = crypto::kdf(username, password)?;
    //let master_password_hash = crypto::kdf(password, &hex::encode(master_key))?;
    
    // if map does not contain master_password_hash
    // Map controlled by server side, make this first
    //return Err(anyhow!("Incorrect username or password"));
 
    // if it does, return Ok(()), 
    Ok(())
}

fn sign_up(username: &String, password: &String) -> Result<()> {
    let master_key = crypto::kdf(username, password)?;
    let master_password_hash = crypto::kdf(password, &hex::encode(master_key))?;
    let stretched_master_key = crypto::hkdf(&master_key)?;
    let symmetric_key: [u8; 32] = crypto::csprng();
    let iv: [u8; 12] = crypto::csprng();
    let nonce = Nonce::from_slice(&iv);
    let protected_symmetric_key: &[u8] = &crypto::encrypt_aes_gcm(&symmetric_key, &stretched_master_key, &nonce)?; 

    // send stretched master key and protected symmetric key to server

    // create user database
    let conn = create_database()?;

    // start user session

    // return Ok if successful
    Ok(())
}


fn login(_username: &String, _password: &String) -> Result<()> {
    // Check if the user exists
    // Decrypt user database
    // Start current user session
    Ok(())
}

fn audit_session() -> Result<()> {
    // print out session information
    Ok(())
}

fn _logout(_username: &String, _password: &String) -> Result<()> {
    // if username matches current session
    // remove the current session
    // save the database
    // the decrypted database
    // delete unencrypted database
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
        Command::Signup(args) => {
            print!("Enter {}'s master password: ", args.username);
            std::io::stdout().flush()?;
            let password = rpassword::read_password()?;
            sign_up(&args.username, &password)?;
            current_user = args.username;
            println!("Success, signed up user: {}!", current_user);
        },
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
            if args.audit == Some(true) { audit_session()?; }
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
 
    Ok(())
}

fn start_client() -> Result<()> {

    Ok(())
}

fn start_server() -> Result<()> {
    Ok(())
}

fn stop_client() -> Result<()> {
    Ok(())
}

fn stop_server() -> Result<()> {
    Ok(())
}
