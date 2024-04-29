mod crypto;
mod password;

use log::{info, warn, error, debug, trace};

use read_input::prelude::*;
use::chrono::prelude::*;
use std::fs::File;
use std::fs::OpenOptions;

use rpassword::read_password;
use std::os::unix::net::UnixStream;
use password::*;
use clap::Parser;
use std::io::Write;
use std::fs;
use std::io;
use std::io::prelude::*;
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

////////////////////////////////////////////////////////////////////////////////////////////////////
// start message passing structs

// struct to store user keys
// to be used as message body between server and client functions
#[derive(Debug)]
pub struct UserKeys {
    master_password_hash: [u8; 32],
    protected_symmetric_key: Vec<u8>,
    nonce: Nonce,
}

// Struct to store the session
// to be used as an intenal flag for the client
#[derive(Debug)]
pub struct Session {
    active: bool,
    username: String,
    symmetric_key: Vec<u8>,
    nonce: Nonce,
}

// Struct for logging session activity
// to be stored in a logfile that lasts the duration of the session
#[derive(Debug)]
pub struct Action {
    timestamp: DateTime<Local>,
    action: String,
    service: String,
    password: String,
}

// end message passing structs
////////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////
// signup functions

fn signup_input(session: &mut Session) -> Result<()> {
    trace!("Gathering inputs for signup.");

    // get username
    let username = input::<String>()
        .repeat_msg("Enter username: ")
        .add_err_test(|x| x.len() >= 8, "Username must be at least 8 characters.")
        .add_err_test(|x| x.chars().any(|c| !c.is_whitespace()), "Username must not contain whitespace.")
        .try_get()?;

    // get password and repeat until user confirms with matching password
    let mut password: String;
    let mut password_confirm: String;

    loop {
        password = input::<String>()
            .repeat_msg("Enter master password: ")
            .add_err_test(|x| x.len() >= 10, "Master password must contain at least 10 characters.")
            .add_err_test(|x| x.chars().any(|c| c.is_digit(10)), "Master password must contain at least one digit.")
            .try_get()?;

        password_confirm = input::<String>()
            .repeat_msg("Confirm master password: ")
            .try_get()?;

        if password == password_confirm {
            break;
        } else {
            println!("Error: Passwords do not match!");
        }
    }

    // pass username and password value onto the signup function
    signup_handler(username, password, session)?;

    println!("Signup successful, welcome to Password Manager!\n");

    // reutrn Ok if signup is successful
    Ok(())
}

fn signup_handler(username: String, password: String, session: &mut Session) -> Result<()> {
    trace!("Handling signup process");

    // generating keys from user input
    let master_key = crypto::kdf(&username, &password)?;
    let master_password_hash = crypto::kdf(&password, &hex::encode(&master_key))?;
    let stretched_master_key = crypto::hkdf(&master_key)?;
    
    // generate a symmetric key and nonce for the user
    let symmetric_key = crypto::csprng::<32>();
    let iv = crypto::csprng::<12>(); 
    let nonce = *Nonce::from_slice(&iv);

    // encrypt the symmetric key using the stretched master key
    let protected_symmetric_key = crypto::encrypt_aes_gcm(&symmetric_key, &stretched_master_key, &nonce)?;

    // create a UserKeys object to store the keys
    let keys = UserKeys {
        master_password_hash,
        protected_symmetric_key,
        nonce,
    };

    // pass the master_password_hash, protected_symmetric_key, and nonce to be stored for retrieval upon login
    assign_key(&keys)?;

    // log in as a convenience to the user
    login_handler(username, password, session)?;
    
    Ok(())
}

fn assign_key(keys: &UserKeys) -> Result<()> {
    
    // take user keys object and store it in the database of known users
    // immediately save database of known users to disk
    // return Ok if succesful

    Ok(())
}

// end signup functions
//////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////
// start login/logout functions

fn login_input(session: &mut Session) -> Result<()> {
    // do input for login, loop until successful
    loop {
        let username = input::<String>()
            .repeat_msg("Enter your username: ")
            .try_get()?;

        print!("Enter your password: ");
        io::stdout().flush()?;
        let password = read_password()?;

        match login_handler(username, password, session) {
            Ok(_) => {
                println!("Login successful, welcome back!\n");
                break;
            }
            Err(err) => {
                println!("Error: Invalid username or password, please try again.\n");
                trace!("Error: {}", err);
                continue;
            }
        }
    }

    Ok(())
}

fn login_handler(username: String, password: String, session: &mut Session) -> Result<()> {
    // generating keys from user input
    let master_key = crypto::kdf(&username, &password)?;
    let master_password_hash = crypto::kdf(&password, &hex::encode(&master_key))?;
    let stretched_master_key = crypto::hkdf(&master_key)?;

    // get the UserKeys object from the database of known users
    let keys = get_key(&master_password_hash)?;

    // decrypt protected symmetric key using the stretched master key
    let symmetric_key = crypto::decrypt_aes_gcm(&keys.protected_symmetric_key, &stretched_master_key, &keys.nonce)?;

    // load values into the current session object
    session.active = true;
    session.username = username;
    session.symmetric_key = symmetric_key;
    session.nonce = keys.nonce;

    // create session logfile
    let mut session_log = File::create("logs/session.log")?; 
    session_log.write_all(format!("Session started at: {}\n", Local::now()).as_bytes())?;

    Ok(())
}

fn get_key(master_password_hash: &[u8; 32]) -> Result<UserKeys> {

    // search through the database of known users to see if the stretched master key is present
    // if so, recreate the UserKeys object abd send it back to the calling function
    let keys = UserKeys {
        master_password_hash: *master_password_hash,
        protected_symmetric_key: vec![0u8; 32],
        nonce: *Nonce::from_slice(&[0u8; 12]),
    };

    Ok(keys)
}

fn logout(session: &mut Session) -> Result<()> {
    // delete session log file
    std::fs::remove_file("logs/session.log")?; 

    // zero the session object
    session.active = false;
    session.username = String::new();
    session.symmetric_key = vec![0u8; 32];
    session.nonce = *Nonce::from_slice(&[0u8; 12]);

    Ok(())
}

// end login/logout functions
//////////////////////////////////////////////////////////////////////////////////////////////////////

fn user(session: &mut Session) -> Result<()> {
    // checking if the user is logged in
    if !session.active {
        println!("Error: not logged in.");
        return Err(anyhow!("Cannot audit user while not logged in."));
    }

    println!("User: {}", session.username);

    Ok(())
}

fn audit(session: &mut Session) -> Result<()> {
    // check if user is logged in
    if !session.active {
        println!("Error: not logged in.");
        return Err(anyhow!("Cannot audit session while not logged in."));
    }

    println!("Printing session info for {}:", session.username);

    // TODO: read the session log file and print the contents

    Ok(())
}

fn put(session: &mut Session) -> Result<()> {
    // check if user is logged in
    if !session.active {
        println!("Error: not logged in.");
        return Err(anyhow!("Cannot add password while not logged in."));
    }

    // get the service name
    let service = input::<String>()
        .repeat_msg("Enter the service name: ")
        .add_err_test(|x| !x.is_empty(), "Service name cannot be empty.")
        .try_get()?;
    
    // ask user whether they will be providing a password or generating one
    let provide = input::<String>()
        .repeat_msg("Will you be providing a password (NOT RECOMMENDED)? (y/n): ")
        .add_err_test(|x| x == "y" || x == "n", "Please enter 'y' or 'n'.")
        .try_get()?;

    
    // get the password or generate a random one
    let password = match provide.as_str() {
        "y" => input::<String>()
                .repeat_msg("Enter the password: ")
                .add_err_test(|x| !x.is_empty(), "Password cannot be empty.")
                .add_err_test(|x| x.len() >= 10, "Password must be at least 10 characters.")
                .try_get()?,
        "n" => hex::encode(crypto::csprng::<32>()),
        &_ => { return Err(anyhow!("Error: How did we get here?")); }
    };

    // add this password to the username's password database
    

    // write this action to the session log file
    let mut session_log = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open("logs/session.log")?;

    session_log.write_all(format!("At {}, {} added service {} with password {}\n", Local::now(), session.username, service, password).as_bytes())?;

    // return Ok if successful
    Ok(())
}

fn get(session: &mut Session) -> Result<()> {
    // get the service name
    let service = input::<String>()
        .repeat_msg("Enter the service name: ")
        .add_err_test(|x| !x.is_empty(), "Service name cannot be empty.")
        .try_get()?;

    // Need to have some sort of flag to determine if logged in and how to retrieve username
    // if user is not logged in return an error 
    
    // get the password for the specified service
    // return the password for the specified service if it exists, otherwise return an error

    // return Ok if successful
    Ok(())
}


fn delete(session: &mut Session) -> Result<()> {
    // get the service name
    let service = input::<String>()
        .repeat_msg("Enter the service name: ")
        .add_err_test(|x| !x.is_empty(), "Service name cannot be empty.")
        .try_get()?;

    // remove the password for the specified service
    // Need to have some sort of flag to determine if logged in and how to retrieve username

    // return Ok if successful
    Ok(())
}

fn purge(session: &mut Session) -> Result<()> {
    // remove the user's password database
    // Need to have some sort of flag to determine if logged in and how to retrieve username

    // return Ok if successful
    Ok(())
}

fn handle_commands(session: &mut Session) -> Result<bool> {
    trace!("Handling next command");
    
    // open the map of known users from the save file and store it in memory

    let command: String = match input().msg("Enter a command: ").try_get() {
        Ok(input) => {
            println!("You entered: {}\n", input);
            input
        }
        Err(err) => {
            println!("Error: Invalid input {}", err);
            return Err(anyhow!("Error: Invalid input"));
        }
    };

    match command.as_str() {
        "signup" => signup_input(session)?,
        "login" => login_input(session)?,
        "user" => user(session)?,
        "session" => audit(session)?,
        "put" => put(session)?,
        "get" => get(session)?,
        "help" => print_commands(),
        "logout" => logout(session)?,
        "delete" => delete(session)?,
        "purge" => purge(session)?,
        "exit" => return Ok(true),
        _ => error!("Error: Invalid command"),
    };

    Ok(false)
}

fn print_commands() {
    info!("Printing list of commands");
    println!("Commands:");
    println!("signup - Create a new account");
    println!("login - Log user into their account");
    println!("put - Add a new password to your collection");
    println!("get - Get the password for a specified service");
    println!("help - Print this list of commands");
    println!("logout - Log user out of their account");
    println!("delete - Remove the entry for a specified service");
    println!("purge - Remove the entry for a specified user");
    println!("exit - Exit the program\n");
}

fn cleanup() -> Result<()> {
    // remove the session log file
    let _ = std::fs::remove_file("logs/session.log");

    Ok(())
}


// end password manager functions
//////////////////////////////////////////////////////////////////////////////////////////////////

fn main() {

    // initialize logging from configuration file
    // since this function is fallable we need to handle the result
    match log4rs::init_file("log_config.yml", Default::default()) {
        Ok(_) => info!("New logging instance initialized"),
        Err(err) => eprintln!("Error: {}", err),
    }

    // create a session instance
    let mut session = Session {
        active: false,
        username: String::new(),
        symmetric_key: vec![0u8; 32],
        nonce: *Nonce::from_slice(&[0u8; 12]),
    };

    // start the client side gui here
    

    // test communication to server application (Unix Socket)
    

    // print the welcome message and list of commands
    println!("Welcome to Password Manager, here is a list of commands:\n");
    print_commands();

    // loop while handling user input until the user exits the program
    // Recoverable errors propagated back to main are logged and the loop continues
    loop{
        match handle_commands(&mut session) {
            Ok(true) => break,
            Err(err) => error!("Error: {}", err),
            _ => continue,
        }
    }

    // cleanup function to remove the session log file
    match cleanup() {
        Ok(_) => info!("Successfully cleaned up system"),
        Err(err) => error!("Error: {}", err),
    };

    // this line signifies in the log that the program is exiting
    // this will be removed in favor of a more idiomatic approach once the program is more complete
    info!("Exiting Password Manager");
}
