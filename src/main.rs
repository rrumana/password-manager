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
    println!("Beginning cryptography.");

    let master_key = crypto::kdf(username, password)?;
    println!("Master key: {}", hex::encode(master_key));
    
    let master_password_hash = crypto::kdf(password, &hex::encode(master_key))?;
    println!("Master password hash: {}", hex::encode(master_password_hash));
    
    let stretched_master_key = crypto::hkdf(&master_key)?;
    println!("Stretched Master Key: {}", hex::encode(stretched_master_key));
    
    let symmetric_key: [u8; 32] = crypto::csprng();
    println!("Symmetric Key: {}", hex::encode(symmetric_key));

    let iv: [u8; 12] = crypto::csprng();
    let nonce = Nonce::from_slice(&iv);
    println!("Initialization Vector: {}", hex::encode(iv));

    let protected_symmetric_key: &[u8] = &crypto::encrypt_aes_gcm(&symmetric_key, &stretched_master_key, &nonce)?; 
    println!("Protected Symmetric Key: {}", hex::encode(protected_symmetric_key));

    let unprotected_symmetric_key: &[u8] = &crypto::decrypt_aes_gcm(&protected_symmetric_key, &stretched_master_key, &nonce)?; 
    println!("Decrypted Symmetric Key: {}", hex::encode(unprotected_symmetric_key)); 
    println!("Cryptography complete.");
    println!("");

    println!("Beginning database operations.");
    // create database
    let conn = create_database()?;

    let test_password1 = Password {
        id: 0,
        service: "hulu.com".to_string(),
        password: "abc123".to_string(),
    };

    let test_password2 = Password {
        id: 0,
        service: "hulu.com1".to_string(),
        password: "abc12983746534".to_string(),
    }; 
    
    let test_password3 = Password {
        id: 0,
        service: "hulu.com2".to_string(),
        password: "abc1233".to_string(),
    }; 


    // put something into database
    println!("Inserting passwords into database:");
    insert_password(&conn, &test_password1.service, &test_password1.password)?;
    insert_password(&conn, &test_password2.service, &test_password2.password)?;
    insert_password(&conn, &test_password3.service, &test_password3.password)?;

    // print out database
    println!("Printing Unprotected database:");
    print_database(&conn)?;

    //save database
    println!("Saving database:");
    save_database(&conn, &username)?;

    // encrypt database
    println!("Encrypting database:");
    encrypt_database(&username, &symmetric_key)?;

    // delete unencrypted database
    println!("Deleting unencrypted database:"); 
    fs::remove_file("rcrumana.db")?;

    // decrypt database
    println!("Recovering original databse through encryption:");
    decrypt_database(&username, &symmetric_key)?;

    // printing database after decryption
    println!("Loading unprotected database into memory:");
    let new_conn = load_database(&username)?;

    println!("Printing unprotected database:");
    print_database(&new_conn)?;

    println!("Database operations complete.");

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
