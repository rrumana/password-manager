mod crypto;
mod password;

use log::{info, error, trace};

use read_input::prelude::*;
use::chrono::prelude::*;
use std::fs::File;
use std::fs::OpenOptions;
use rusqlite::Connection;

use rpassword::read_password;
use std::io::Write;
use std::io;
use std::io::prelude::*;
use std::collections::HashMap;
use anyhow::{anyhow, Result};

#[derive(Debug)]
pub struct Session {
    usermap: HashMap<[u8; 32], [u8; 44]>,
    passmap: HashMap<String, [u8; 32]>,
    active: bool,
    username: String,
    symmetric_key: Vec<u8>,
    conn: Connection,
 }

fn signup(session: &mut Session) -> Result<()> {
    let username = input::<String>()
        .repeat_msg("Enter username: ")
        .add_err_test(|x| x.len() >= 8, "Username must be at least 8 characters.")
        .add_err_test(|x| x.chars().any(|c| !c.is_whitespace()), "Username must not contain whitespace.")
        .try_get()?;

    // Should add check to see if username is already taken to avoid possible collisions and
    // fragmentation of the user database

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

    let master_key = crypto::kdf(&username, &password)?;
    let master_password_hash = crypto::kdf(&password, &hex::encode(&master_key))?;
    let stretched_master_key = crypto::hkdf(&master_key)?; 
    let symmetric_key = crypto::csprng::<32>();
    let protected_symmetric_key = crypto::encrypt_aes_gcm(&symmetric_key, &stretched_master_key)?.as_slice().try_into()?;

    assign_key(master_password_hash, protected_symmetric_key, session)?;
    login_handler(username, password, session)?; 

    println!("Signup successful, welcome to Password Manager!\n");
    println!("You are now logged in!\n");

    Ok(())
}

fn assign_key(master_password_hash: [u8; 32], protected_symmetric_key: [u8; 44], session: &mut Session) -> Result<()> {
    
    // Send keys off to the server to be stored for later use
    // For now this is mediated by the session object, but in the future this will be broken off
    // into a server application

    session.usermap.insert(master_password_hash, protected_symmetric_key); 

    Ok(())
}

fn login_input(session: &mut Session) -> Result<()> {
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
    let master_key = crypto::kdf(&username, &password)?;
    let master_password_hash = crypto::kdf(&password, &hex::encode(&master_key))?;
    let stretched_master_key = crypto::hkdf(&master_key)?;

    let protected_symmetric_key = get_key(&master_password_hash, session)?;
    let symmetric_key = crypto::decrypt_aes_gcm(protected_symmetric_key, &stretched_master_key)?;

    password::decrypt_database(&username, &symmetric_key.as_slice().try_into()?)?;

    let conn = password::load_database(&username)?;

    session.active = true;
    session.username = username;
    session.symmetric_key = symmetric_key;
    session.conn = conn; 

    let mut session_log = File::create("logs/session.log")?; 
    session_log.write_all(format!("Session started at: {}\n", Local::now()).as_bytes())?;

    println!("Login successful, welcome back!\n");

    Ok(())
}

fn get_key<'a>(master_password_hash: &[u8; 32], session: &'a mut Session) -> Result<&'a [u8; 44]> {

    // search through the database of known users to see if the stretched master key is present
    // if so, recreate the UserKeys object abd send it back to the calling function
    
    let protected_symmetric_key = match session.usermap.get(master_password_hash) {
        Some(key) => key,
        None => {
            println!("Error: User not found.");
            return Err(anyhow!("User not found."));
        }
    };

    Ok(protected_symmetric_key)
}

fn logout(session: &mut Session) -> Result<()> {
    if !session.active {
        println!("Error: not logged in.");
        return Err(anyhow!("Cannot log out when not logged in."));
    }

    password::save_database(&session.conn, &session.username)?;
    password::encrypt_database(&session.username, &session.symmetric_key.as_slice().try_into()?)?;

    std::fs::remove_file("logs/session.log")?;

    session.active = false;
    session.username = String::new();
    session.symmetric_key = vec![0u8; 32];
    session.conn = Connection::open_in_memory()?;
    
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
    let session_log = File::open("logs/session.log")?;
    let lines = io::BufReader::new(session_log).lines();

    for line in lines {
        println!("{}", line?);
    }

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
    password::insert_password(&session.conn, &service, &password)?;
    password::save_database(&session.conn, &session.username)?;

    // write this action to the session log file
    let mut session_log = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open("logs/session.log")?;

    session_log.write_all(format!("At {}, {} added service {} with password {}\n", Local::now(), session.username, service, password).as_bytes())?;

    Ok(())
}

fn get(session: &mut Session) -> Result<()> {
    // check if user is logged in
    if !session.active {
        println!("Error: not logged in.");
        return Err(anyhow!("Cannot retrieve password while not logged in."));
    } 

    // get the service name
    let service = input::<String>()
        .repeat_msg("Enter the service name: ")
        .add_err_test(|x| !x.is_empty(), "Service name cannot be empty.")
        .try_get()?;

    // get the password for the specified service and print it
    let password = password::get_password(&session.conn, &service)?;
    println!("Password for {} is: {}", service, password);

    Ok(())
}

fn delete(session: &mut Session) -> Result<()> {
    if !session.active {
        println!("Error: not logged in.");
        return Err(anyhow!("Cannot delete password while not logged in."));
    }  
    
    let service = input::<String>()
        .repeat_msg("Enter the service name: ")
        .add_err_test(|x| !x.is_empty(), "Service name cannot be empty.")
        .try_get()?;

    let confirm = input::<String>()
        .repeat_msg("Are you sure you would like to delete entry?\nThis action cannot be undone (y/n): ")
        .add_err_test(|x| x == "y" || x == "n", "Please enter 'y' or 'n'.")
        .try_get()?;

    if confirm == "y" {
        password::delete_password(&session.conn, &service)?;
    } else {
        println!("Deletion cancelled.");
    }

    Ok(())
}

fn purge(session: &mut Session) -> Result<()> {
    if !session.active {
        println!("Error: not logged in.");
        return Err(anyhow!("Cannot delete account while not logged in."));
    } 

    let confirm = input::<String>()
        .repeat_msg("Are you sure you would like to delete user?\nThis action cannot be undone (YES/NO): ")
        .add_err_test(|x| x == "YES" || x == "NO", "Please enter 'YES' or 'NO'.")
        .try_get()?;

    if confirm == "YES" {
        password::delete_database(&session.conn)?;
        password::delete_user(&session.username)?;
    } else {
        println!("Deletion cancelled.");
    }

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
        "signup" => signup(session)?,
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
    let _ = std::fs::remove_file("logs/session.log");

    Ok(())
}


// end password manager functions
//////////////////////////////////////////////////////////////////////////////////////////////////

fn main() {

    match log4rs::init_file("log_config.yml", Default::default()) {
        Ok(_) => info!("New logging instance initialized"),
        Err(err) => eprintln!("Error: {}", err),
    }

    let mut session = Session {
        usermap: HashMap::new(),
        passmap: HashMap::new(),
        active: false,
        username: String::new(),
        symmetric_key: vec![0u8; 32],
        conn: match Connection::open_in_memory() {
            Ok(conn) => conn,
            Err(err) => {
                error!("Error: {}", err);
                return;
            }
        },
    };

    // start the client side gui here
    

    // test communication to server application (reqwest)
    //let response = match reqwest::blocking::get("http://127.0.0.1:6969").unwrap().text() {
    //    Ok(response) => response,
    //   Err(err) => {
    //        error!("Error: {}", err);
    //        return;
    //    },
    //};
    //println!("{:#?}", response);      

    println!("Welcome to Password Manager, here is a list of commands:\n");
    print_commands();

    loop{
        match handle_commands(&mut session) {
            Ok(true) => break,
            Err(err) => error!("Error: {}", err),
            _ => continue,
        }
    }

    match cleanup() {
        Ok(_) => info!("Successfully cleaned up system"),
        Err(err) => error!("Error: {}", err),
    };

    // this will be removed in favor of a more idiomatic approach once the program is more complete
    info!("Exiting Password Manager");
}
