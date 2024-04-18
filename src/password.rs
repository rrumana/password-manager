use crate::crypto;

use std::io::{Write, Read, BufWriter, BufReader};
use std::fs::File;
use std::path::Path;
use anyhow::Result;
use aes_gcm_siv::Nonce;
use serde::{Serialize, Deserialize};
use rusqlite::Connection;

// A custom struct to store the service and password for each entry
// This represents one row in the user's table in the database
// Encrypted and saved to disk
#[derive(Debug, Serialize, Deserialize)]
pub struct Password {
    pub id: i32,
    pub service: String,
    pub password: String,
}

// A custom struct to store the username and nonce for each user
// saved to disk as is
#[derive(Debug, Serialize, Deserialize)]
pub struct UserNonce {
    pub username: String,
    pub nonce: [u8; 12],
}

pub fn create_database() -> Result<Connection> {
    // create a new in-memory database
    let conn = Connection::open_in_memory()?;

    // execute sql command to create password table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            password TEXT NOT NULL
        )",
        (),
    )?;

    // if successful return the connection
    Ok(conn)
}

pub fn delete_database(conn: &Connection) -> Result<()> {
    conn.execute(
        "DROP TABLE IF EXISTS passwords",
        (),
    )?;
    Ok(())
}

pub fn insert_password(conn: &Connection, service: &str, password: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO passwords (service, password) VALUES (?1, ?2)",
        &[service, password],
    )?;
    Ok(())
}

pub fn update_password(conn: &Connection, service: &str, password: &str) -> Result<()> {
    conn.execute(
        "UPDATE passwords SET password = ?1 WHERE service = ?2",
        &[password, service],
    )?;
    Ok(())
}

pub fn get_password(conn: &Connection, service: &str) -> Result<String> {
    // prepare sql query to select all rows where the service matches the input
    let query = format!("Select * FROM passwords WHERE service = '{}'", service);
    let mut stmt = conn.prepare(&query)?;

    // execute the statement and map the results to a Password struct
    let rows = stmt.query_map([], |row| {
        Ok(Password {
            id: row.get(0)?,
            service: row.get(1)?,
            password: row.get(2)?,
        })
    })?;

    // iterate over results and return the password
    // if more than one password is found, discard all but first (Temporary measure)
    // if no password is found, return an error
    let password: Password = match rows.into_iter().nth(0) {
        Some(password) => password?,
        None => return Err(anyhow::anyhow!("No password found")),
    };

    Ok(password.password)
}

pub fn delete_password(conn: &Connection, service: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM passwords WHERE service = ?1",
        &[service],
    )?;
    Ok(())
}

pub fn print_database(conn: &Connection) -> Result<()> {
    // prepare sql query to select all rows
    let mut stmt = conn.prepare("Select * FROM passwords")?;

    // execute the query and map the results to a Password struct
    let password_iter = stmt.query_map([], |row| {
        Ok(Password {
            id: row.get(0)?,
            service: row.get(1)?,
            password: row.get(2)?,
        })
    })?;

    // iterate over the results and print them (debug only)
    for password in password_iter {
        println!("Password: {:?}", password?);
    }
 
    // return Ok if successful
    Ok(())
}

pub fn save_database(conn: &Connection, username: &str) -> Result<()> {
    // open database file for writing
    let db_file = File::create(format!("{}.db", username))?;

    // create a buffwriter to write to the file
    let mut writer = BufWriter::new(db_file);

    // prepare a sql statement to select all from the passwords in the table
    let mut stmt = conn.prepare("Select * FROM passwords")?;

    // execute the statement and map the results to a Password struct
    let password_iter = stmt.query_map([], |row| {
        Ok(Password {
            id: row.get(0)?,
            service: row.get(1)?,
            password: row.get(2)?,
        })
    })?;

    // iterate over the results and add them to a vector
    let vector_of_passwords: Vec<Password> = password_iter.map(|x| x.unwrap()).collect();

    // serialize the vector and write it to the file
    let serialized = serde_json::to_string(&vector_of_passwords)?;
    writer.write_all(serialized.as_bytes())?;
 
    // return Ok if successful
    Ok(())
}

pub fn load_database(username: &str) -> Result<Connection> {
    // open the databse file for reading
    let db_file = File::open(format!("{}.db", username))?;

    // creater a reader and a buffer to read into
    let mut reader = BufReader::new(db_file);

    // initialize a new in-memory database and create password table
    let conn = Connection::open_in_memory()?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            password TEXT NOT NULL
        )",
        (),
    )?;

    // deserialize the buffer into a vec of Password structs
    let passwords: Vec<Password> = serde_json::from_reader(&mut reader)?;

    // insert each password into the database
    for password in passwords {
        insert_password(&conn, &password.service, &password.password)?;
    }

    // if successful return the connection
    Ok(conn)
}

pub fn delete_user(username: &str) -> Result<()> {
    // check if typical database file exists, if so delete it
    if Path::new(&format!("{}.db", username)).exists() {
        std::fs::remove_file(format!("{}.db", username))?;
    }
    // check if encrypted database file exists, if so delete it
    if Path::new(&format!("{}.db.enc", username)).exists()  {
        std::fs::remove_file(format!("{}.db.enc", username))?;
    }

    // check if nonce file exists, if so delete it
    if Path::new(&format!("{}_nonce.txt", username)).exists() {
        std::fs::remove_file(format!("{}_nonce.txt", username))?;
    }

    // return ok if successful
    Ok(())
}

pub fn encrypt_database(username: &str, symmetric_key: &[u8; 32]) -> Result<()> {
    // create filepaths
    let filepath = format!("{}.db", username);
    let savepath = format!("{}.db.enc", username);
    let nonces = format!("{}_nonce.txt", username);

    // create nonce
    let iv: [u8; 12] = crypto::csprng();
    let nonce = Nonce::from_slice(&iv);

    // open db file for reading, encrypted file for writing
    let mut db_file = File::open(filepath)?;
    let mut encrypted_file = File::create(savepath)?;
    
    // create buffer of 16 bytes
    const BUFFER_SIZE: usize = 16;
    let mut buffer = [0u8; BUFFER_SIZE];

    // while loop
    // read from db file, encrypt, write to encrypted file until end of file is reached
    loop {
        let bytes = db_file.read(&mut buffer)?;
        if bytes == BUFFER_SIZE {
            let encrypted_buffer = crypto::encrypt_aes_gcm(&buffer, symmetric_key, &nonce)?;
            encrypted_file.write(&encrypted_buffer)?;
        } else {
            let encrypted_buffer = crypto::encrypt_aes_gcm(&buffer[..bytes], symmetric_key, &nonce)?;
            encrypted_file.write(&encrypted_buffer)?;
            break;
        }
    }

    // capture current state of the nonce in slice
    let nonce_vec = nonce.to_vec();
    let nonce_slice = &nonce_vec[..];

    // save nonce in UserNonce struct
    let temp_nonce = UserNonce {
        username: username.to_string(),
        nonce: nonce_slice.try_into()?,
    };

    // serialize struct and write data to nonces file
    serde_json::to_writer(&mut File::create(nonces)?, &temp_nonce)?;

    // return Ok if successful
    Ok(())
}

pub fn decrypt_database(username: &str, symmetric_key: &[u8; 32]) -> Result<()> {
    // create filepaths
    let filepath = format!("{}.db.enc", username);
    let savepath = format!("{}.db", username);
    let user_filepath = format!("{}_nonce.txt", username);

    
    // open nonces file for reading
    let nonce_file = File::open(user_filepath)?;

    // read contents of file into UserNonce object
    let usernonce: UserNonce = serde_json::from_reader(nonce_file)?;
    let nonce = Nonce::from_slice(&usernonce.nonce);

    let mut encrypted_file = File::open(filepath)?;
    let mut db_file = File::create(savepath)?;
    
    // create buffer of 32 bytes
    const BUFFER_SIZE: usize = 32;
    let mut buffer = [0u8; BUFFER_SIZE];

    // while loop
    // read from encrypted file, decrypt, write to db file until end of file is reached
    loop {
        let bytes = encrypted_file.read(&mut buffer)?;
        if bytes == BUFFER_SIZE {
            let decrypted_buffer = crypto::decrypt_aes_gcm(&buffer, symmetric_key, &nonce)?;
            db_file.write(&decrypted_buffer)?;
        } else if bytes == 0 {
            break;
        } else {
            let decrypted_buffer = crypto::decrypt_aes_gcm(&buffer[..bytes], symmetric_key, &nonce)?;
            db_file.write(&decrypted_buffer)?;
            break;
        }
    }

    // return Ok if successful
    Ok(())
}

#[cfg(test)]
mod password_tests {
    use super::*;

    // This test ensures program doesn't blow up when databases are be created
    #[test]
    fn test_create() {
        assert!(create_database().is_ok());
    }

    // This test ensures databases can be inserted into and verifies the output
    #[test]
    fn test_insert() {
        let conn = create_database().unwrap();
        assert!(insert_password(&conn, "password_manager", "password123").is_ok());
        assert!(get_password(&conn, "password_manager").is_ok()); 
        assert!(get_password(&conn, "password_manager").unwrap() == "password123");
    }

    // This test ensures rows can be updated and verifies the output
    #[test]
    fn test_row_update() {
        let conn = create_database().unwrap();
        let _ = insert_password(&conn, "password_manager", "password123").unwrap();
        assert!(get_password(&conn, "password_manager").is_ok()); 
        assert!(get_password(&conn, "password_manager").unwrap() == "password123");
        assert!(update_password(&conn, "password_manager", "password456").is_ok());
        assert!(get_password(&conn, "password_manager").unwrap() == "password456");
    }

    // This test ensures rows can be deleted and verifies the output
    #[test]
    fn test_row_delete() {
        let conn = create_database().unwrap();
        let _ = insert_password(&conn, "password_manager", "password123").unwrap();
        assert!(get_password(&conn, "password_manager").is_ok()); 
        assert!(get_password(&conn, "password_manager").unwrap() == "password123");
        assert!(delete_password(&conn, "password_manager").is_ok());
        assert!(get_password(&conn, "password_manager").is_err());
    }

    // This test ensures databases can be deleted correctly
    #[test]
    fn test_table_delete() {
        let conn = create_database().unwrap();
        let _ = insert_password(&conn, "password_manager", "password123").unwrap();
        assert!(delete_database(&conn).is_ok());
        assert!(get_password(&conn, "password_manager").is_err());
    }

    // This test ensures databases can be saved and loaded properly and verifies the data
    #[test]
    fn test_save() {
        let conn = create_database().unwrap();
        let _ = insert_password(&conn, "password_manager", "password123");
        assert!(save_database(&conn, "test_username1").is_ok());
        let _ = delete_database(&conn);
        let load_result = load_database("test_username1");
        assert!(load_result.is_ok());
        let conn = load_result.unwrap();
        assert!(get_password(&conn, "password_manager").is_ok());
        assert!(get_password(&conn, "password_manager").unwrap() == "password123");
        let _ = delete_user("test_username1");
    }

    // This tests if databases can be encryptd and decrypoted while maintaining data integrity
    #[test]
    fn test_encrypt() {
        let conn = create_database().unwrap();
        let _ = insert_password(&conn, "password_manager", "password123");
        let _ = save_database(&conn, "test_username2");
        let symmetric_key = crypto::csprng::<32>();
        assert!(encrypt_database("test_username2", &symmetric_key).is_ok());
        assert!(decrypt_database("test_username2", &symmetric_key).is_ok());
        let conn = load_database("test_username2").unwrap();
        assert!(get_password(&conn, "password_manager").is_ok());
        assert!(get_password(&conn, "password_manager").unwrap() == "password123");
        let _ = delete_user("test_username2");
    }

    // This test ensures that user information can be deleted correctly
    #[test]
    fn test_user_delete() {
        let conn = create_database().unwrap();
        let _ = insert_password(&conn, "password_manager", "password123");
        let _ = get_password(&conn, "password_manager");
        let _ = save_database(&conn, "test_username3");
        let _ = encrypt_database("test_username3", &crypto::csprng::<32>());
        assert!(delete_user("test_username3").is_ok());
        assert!(Path::new("test_username3.db").exists() == false);
        assert!(Path::new("test_username3.db.enc").exists() == false);
        assert!(Path::new("test_username3_nonce.txt").exists() == false);
    }

}
