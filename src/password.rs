use crate::crypto;

use std::io::{Write, Read, BufWriter, BufReader};
use std::fs;
use std::fs::File;
use std::path::Path;
use anyhow::Result;
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

pub fn create_database() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            password TEXT NOT NULL
        )",
        (),
    )?;

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
    let query = format!("Select * FROM passwords WHERE service = '{}'", service);
    let mut stmt = conn.prepare(&query)?;

    let rows = stmt.query_map([], |row| {
        Ok(Password {
            id: row.get(0)?,
            service: row.get(1)?,
            password: row.get(2)?,
        })
    })?;

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
    let mut stmt = conn.prepare("Select * FROM passwords")?;

    let password_iter = stmt.query_map([], |row| {
        Ok(Password {
            id: row.get(0)?,
            service: row.get(1)?,
            password: row.get(2)?,
        })
    })?;

    for password in password_iter {
        println!("Password: {:?}", password?);
    }
 
    Ok(())
}

pub fn check_directories() -> Result<()> {
    fs::create_dir_all("database/unencrypted")?;
    fs::create_dir_all("database/encrypted")?;
    Ok(())
}

pub fn save_database(conn: &Connection, username: &str) -> Result<()> {
    match check_directories() {
        Ok(_) => (),
        Err(err) => return Err(anyhow::anyhow!("Error verifying database directories: {}", err)),
    };

    let db_file = File::create(format!("database/unencrypted/{}.db", username))?;
    let mut writer = BufWriter::new(db_file);
    let mut stmt = conn.prepare("Select * FROM passwords")?;

    let password_iter = stmt.query_map([], |row| {
        Ok(Password {
            id: row.get(0)?,
            service: row.get(1)?,
            password: row.get(2)?,
        })
    })?;

    let vector_of_passwords: Vec<Password> = password_iter.map(|x| x.unwrap()).collect();
    let serialized = serde_json::to_string(&vector_of_passwords)?;
    writer.write_all(serialized.as_bytes())?;
 
    Ok(())
}

pub fn load_database(username: &str) -> Result<Connection> {
    match check_directories() {
        Ok(_) => (),
        Err(err) => return Err(anyhow::anyhow!("Error verifying database directories: {}", err)),
    };

    let filepath = format!("database/unencrypted/{}.db", username);
    let conn = create_database()?;

    if Path::new(&filepath).exists() {
        let db_file = File::open(filepath)?;
        let mut reader = BufReader::new(db_file);
        let passwords: Vec<Password> = serde_json::from_reader(&mut reader)?;

        for password in passwords {
            insert_password(&conn, &password.service, &password.password)?;
        }
    }

    Ok(conn)
}

pub fn delete_user(username: &str) -> Result<()> {
    match check_directories() {
        Ok(_) => (),
        Err(err) => return Err(anyhow::anyhow!("Error verifying database directories: {}", err)),
    };

    if Path::new(&format!("database/unencrypted/{}.db", username)).exists() {
        std::fs::remove_file(format!("database/unencrypted/{}.db", username))?;
    }
    if Path::new(&format!("database/encrypted/{}.db.enc", username)).exists()  {
        std::fs::remove_file(format!("database/encrypted/{}.db.enc", username))?;
    }

    Ok(())
}

pub fn encrypt_database(username: &str, symmetric_key: &[u8; 32]) -> Result<()> {
    match check_directories() {
        Ok(_) => (),
        Err(err) => return Err(anyhow::anyhow!("Error verifying database directories: {}", err)),
    };

    let filepath = format!("database/unencrypted/{}.db", username);
    let mut plaintext_file = File::open(&filepath)?;

    let mut plaintext = Vec::new();
    plaintext_file.read_to_end(&mut plaintext)?;

    let encrypted_data = crypto::encrypt_aes_gcm(&plaintext, symmetric_key)?;

    let savepath = format!("database/encrypted/{}.db.enc", username);
    let mut encrypted_file = File::create(savepath)?;
    encrypted_file.write_all(&encrypted_data)?;

    fs::remove_file(filepath)?;

    Ok(())
}

pub fn decrypt_database(username: &str, symmetric_key: &[u8; 32]) -> Result<()> {
    match check_directories() {
        Ok(_) => (),
        Err(err) => return Err(anyhow::anyhow!("Error verifying database directories: {}", err)),
    };

    let filepath = format!("database/encrypted/{}.db.enc", username);
    let mut encrypted_file = File::open(&filepath)?;

    let mut encrypted_data = Vec::new();
    encrypted_file.read_to_end(&mut encrypted_data)?;

    let plaintext = crypto::decrypt_aes_gcm(&encrypted_data, symmetric_key)?;

    let savepath = format!("database/unencrypted/{}.db", username);
    let mut plaintext_file = File::create(savepath)?;
    plaintext_file.write_all(&plaintext)?;

    fs::remove_file(filepath)?;

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
