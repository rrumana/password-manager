# Password-Manager

I am attempting to write my own password manager in Rust.

Naive implementation of the cryptography has been finished:
  - Using Argon2 for password hashing
  - Using HKDF to stretch master key into longer key
  - Using CSPRNG for databse encryption keys and initialization vectors
  - AES-256-GCM-SIV for encryption of both the database encryption keys and the database itself

This model will make more sense with the addition of a server side application holding onto encrypted databse encryption keys. Currently they are stored locally, which is unsafe, but temporary.

The database implementation has been finished, including encryption and decryption using AES. Storing the usernames and initialization vectors in a text file feels wrong but neither needs any real protection for the encryption to remain secure. I will find a more permanent home for those as well. I am envisioning the storage file being encrypted until server side verification of a correct master password hash, but that is far off into the future.

Next steps for this project are (in the order I plan to do them):
  - Implementing all of the CLI commands to work correctly (currently only the underlying functions have been impemented)
  - Create a logging system to more robustly handle errors / debugging
  - Create unit tests for modules and integration tests
  - Split server side and user side functionality
  - Front end modeling since this is currently a CLI appication
  - Create more secure storage of usernames and Initialization Vectors
  - probably ore stuff I cannot remember

USE AT YOUR OWN RISK!!
  - Although this project modeled to be secure, I am not a cybersecurity expert or cryptographic researcher, and therefore cannot gaurantee saftey past theory.
  - There is no way to recover lost passwords. If you happen to lose your master password there isn't anything I can do about it, and your data will remain encrypted.
  - Feel free to use this project in any way you like, but you and only you are responsible for any data loss, corruption, encryption, etc...
