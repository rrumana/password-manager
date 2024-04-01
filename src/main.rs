mod args;

use args::*;
use clap::Parser;

fn main() {
    //println!("Welcome to Password Manager!");

    let args = PwmParse::parse();

    println!("{:?}", args);
    
    let command = match args.command {
        Command::Add(add)  => {
            println!("Command: {:?}", add);
            let service = add.service_name;
            let password = add.password;
            println!("Service: {}", service);
            println!("Password: {}", password);
        },
        Command::Get(get) => {
            println!("Command: {:?}", get);
        },
        Command::Delete(delete) => {
            println!("Command: {:?}", delete);
        },
        Command::List(list) => {
            println!("Command: {:?}", list);
        },
    };

    println!("{:?}", command);

    //println!("Enter in a string below:");
    //let line: String = read!("{}\n");
    //println!("You entered: {}", line);

    // parse command line arguments
    // pwm --version
    // pwm --help
    // pwm list <include_password>
    // pwm add <service name> <password>
    // pwm get <service name>
    // pwm remove <service name>
} 
