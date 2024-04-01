mod args;

use args::PwmParse;
use clap::Parser;

fn main() {
    println!("Welcome to Password Manager!");

    let args = PwmParse::parse();

    println!("{:?}", args);

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
