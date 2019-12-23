mod validator;

use clap::{Arg,App};

pub fn brb_app <'a,'b> () -> App<'a, 'b> {

    let arg_storage_dir = Arg::with_name("storage_dir")
        .takes_value(true)
        .long("dir")
        .short("d")
        .env("BRB_STORAGE_DIR")
        .help("Full path to the local block storage directory");

    let arg_trusted_keys_file = Arg::with_name("trusted_keys_file")
        .takes_value(true)
        .long("keys")
        .short("k")
        .env("BRB_TRUSTED_KEYS_FILE")
        .help("Full path to the file that contains one or more public keys to verify incomming block signatures with");

    let arg_bind_addr = Arg::with_name("bind_addr")
        .takes_value(true)
        .long("addr")
        .short("a")
        .env("BRB_BIND_ADDR")
        .help("Address & port to listen for incoming requests on")
        .long_help("Address & port to listen for incoming requests on.\nExamples: 127.0.0.1:3000, 0.0.0.0:8080");

    App::new("brb")
        .version("0.1")
        .author("Kirk P. <necrobious@gmail.com>")
        .about("Block Repository Broker")
        .arg(arg_storage_dir
            .clone()
            .required(true)
            .validator_os(validator::is_readable_dir))
        .arg(arg_trusted_keys_file
            .clone()
            .required(true)
            .validator_os(validator::is_readable_file))
        .arg(arg_bind_addr
            .clone()
            .required(true)
            .validator(validator::is_network_addr))
}
