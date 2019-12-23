use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::env;
use std::path::Path;

pub fn is_readable_file (path_os_str: &OsStr) -> Result<(), OsString> {
    fs::metadata(Path::new(path_os_str))
        .map_err(|_| {
            let mut msg = OsString::new();
            msg.push("Could not open file for reading: '");
            msg.push(path_os_str);
            msg.push("'. Either the path does not exit or you lack the permission to read from it.");
            msg
        })
        .and_then(|meta| {
            if meta.is_file() { Ok( () ) }
            else {
                let mut msg = OsString::new();
                msg.push("Path is not of type file: '");
                msg.push(path_os_str);
                msg.push("'.");
                Err(msg)
            }
        })
}

pub fn is_network_addr (bind: String) -> Result<(), String> {

    let addr_res = bind.parse();

    if addr_res.is_err() { return Err(format!("invalid addres and/or port number {}: {:?}", bind, addr_res )) }

    let addr : std::net::SocketAddr = addr_res.unwrap();

    if addr.port() > 1024 {
        return Ok(())
    }
    match env::var("USER") {
        Ok(ref val) if  val == "root" => Ok(()),
        _ => Err(format!("need root to bind to ports 1024 and below."))
    }

}


fn err_msg <'a> (l: &'a str, e: &'a OsStr, r: &'a str) -> OsString  {
    let mut buf = OsString::new();
    buf.push(l);
    buf.push(e);
    buf.push(r);
    buf
}

pub fn is_readable_dir (path_os_str: &OsStr) -> Result<(), OsString> {
    fs::metadata(Path::new(path_os_str))
        .map_err( |_| {
            err_msg("Could not open directory for reading: '", path_os_str, "'. Either the path does not exit or you lack the permission to read from it.")
        })
        .and_then( |meta| {
            if meta.is_dir() { Ok( () ) }
            else { Err(err_msg("Path is not of type directory: '", path_os_str, "'.")) }
        })
}

/*
pub fn is_writable_dir (path_os_str: &OsStr) -> Result<(), OsString> {
    fs::metadata(Path::new(path_os_str))
        .map_err(|_| {
            let mut msg = OsString::new();
            msg.push("Could not open directory for writing: '");
            msg.push(path_os_str);
            msg.push("'. Either the path does not exit or you lack the permission to write to it.");
            msg
        })
        .and_then(|meta| {
            if meta.is_dir() {
                if !meta.permissions().readonly() {
                    Ok( () )
                }
                else {
                    let mut msg = OsString::new();
                    msg.push("Directory is not writable: '");
                    msg.push(path_os_str);
                    msg.push("'.");
                    Err(msg)
                }
            }
            else {
                let mut msg = OsString::new();
                msg.push("Path is not of type directory: '");
                msg.push(path_os_str);
                msg.push("'.");
                Err(msg)
            }
        })
}
*/

