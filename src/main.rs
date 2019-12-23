#![deny(warnings)]

#[macro_use]
extern crate lazy_static;

mod cli;

use log::{info, warn, debug};
use std::fs;
use std::io::{self, Read};
use std::path;
use std::borrow::Borrow;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode, Uri};
use core::future::Future;
use regex::Regex;
use hex;
use octetkeypair_sodiumoxide::pub_keys_from_json_reader;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::sign::ed25519::PublicKey;
use cachet::v1::cachet;



type HandlerResult = std::result::Result<Response<Body>, hyper::Error>;


const MAX_BLOCK_SIZE: usize = 1000500 ;


#[derive(Clone,Debug)]
pub struct Config {
    pub keys:Vec<PublicKey>,
    pub storage_dir: path::PathBuf,
}


fn maybe_block_digest (uri: &Uri) -> Option<(String, Vec<u8>)> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"/([0-9A-Fa-f]{64})").unwrap();
    }

    RE.captures(uri.path())
        .and_then(|caps| caps.get(1))
        .and_then(|mtch| {
            let hex_str = mtch.as_str();
            hex::decode(mtch.as_str()).ok().map(|bytes| (hex_str.to_string(), bytes))
        })
}

fn not_found_response () -> HandlerResult {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::NOT_FOUND;
    *response.body_mut() = Body::empty();
    Ok(response)
}

fn method_not_allowed_response () -> HandlerResult {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
    *response.body_mut() = Body::empty();
    Ok(response)
}

fn unauthorized_response () -> HandlerResult {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    *response.body_mut() = Body::empty();
    Ok(response)
}

fn service_unavailable_reponse () -> HandlerResult {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    *response.body_mut() = Body::empty();
    Ok(response)
}


fn accepted_reponse () -> HandlerResult {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::ACCEPTED;
    *response.body_mut() = Body::empty();
    Ok(response)
}

async fn handle_write_block_request(cfg:Config, req: Request<Body>) -> HandlerResult {
    let root_key_store = Box::new(cfg.keys);
    let storage_dir = cfg.storage_dir;

    debug!("dispatching block ingress handeler");

    let whole_body = hyper::body::to_bytes(req.into_body()).await?;

    let c = cachet(&whole_body, root_key_store);
    if c.is_err() {
        //warn!("uploaded data failed signature authentication: {:?}", c.unwrap_err());
        warn!("uploaded data failed signature authentication");
        return unauthorized_response()
    }

    debug!("writing block contents to storage directory.");
    let mut block_path = path::PathBuf::from(storage_dir);

    debug!("computing SHA256 digest of block's contents");
    let block_hash_string =
        sha256::hash(whole_body.borrow()).0.iter()
            .map(|b| format!("{:02x?}",b))
            .collect::<String>();

    debug!("extracting the first four characters of the hex representation of the block's SHA256 digest:{}",block_hash_string);
    let block_prefix = &block_hash_string[..4];

    debug!("adding the first four characters of the hex repesentation of the block's digest to the block's storage path: {}", block_prefix);
    block_path.push(block_prefix);

    if !block_path.exists() {
        debug!("creating the prefix diectory for the block, using the first four characters of the hex repesentation of the block's digest: {}", block_path.display());
        let prefix_dir_create_res = fs::create_dir_all(&block_path);
        if prefix_dir_create_res.is_err() {
            let err = prefix_dir_create_res.unwrap_err();
            warn!("error creating block prefix directory: {:?}", err);
            return service_unavailable_reponse()
        }
    }

    debug!("adding the hex repesentation of the block's digest storage path, as the final block name.");
    block_path.push(block_hash_string);

    debug!("testing if final block's local storage path exists: {}", block_path.display());

    if !block_path.exists() {
        debug!("block does not exist, writing the block to disk: {}.", block_path.display());
        let write_res = fs::write(&block_path, whole_body);
        if write_res.is_err() {
            warn!("error writing block to disk at {}: {:?}", block_path.display(), write_res.unwrap_err());
            return service_unavailable_reponse()
        }
        info!("new block written to disk: {}.", block_path.display());
    }
    else {
        warn!("block already exists: {}", block_path.display());
    }

    accepted_reponse()
}

async fn handle_read_block_request(cfg:Config, req: Request<Body>, headers_only:bool) -> HandlerResult {
    debug!("looking at request URL to extract block digest");
    let dgst_opt = maybe_block_digest(req.uri());
    if dgst_opt.is_none() {
        info!("404 {:?}", req);
        return not_found_response();
    }
    let (hex_dgst_str, hex_dgst_bytes) = dgst_opt.unwrap();
    debug!("found block digest in request URL: {}",hex_dgst_str);

    let block_prefix = &hex_dgst_str[..4];
    debug!("extracted block prefix: {}", hex_dgst_str);

    let storage_dir = cfg.storage_dir;
    let mut block_path = path::PathBuf::from(storage_dir);
    block_path.push(block_prefix);
    block_path.push(hex_dgst_str.clone());

    debug!("Looking for block {} in local storage at path {}", hex_dgst_str, block_path.display());
    if !block_path.exists() {
        debug!("block {} not found in local storage at path {}", hex_dgst_str, block_path.display());
        return not_found_response();
    }

    debug!("retrieving metadata for block {} found in local storage at path {}, but file metadata is unavailable, which should never happen", hex_dgst_str, block_path.display());
    let block_md_res = block_path.metadata();
    if block_md_res.is_err() {
        debug!("block {} found in local storage at path {}, but file metadata is unavailable, which should never happen:{:?}", hex_dgst_str, block_path.display(),block_md_res.unwrap_err());
        return not_found_response();
    }

    let block_md = block_md_res.unwrap();
    let block_len = block_md.len() as usize;

    debug!("testing that block {} found in local storage at path {} is smaller than maximum block size limit.", hex_dgst_str, block_path.display());
    if block_len > MAX_BLOCK_SIZE {
        debug!("block {} found in local storage at path {}, but exceeds maximum block size limit, which should never happen", hex_dgst_str, block_path.display());
        return not_found_response();
    }

    debug!("attempting to open block {} found in local storage at path {} for reading...", hex_dgst_str, block_path.display());
    let block_file_res = fs::File::open(&block_path);
    if block_file_res.is_err() {
        debug!("block {} found in local storage at path {}, but could not be opened for reading:{:?}", hex_dgst_str, block_path.display(),block_file_res.unwrap_err());
        return not_found_response();
    }

    let mut block_file = block_file_res.unwrap();

    let mut unverified_block_data:Vec<u8> = Vec::with_capacity(block_len);
    debug!("attempting to read block {} found in local storage at path {} for reading...", hex_dgst_str, block_path.display());
    let bytes_read_res = block_file.read_to_end(&mut unverified_block_data);
    if bytes_read_res.is_err() {
        debug!("failed reading bytes for block {} found in local storage at path {}: {:?}", hex_dgst_str, block_path.display(), bytes_read_res.unwrap_err());
        return not_found_response();
    }

    let bytes_read = bytes_read_res.unwrap();

    if bytes_read != block_len  {
        debug!("reading bytes for block {} found in local storage at path {} did not read the expected number of bytes: expected to read {} bytes, accutally read {} bytes", hex_dgst_str, block_path.display(), block_len, bytes_read);
        return not_found_response();
    }

    debug!("calculating the sha256 digest for the bytes for block found in local storage at path {} match the requested block {}", block_path.display(), hex_dgst_str);
    let mut block_dgst = sha256::hash(unverified_block_data.borrow());

    debug!("calculating time-constant comparison of requested sha256 digest {} and the computed sha256 of the bytes read from local storage at path {}, {:02x?}", hex_dgst_str, block_path.display(), block_dgst);
    let mut sum = 0x00;
    for (l, r) in block_dgst.0.iter_mut().zip(hex_dgst_bytes.iter()) {
        sum ^= *l ^ *r
    }

    debug!("constructing trusted root keys store from config");
    let root_key_store = Box::new(cfg.keys);

    debug!("constructing cachet using bytes found in local storage at path {} for requested block {}", block_path.display(), hex_dgst_str);
    let cachet_res = cachet(unverified_block_data.borrow(), root_key_store);

    if sum != 0x00 || cachet_res.is_err() {
        debug!("block {} found in local storage at path {} could not be authenticated. Either the contents digest did not match the digest requested, or the signature within the stored block did not match the trusted keys in the root key store.", hex_dgst_str, block_path.display());
        return not_found_response();
    }

    // data can be trusted at this point, relabel it just for clarity.
    let verified_block_data = unverified_block_data;

    Ok(Response::new(
        if headers_only {
            Body::empty()
        } else {
            Body::from(verified_block_data)
        }
    ))
}


async fn router(cfg: Config, req: Request<Body>) -> HandlerResult {
    match *req.method() {
        Method::GET => handle_read_block_request(cfg, req, false).await,
        Method::HEAD => handle_read_block_request(cfg, req, true).await,
        Method::POST => handle_write_block_request(cfg, req).await,
        _ => method_not_allowed_response()
    }
}


pub fn curry_config<G, S> (c:Config, g: G) -> impl Fn(Request<Body>) -> S
where
    G: Fn(Config, Request<Body>) -> S,
    S: Future<Output=HandlerResult> {
    move |req| g(c.clone(),req)
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    info!("Logging initialized");

    let matches = cli::brb_app().get_matches();

    // safe to unwrap, since clap crate is enforcing a value is set at runtime.
    let addr = matches.value_of("bind_addr").unwrap().parse().unwrap();
    let storage_dir = matches.value_of("storage_dir").unwrap();
    let keys_file = matches.value_of("trusted_keys_file").unwrap();

    info!("Opening trusted keys file: {}", keys_file);
    let file   = fs::File::open(keys_file)?;
    let reader = io::BufReader::new(file);
    let keys   = pub_keys_from_json_reader(reader)?;

    info!("Serving blocks locally from {}", storage_dir);
    let cfg = Config {
        keys: keys,
        storage_dir: path::Path::new(storage_dir).to_path_buf(),
    };

    info!("Binding to network address {}", addr);

    let service = make_service_fn(|_| {
        let config = cfg.clone();
        async {
            Ok::<_, hyper::Error>(
                service_fn(curry_config(config, router))
            )
        }
    });

    let server = Server::bind(&addr).serve(service);

    server.await?;

    Ok(())
}
