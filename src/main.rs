extern crate clap;
extern crate sha2;
extern crate bs58;
extern crate hex;
extern crate sodiumoxide;

use clap::{Arg, App, SubCommand, AppSettings};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};


fn main() {
    let matches = App::new("gensis-cli")
        .setting(AppSettings::ArgRequiredElseHelp)
        .setting(AppSettings::UnifiedHelpMessage)
        .setting(AppSettings::DisableHelpSubcommand)
        .version("1.0")
        .about("genesis crypto CLI")
        .subcommand(
            SubCommand::with_name("hash")
            .about("base58 encoded multihash (sha256) of a file")
            .arg(Arg::with_name("file")
                 .required(true)
                 .takes_value(true)
                 .index(1)
                )
            )
        .subcommand(
            SubCommand::with_name("identity")
            .about("generate an identity from private data")
            .arg(Arg::with_name("code")
                 .short("c")
                 .long("code")
                 .help("print hex as embeddable source code")
                )
            .arg(Arg::with_name("prv")
                 .help("private data file")
                 .required(true)
                 .takes_value(true)
                 .index(1)
                )
            )
        .subcommand(
            SubCommand::with_name("box")
            .about("sign, encrypt and hash a file")
            .arg(Arg::with_name("sign")
                 .short("s")
                 .long("sign")
                 .help("sign with secret private data file")
                 .takes_value(true)
                )
            .arg(Arg::with_name("in")
                 .short("i")
                 .required(true)
                 .takes_value(true)
                )
            .arg(Arg::with_name("out")
                 .short("o")
                 .required(true)
                 .takes_value(true)
                )
            )
        .get_matches();

    match matches.subcommand() {
        ("identity", Some(submatches)) =>{
            let prv = submatches.value_of("prv").unwrap();
            let (sp,_) = prv_from_file(prv);

            if submatches.is_present("code") {
                let hx : Vec<&u8> = sp.as_ref().iter().collect();
                print!("[");
                for (i,x) in hx.iter().enumerate() {
                    if (i % 8) == 0 && i > 0 {
                        print!("\n ");
                    }
                    print!("0x{:x}", x);
                    if i < hx.len() - 1 {
                        print!(",");
                    }
                }
                print!("]\n");
            } else {
                println!("{}", bs58::encode(sp.0.as_ref())
                         .with_alphabet(bs58::alphabet::BITCOIN)
                         .into_string());
            }

        },
        ("hash", Some(submatches)) =>{
            let file = submatches.value_of("file").unwrap();
            let mut f = File::open(file).unwrap();
            let mut hasher = Sha256::default();

            let mut buf = [0;1024];
            loop {
                let r = f.read(&mut buf).unwrap();
                if r <= 0 {
                    break;
                }
                hasher.input(&buf[..r]);
            }

            // multihash https://github.com/multiformats/multihash
            let mut re = vec![0x12,32];
            re.append(&mut hasher.result().to_vec());

            println!("{}", bs58::encode(re)
                     .with_alphabet(bs58::alphabet::BITCOIN)
                     .into_string());

        },
        ("box", Some(submatches)) => {
            let file = submatches.value_of("in").unwrap();
            let mut f = File::open(file).unwrap();
            let mut text : Vec<u8> = vec![b'#',b'g',b'c',b'1'];
            text.push(b'n');
            if let Some(_) = submatches.value_of("sign") {
                text.push(b'e');
            } else {
                text.push(b'n');
            }
            text.push(b'\n');
            f.read_to_end(&mut text).unwrap();

            if let Some(prv) = submatches.value_of("sign") {
                let (_,sk) = prv_from_file(prv);
                let mut sig = sign::ed25519::sign_detached(text.as_ref(), &sk);

                text.append(&mut sig.as_ref().to_vec());
            }

            let file = submatches.value_of("out").unwrap();
            let mut f = File::create(file).unwrap();
            f.write_all(&text).unwrap();

            let mut hasher = Sha256::default();
            hasher.input(&text);
            // multihash https://github.com/multiformats/multihash
            let mut re = vec![0x12,32];
            re.append(&mut hasher.result().to_vec());

            println!("{}", bs58::encode(re)
                     .with_alphabet(bs58::alphabet::BITCOIN)
                     .into_string());
        },
        _ => unreachable!()
    }


}

fn prv_from_file(filename: &str) -> (PublicKey, SecretKey) {
    let mut kf = File::open(filename).unwrap();
    let mut prv = Vec::new();
    kf.read_to_end(&mut prv).unwrap();
    if prv.len() != 512 {
        panic!("private key data must be 512 bytes");
    }
    let seed    = sign::ed25519::Seed::from_slice(&prv[0..32]).unwrap();
    sign::ed25519::keypair_from_seed(&seed)
}


