use std::fs::{self, File};
use std::str;
use tempfile;

use std::sync::Arc;
use std::io::{self, Write};

use rustls;

use rustls::{ClientConfig, ClientSession};
use rustls::{ServerConfig, ServerSession};
use rustls::Session;
use rustls::ProtocolVersion;
use rustls::TLSError;
use rustls::{Certificate, PrivateKey};
use rustls::internal::pemfile;
use rustls::{RootCertStore, NoClientAuth, AllowAnyAuthenticatedClient};

use webpki;

macro_rules! embed_files {
    (
        $(
            ($name:ident, $keytype:expr, $path:expr);
        )+
    ) => {
        $(
            const $name: &'static [u8] = include_bytes!(
                concat!("../../test-ca/", $keytype, "/", $path));
        )+

        pub fn bytes_for(keytype: &str, path: &str) -> &'static [u8] {
            match (keytype, path) {
                $(
                    ($keytype, $path) => $name,
                )+
                _ => panic!("unknown keytype {} with path {}", keytype, path),
            }
        }

        pub fn new_test_ca() -> tempfile::TempDir {
            let dir = tempfile::TempDir::new().unwrap();

            fs::create_dir(dir.path().join("ecdsa")).unwrap();
            fs::create_dir(dir.path().join("rsa")).unwrap();

            $(
                let mut f = File::create(dir.path().join($keytype).join($path)).unwrap();
                f.write($name).unwrap();
            )+

            dir
        }
    }
}

embed_files! {
    (ECDSA_CA_CERT, "ecdsa", "ca.cert");
    (ECDSA_CA_DER, "ecdsa", "ca.der");
    (ECDSA_CA_KEY, "ecdsa", "ca.key");
    (ECDSA_CLIENT_CERT, "ecdsa", "client.cert");
    (ECDSA_CLIENT_CHAIN, "ecdsa", "client.chain");
    (ECDSA_CLIENT_FULLCHAIN, "ecdsa", "client.fullchain");
    (ECDSA_CLIENT_KEY, "ecdsa", "client.key");
    (ECDSA_CLIENT_REQ, "ecdsa", "client.req");
    (ECDSA_END_CERT, "ecdsa", "end.cert");
    (ECDSA_END_CHAIN, "ecdsa", "end.chain");
    (ECDSA_END_FULLCHAIN, "ecdsa", "end.fullchain");
    (ECDSA_END_KEY, "ecdsa", "end.key");
    (ECDSA_END_REQ, "ecdsa", "end.req");
    (ECDSA_INTER_CERT, "ecdsa", "inter.cert");
    (ECDSA_INTER_KEY, "ecdsa", "inter.key");
    (ECDSA_INTER_REQ, "ecdsa", "inter.req");
    (ECDSA_NISTP256_PEM, "ecdsa", "nistp256.pem");
    (ECDSA_NISTP384_PEM, "ecdsa", "nistp384.pem");

    (RSA_CA_CERT, "rsa", "ca.cert");
    (RSA_CA_DER, "rsa", "ca.der");
    (RSA_CA_KEY, "rsa", "ca.key");
    (RSA_CLIENT_CERT, "rsa", "client.cert");
    (RSA_CLIENT_CHAIN, "rsa", "client.chain");
    (RSA_CLIENT_FULLCHAIN, "rsa", "client.fullchain");
    (RSA_CLIENT_KEY, "rsa", "client.key");
    (RSA_CLIENT_REQ, "rsa", "client.req");
    (RSA_CLIENT_RSA, "rsa", "client.rsa");
    (RSA_END_CERT, "rsa", "end.cert");
    (RSA_END_CHAIN, "rsa", "end.chain");
    (RSA_END_FULLCHAIN, "rsa", "end.fullchain");
    (RSA_END_KEY, "rsa", "end.key");
    (RSA_END_REQ, "rsa", "end.req");
    (RSA_END_RSA, "rsa", "end.rsa");
    (RSA_INTER_CERT, "rsa", "inter.cert");
    (RSA_INTER_KEY, "rsa", "inter.key");
    (RSA_INTER_REQ, "rsa", "inter.req");
}

pub fn transfer(left: &mut dyn Session, right: &mut dyn Session) -> usize {
    let mut buf = [0u8; 262144];
    let mut total = 0;

    while left.wants_write() {
        let sz = {
            let into_buf: &mut io::Write = &mut &mut buf[..];
            left.write_tls(into_buf).unwrap()
        };
        total += sz;
        if sz == 0 {
            return total;
        }

        let mut offs = 0;
        loop {
            let from_buf: &mut io::Read = &mut &buf[offs..sz];
            offs += right.read_tls(from_buf).unwrap();
            if sz == offs {
                break;
            }
        }
    }

    total
}

#[derive(Clone, Copy)]
pub enum KeyType {
    RSA,
    ECDSA
}

pub static ALL_KEY_TYPES: [KeyType; 2] = [ KeyType::RSA, KeyType::ECDSA ];

impl KeyType {
    fn bytes_for(&self, part: &str) -> &'static [u8] {
        match self {
            KeyType::RSA => bytes_for("rsa", part),
            KeyType::ECDSA => bytes_for("ecdsa", part),
        }
    }

    pub fn get_chain(&self) -> Vec<Certificate> {
        pemfile::certs(&mut io::BufReader::new(self.bytes_for("end.fullchain")))
            .unwrap()
    }

    pub fn get_key(&self) -> PrivateKey {
        pemfile::pkcs8_private_keys(&mut io::BufReader::new(self.bytes_for("end.key")))
                .unwrap()[0]
            .clone()
    }

    fn get_client_chain(&self) -> Vec<Certificate> {
        pemfile::certs(&mut io::BufReader::new(self.bytes_for("client.fullchain")))
            .unwrap()
    }

    fn get_client_key(&self) -> PrivateKey {
        pemfile::pkcs8_private_keys(&mut io::BufReader::new(self.bytes_for("client.key")))
                .unwrap()[0]
            .clone()
    }
}

pub fn make_server_config(kt: KeyType) -> ServerConfig {
    let mut cfg = ServerConfig::new(NoClientAuth::new());
    cfg.set_single_cert(kt.get_chain(), kt.get_key()).unwrap();

    cfg
}

pub fn make_server_config_with_mandatory_client_auth(kt: KeyType) -> ServerConfig {
    let roots = kt.get_chain();
    let mut client_auth_roots = RootCertStore::empty();
    for root in roots {
        client_auth_roots.add(&root).unwrap();
    }

    let client_auth = AllowAnyAuthenticatedClient::new(client_auth_roots);
    let mut cfg = ServerConfig::new(client_auth);
    cfg.set_single_cert(kt.get_chain(), kt.get_key()).unwrap();

    cfg
}

pub fn make_client_config(kt: KeyType) -> ClientConfig {
    let mut cfg = ClientConfig::new();
    let mut rootbuf = io::BufReader::new(kt.bytes_for("ca.cert"));
    cfg.root_store.add_pem_file(&mut rootbuf).unwrap();

    cfg
}

pub fn make_client_config_with_auth(kt: KeyType) -> ClientConfig {
    let mut cfg = make_client_config(kt);
    cfg.set_single_client_cert(kt.get_client_chain(), kt.get_client_key());
    cfg
}

pub fn make_pair(kt: KeyType) -> (ClientSession, ServerSession) {
    make_pair_for_configs(make_client_config(kt),
                          make_server_config(kt))
}

pub fn make_pair_for_configs(client_config: ClientConfig,
                             server_config: ServerConfig) -> (ClientSession, ServerSession) {
    make_pair_for_arc_configs(&Arc::new(client_config),
                              &Arc::new(server_config))
}

pub fn make_pair_for_arc_configs(client_config: &Arc<ClientConfig>,
                                 server_config: &Arc<ServerConfig>) -> (ClientSession, ServerSession) {
    (
        ClientSession::new(client_config, dns_name("localhost")),
        ServerSession::new(server_config)
    )
}

pub fn do_handshake(client: &mut ClientSession, server: &mut ServerSession) -> (usize, usize) {
    let (mut to_client, mut to_server) = (0, 0);
    while server.is_handshaking() || client.is_handshaking() {
        to_server += transfer(client, server);
        server.process_new_packets().unwrap();
        to_client += transfer(server, client);
        client.process_new_packets().unwrap();
    }
    (to_server, to_client)
}

pub struct AllClientVersions {
    client_config: ClientConfig,
    index: usize,
}

impl AllClientVersions {
    pub fn new(client_config: ClientConfig) -> AllClientVersions {
        AllClientVersions { client_config, index: 0 }
    }
}

impl Iterator for AllClientVersions {
    type Item = ClientConfig;

    fn next(&mut self) -> Option<ClientConfig> {
        let mut config = self.client_config.clone();
        self.index += 1;

        match self.index {
            1 => {
                config.versions = vec![ProtocolVersion::TLSv1_2];
                Some(config)
            },
            2 => {
                config.versions = vec![ProtocolVersion::TLSv1_3];
                Some(config)
            },
            _ => None
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum TLSErrorFromPeer { Client(TLSError), Server(TLSError) }

pub fn do_handshake_until_error(client: &mut ClientSession,
                                server: &mut ServerSession)
                               -> Result<(), TLSErrorFromPeer> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server.process_new_packets()
            .map_err(|err| TLSErrorFromPeer::Server(err))?;
        transfer(server, client);
        client.process_new_packets()
            .map_err(|err| TLSErrorFromPeer::Client(err))?;
    }

    Ok(())
}

pub fn dns_name(name: &'static str) -> webpki::DNSNameRef<'_> {
    webpki::DNSNameRef::try_from_ascii_str(name).unwrap()
}

pub struct FailsReads {
    errkind: io::ErrorKind
}

impl FailsReads {
    pub fn new(errkind: io::ErrorKind) -> FailsReads {
        FailsReads { errkind }
    }
}

impl io::Read for FailsReads {
    fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(self.errkind))
    }
}
