# `hyper-sync-rustls`

This is an integration between the [`rustls` TLS
stack](https://github.com/ctz/rustls) and the synchronous version (0.10) of the
[`hyper` HTTP library](https://github.com/hyperium/hyper). This is a maintained
fork of [`hyper-rustls`](https://github.com/ctz/hyper-rustls) for synchronous
hyper.

## Usage

These are provided as an example of the minimal changes needed to use rustls in
your existing hyper-based program. Note that these are derived works of original
hyper source, and are distributed under hyper's license.

### Client

Enable the `client` feature for access to client types.

```diff
--- ../hyper/examples/client.rs	2016-10-03 23:29:00.850098245 +0100
+++ examples/client.rs	2016-10-08 07:36:05.076449122 +0100
@@ -1,6 +1,8 @@
 #![deny(warnings)]
 extern crate hyper;
 
+extern crate hyper_sync_rustls;
+
 extern crate env_logger;
 
 use std::env;
@@ -8,6 +10,7 @@
 
 use hyper::Client;
 use hyper::header::Connection;
+use hyper::net::HttpsConnector;
 
 fn main() {
     env_logger::init().unwrap();
@@ -32,7 +35,7 @@
             }
             Client::with_http_proxy(proxy, port)
         },
-        _ => Client::new()
+        _ => Client::with_connector(HttpsConnector::new(hyper_sync_rustls::TlsClient::new()))
     };
 
     let mut res = client.get(&*url)
```

### Server

Enable the `server` feature for access to client types.

```diff
--- ../hyper/examples/server.rs	2016-10-03 23:29:00.850098245 +0100
+++ examples/server.rs	2016-10-08 07:31:38.720667338 +0100
@@ -1,5 +1,6 @@
 #![deny(warnings)]
 extern crate hyper;
+extern crate hyper_sync_rustls;
 extern crate env_logger;
 
 use std::io::copy;
@@ -41,7 +42,10 @@
 
 fn main() {
     env_logger::init().unwrap();
-    let server = Server::http("127.0.0.1:1337").unwrap();
+    let certs = hyper_sync_rustls::util::load_certs("examples/sample.pem").unwrap();
+    let key = hyper_sync_rustls::util::load_private_key("examples/sample.rsa").unwrap();
+    let tls = hyper_sync_rustls::TlsServer::new(certs, key);
+    let server = Server::https("127.0.0.1:1337", tls).unwrap();
     let _guard = server.handle(echo);
-    println!("Listening on http://127.0.0.1:1337");
+    println!("Listening on https://127.0.0.1:1337");
 }
```

## License

`hyper-sync-rustls` is licensed under either of the following, at your option:

 * Apache License, Version 2.0 ([full text](http://www.apache.org/licenses/LICENSE-2.0))
 * MIT License ([full text](http://opensource.org/licenses/MIT))
