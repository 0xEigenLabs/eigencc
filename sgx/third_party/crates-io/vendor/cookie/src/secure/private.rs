use secure::ring::aead::{Aad, Algorithm, Nonce, AES_256_GCM};
use secure::ring::aead::{LessSafeKey, UnboundKey};
use secure::ring::rand::{SecureRandom, SystemRandom};
use secure::{base64, Key};

use {Cookie, CookieJar};

// Keep these in sync, and keep the key len synced with the `private` docs as
// well as the `KEYS_INFO` const in secure::Key.
static ALGO: &'static Algorithm = &AES_256_GCM;
const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// A child cookie jar that provides authenticated encryption for its cookies.
///
/// A _private_ child jar signs and encrypts all the cookies added to it and
/// verifies and decrypts cookies retrieved from it. Any cookies stored in a
/// `PrivateJar` are simultaneously assured confidentiality, integrity, and
/// authenticity. In other words, clients cannot discover nor tamper with the
/// contents of a cookie, nor can they fabricate cookie data.
///
/// This type is only available when the `secure` feature is enabled.
pub struct PrivateJar<'a> {
    parent: &'a mut CookieJar,
    key: [u8; KEY_LEN]
}

impl<'a> PrivateJar<'a> {
    /// Creates a new child `PrivateJar` with parent `parent` and key `key`.
    /// This method is typically called indirectly via the `signed` method of
    /// `CookieJar`.
    #[doc(hidden)]
    pub fn new(parent: &'a mut CookieJar, key: &Key) -> PrivateJar<'a> {
        let mut key_array = [0u8; KEY_LEN];
        key_array.copy_from_slice(key.encryption());
        PrivateJar { parent: parent, key: key_array }
    }

    /// Given a sealed value `str` and a key name `name`, where the nonce is
    /// prepended to the original value and then both are Base64 encoded,
    /// verifies and decrypts the sealed value and returns it. If there's a
    /// problem, returns an `Err` with a string describing the issue.
    fn unseal(&self, name: &str, value: &str) -> Result<String, &'static str> {
        let mut data = base64::decode(value).map_err(|_| "bad base64 value")?;
        if data.len() <= NONCE_LEN {
            return Err("length of decoded data is <= NONCE_LEN");
        }

        let ad = Aad::from(name.as_bytes());
        let key = LessSafeKey::new(UnboundKey::new(&ALGO, &self.key).expect("matching key length"));
        let (nonce, mut sealed) = data.split_at_mut(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .expect("invalid length of `nonce`");
        let unsealed = key.open_in_place(nonce, ad, &mut sealed)
            .map_err(|_| "invalid key/nonce/value: bad seal")?;

        ::std::str::from_utf8(unsealed)
            .map(|s| s.to_string())
            .map_err(|_| "bad unsealed utf8")
    }

    /// Returns a reference to the `Cookie` inside this jar with the name `name`
    /// and authenticates and decrypts the cookie's value, returning a `Cookie`
    /// with the decrypted value. If the cookie cannot be found, or the cookie
    /// fails to authenticate or decrypt, `None` is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie, Key};
    ///
    /// let key = Key::generate();
    /// let mut jar = CookieJar::new();
    /// let mut private_jar = jar.private(&key);
    /// assert!(private_jar.get("name").is_none());
    ///
    /// private_jar.add(Cookie::new("name", "value"));
    /// assert_eq!(private_jar.get("name").unwrap().value(), "value");
    /// ```
    pub fn get(&self, name: &str) -> Option<Cookie<'static>> {
        if let Some(cookie_ref) = self.parent.get(name) {
            let mut cookie = cookie_ref.clone();
            if let Ok(value) = self.unseal(name, cookie.value()) {
                cookie.set_value(value);
                return Some(cookie);
            }
        }

        None
    }

    /// Adds `cookie` to the parent jar. The cookie's value is encrypted with
    /// authenticated encryption assuring confidentiality, integrity, and
    /// authenticity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie, Key};
    ///
    /// let key = Key::generate();
    /// let mut jar = CookieJar::new();
    /// jar.private(&key).add(Cookie::new("name", "value"));
    ///
    /// assert_ne!(jar.get("name").unwrap().value(), "value");
    /// assert_eq!(jar.private(&key).get("name").unwrap().value(), "value");
    /// ```
    pub fn add(&mut self, mut cookie: Cookie<'static>) {
        self.encrypt_cookie(&mut cookie);

        // Add the sealed cookie to the parent.
        self.parent.add(cookie);
    }

    /// Adds an "original" `cookie` to parent jar. The cookie's value is
    /// encrypted with authenticated encryption assuring confidentiality,
    /// integrity, and authenticity. Adding an original cookie does not affect
    /// the [`CookieJar::delta()`](struct.CookieJar.html#method.delta)
    /// computation. This method is intended to be used to seed the cookie jar
    /// with cookies received from a client's HTTP message.
    ///
    /// For accurate `delta` computations, this method should not be called
    /// after calling `remove`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie, Key};
    ///
    /// let key = Key::generate();
    /// let mut jar = CookieJar::new();
    /// jar.private(&key).add_original(Cookie::new("name", "value"));
    ///
    /// assert_eq!(jar.iter().count(), 1);
    /// assert_eq!(jar.delta().count(), 0);
    /// ```
    pub fn add_original(&mut self, mut cookie: Cookie<'static>) {
        self.encrypt_cookie(&mut cookie);

        // Add the sealed cookie to the parent.
        self.parent.add_original(cookie);
    }

    /// Encrypts the cookie's value with authenticated encryption assuring
    /// confidentiality, integrity, and authenticity.
    fn encrypt_cookie(&self, cookie: &mut Cookie) {
        // Create the `LessSafeKey` structure.
        let unbound = UnboundKey::new(&ALGO, &self.key).expect("matching key length");
        let key = LessSafeKey::new(unbound);

        // Create a vec to hold the [nonce | cookie value | tag].
        let cookie_val = cookie.value().as_bytes();
        let mut data = vec![0; NONCE_LEN + cookie_val.len() + ALGO.tag_len()];

        // Split data into three: nonce, input/output, tag. Copy input.
        let (nonce, in_out) = data.split_at_mut(NONCE_LEN);
        let (in_out, tag) = in_out.split_at_mut(cookie_val.len());
        in_out.copy_from_slice(cookie_val);

        // Randomly generate the nonce into the nonce piece.
        SystemRandom::new().fill(nonce).expect("couldn't random fill nonce");
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .expect("invalid `nonce` length");

        // Perform the actual sealing operation, using the cookie's name as
        // associated data to prevent value swapping.
        let ad = Aad::from(cookie.name().as_bytes());
        let ad_tag = key.seal_in_place_separate_tag(nonce, ad, in_out)
            .expect("in-place seal");

        // Copy the tag into the tag piece.
        tag.copy_from_slice(ad_tag.as_ref());

        // Base64 encode [none | encrypted value | tag].
        cookie.set_value(base64::encode(&data));
    }

    /// Removes `cookie` from the parent jar.
    ///
    /// For correct removal, the passed in `cookie` must contain the same `path`
    /// and `domain` as the cookie that was initially set.
    ///
    /// See [CookieJar::remove](struct.CookieJar.html#method.remove) for more
    /// details.
    ///
    /// # Example
    ///
    /// ```rust
    /// use cookie::{CookieJar, Cookie, Key};
    ///
    /// let key = Key::generate();
    /// let mut jar = CookieJar::new();
    /// let mut private_jar = jar.private(&key);
    ///
    /// private_jar.add(Cookie::new("name", "value"));
    /// assert!(private_jar.get("name").is_some());
    ///
    /// private_jar.remove(Cookie::named("name"));
    /// assert!(private_jar.get("name").is_none());
    /// ```
    pub fn remove(&mut self, cookie: Cookie<'static>) {
        self.parent.remove(cookie);
    }
}

#[cfg(test)]
mod test {
    use {CookieJar, Cookie, Key};

    #[test]
    fn simple() {
        let key = Key::generate();
        let mut jar = CookieJar::new();
        assert_simple_behaviour!(jar, jar.private(&key));
    }

    #[test]
    fn private() {
        let key = Key::generate();
        let mut jar = CookieJar::new();
        assert_secure_behaviour!(jar, jar.private(&key));
    }

#[test]
    fn roundtrip_tests() {
        use ::{Cookie, CookieJar};

        // Secret is 'Super secret!' passed through sha256
        let secret = b"\x1b\x1c\x6f\x1b\x31\x99\x82\x77\x0e\x05\xb6\x05\x54\x0b\xd9\xea\
            \x54\x9f\x9a\x56\xf4\x0f\x97\xdc\x6e\xf2\x89\x86\x91\xe0\xa5\x79";
        let key = Key::from_master(secret);

        let mut jar = CookieJar::new();
        jar.add(Cookie::new("signed_with_ring014", "3tdHXEQ2kf6fxC7dWzBGmpSLMtJenXLKrZ9cHkSsl1w=Tamper-proof"));
        jar.add(Cookie::new("encrypted_with_ring014", "lObeZJorGVyeSWUA8khTO/8UCzFVBY9g0MGU6/J3NN1R5x11dn2JIA=="));
        jar.add(Cookie::new("signed_with_ring016", "3tdHXEQ2kf6fxC7dWzBGmpSLMtJenXLKrZ9cHkSsl1w=Tamper-proof"));
        jar.add(Cookie::new("encrypted_with_ring016", "SU1ujceILyMBg3fReqRmA9HUtAIoSPZceOM/CUpObROHEujXIjonkA=="));

        let signed = jar.signed(&key);
        assert_eq!(signed.get("signed_with_ring014").unwrap().value(), "Tamper-proof");
        assert_eq!(signed.get("signed_with_ring016").unwrap().value(), "Tamper-proof");

        let private = jar.private(&key);
        assert_eq!(private.get("encrypted_with_ring014").unwrap().value(), "Tamper-proof");
        assert_eq!(private.get("encrypted_with_ring016").unwrap().value(), "Tamper-proof");
    }
}
