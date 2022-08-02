use wasm_bindgen::JsCast;

mod body;
mod client;
mod request;
mod response;
/// TODO
pub mod multipart;

pub use self::body::Body;
pub use self::client::{Client, ClientBuilder};
pub use self::request::{Request, RequestBuilder};
pub use self::response::Response;


async fn promise<T>(promise: js_sys::Promise) -> Result<T, crate::error::BoxError>
where
    T: JsCast,
{
    use wasm_bindgen_futures::JsFuture;

    let js_val = JsFuture::from(promise)
        .await
        .map_err(crate::error::wasm)?;

    js_val
        .dyn_into::<T>()
        .map_err(|_js_val| {
            "promise resolved to unexpected type".into()
        })
}
