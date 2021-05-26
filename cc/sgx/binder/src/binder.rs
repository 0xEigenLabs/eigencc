use sgx_types::*;
use sgx_urts::SgxEnclave;

use serde::de::DeserializeOwned;
use serde::Serialize;

use eigen_core::ipc::channel::ECallChannel;
use eigen_core::ipc::protos::ecall::{FinalizeEnclaveInput, FinalizeEnclaveOutput};
use eigen_core::ipc::protos::ecall::{InitEnclaveInput, InitEnclaveOutput};
use eigen_core::ipc::protos::ECallCommand;
use eigen_core::ipc::IpcSender;
use eigen_core::Result;

static ENCLAVE_FILE_SUFFIX: &str = "_enclave.signed.so";

use std::sync::Arc;
#[derive(Clone)]
pub struct TeeBinder {
    name: String,
    debug_launch: i32,
    enclave_id: sgx_enclave_id_t,
    enclave: Arc<SgxEnclave>,
}

impl TeeBinder {
    pub fn new(name: &str, debug_launch: i32) -> Result<TeeBinder> {
        let name = name.to_string();
        let enclave = init_enclave(&name, debug_launch)?;
        let enclave_id = enclave.geteid();

        let tee = TeeBinder {
            name,
            debug_launch,
            enclave: Arc::new(enclave),
            enclave_id,
        };

        debug!("EnclaveID: {}", enclave_id);

        let args_info = InitEnclaveInput::default();
        let _ret_info = tee.invoke::<InitEnclaveInput, InitEnclaveOutput>(
            ECallCommand::InitEnclave.into(),
            args_info,
        )?;

        Ok(tee)
    }

    pub fn invoke<U, V>(&self, cmd: u32, args_info: U) -> Result<V>
    where
        U: Serialize,
        V: DeserializeOwned,
    {
        let mut channel = ECallChannel::new(self.enclave_id);
        channel.invoke::<U, V>(cmd, args_info)
    }

    pub fn finalize(&self) {
        let args_info = FinalizeEnclaveInput::default();
        match self.invoke::<FinalizeEnclaveInput, FinalizeEnclaveOutput>(
            ECallCommand::FinalizeEnclave.into(),
            args_info,
        ) {
            Ok(_) => {}
            Err(e) => info!("{:?}", e),
        }
    }
}

impl Drop for TeeBinder {
    fn drop(&mut self) {
        debug!("Dropping TeeBinder, start finalize().");
        self.finalize();
    }
}

fn init_enclave(enclave_name: &str, debug_launch: i32) -> Result<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024]; // launch_token is deprecated
    let mut launch_token_updated: i32 = 0; // launch_token is deprecated

    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };

    let enclave_file = format!("{}{}", enclave_name, ENCLAVE_FILE_SUFFIX);

    let enclave = SgxEnclave::create(
        enclave_file,
        debug_launch,
        &mut launch_token,         // launch_token is deprecated
        &mut launch_token_updated, // launch_token is deprecated
        &mut misc_attr,
    )?;

    Ok(enclave)
}
