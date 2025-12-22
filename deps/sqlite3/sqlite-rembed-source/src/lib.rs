mod clients;
mod clients_vtab;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use clients::{Client, CohereClient, LlamafileClient, NomicClient, OllamaClient, OpenAiClient};
use clients_vtab::ClientsTable;
use sqlite_loadable::{
    api, define_scalar_function, define_scalar_function_with_aux, define_virtual_table_writeablex,
    prelude::*, Error, Result,
};
use zerocopy::AsBytes;

const FLOAT32_VECTOR_SUBTYPE: u8 = 223;
const CLIENT_OPTIONS_POINTER_NAME: &[u8] = b"sqlite-rembed-client-options\0";

pub fn rembed_version(context: *mut sqlite3_context, _values: &[*mut sqlite3_value]) -> Result<()> {
    api::result_text(context, format!("v{}", env!("CARGO_PKG_VERSION")))?;
    Ok(())
}

pub fn rembed_debug(context: *mut sqlite3_context, _values: &[*mut sqlite3_value]) -> Result<()> {
    api::result_text(
        context,
        format!(
            "Version: v{}
Source: {}
",
            env!("CARGO_PKG_VERSION"),
            env!("GIT_HASH")
        ),
    )?;
    Ok(())
}

pub fn rembed_client_options(
    context: *mut sqlite3_context,
    values: &[*mut sqlite3_value],
) -> Result<()> {
    if (values.len() % 2) != 0 {
        return Err(Error::new_message(
            "Must have an even number of arguments to rembed_client_options, as key/value pairs.",
        ));
    }
    let mut options: HashMap<String, String> = HashMap::new();
    let mut format: Option<String> = None;
    for pair in values.chunks(2) {
        let key = api::value_text(&pair[0])?;
        let value = api::value_text(&pair[1])?;
        if key == "format" {
            format = Some(value.to_owned());
        } else {
            options.insert(key.to_owned(), value.to_owned());
        }
    }

    let format = match format {
        Some(format) => format,
        None => {
            return Err(Error::new_message("'format' key is required."));
        }
    };
    let client: Client = match format.as_str() {
        "openai" => Client::OpenAI(OpenAiClient::new(
            options
                .get("model")
                .ok_or_else(|| Error::new_message("'model' option is required"))?,
            options.get("url").cloned(),
            options.get("key").cloned(),
        )?),
        "nomic" => Client::Nomic(NomicClient::new(
            options
                .get("model")
                .ok_or_else(|| Error::new_message("'model' option is required"))?,
            options.get("url").cloned(),
            options.get("key").cloned(),
        )?),
        "cohere" => Client::Cohere(CohereClient::new(
            options
                .get("model")
                .ok_or_else(|| Error::new_message("'model' option is required"))?,
            options.get("url").cloned(),
            options.get("key").cloned(),
        )?),
        "ollama" => Client::Ollama(OllamaClient::new(
            options
                .get("model")
                .ok_or_else(|| Error::new_message("'model' option is required"))?,
            options.get("url").cloned(),
        )),
        "llamafile" => Client::Llamafile(LlamafileClient::new(options.get("url").cloned())),
        format => return Err(Error::new_message(format!("Unknown format '{format}'"))),
    };

    api::result_pointer(context, CLIENT_OPTIONS_POINTER_NAME, client);

    Ok(())
}
pub fn rembed(
    context: *mut sqlite3_context,
    values: &[*mut sqlite3_value],
    clients: &Rc<RefCell<HashMap<String, Client>>>,
) -> Result<()> {
    let client_name = api::value_text(&values[0])?;
    let input = api::value_text(&values[1])?;
    let x = clients.borrow();
    let client = x.get(client_name).ok_or_else(|| {
        Error::new_message(format!(
            "Client with name {client_name} was not registered with rembed_clients."
        ))
    })?;

    let embedding = match client {
        Client::OpenAI(client) => client.infer_single(input)?,
        Client::Jina(client) => client.infer_single(input)?,
        Client::Mixedbread(client) => client.infer_single(input)?,
        Client::Ollama(client) => client.infer_single(input)?,
        Client::Llamafile(client) => client.infer_single(input)?,
        Client::Nomic(client) => {
            let input_type = values.get(2).and_then(|v| api::value_text(v).ok());
            client.infer_single(input, input_type)?
        }
        Client::Cohere(client) => {
            let input_type = values.get(2).and_then(|v| api::value_text(v).ok());
            client.infer_single(input, input_type)?
        }
    };

    api::result_blob(context, embedding.as_bytes());
    api::result_subtype(context, FLOAT32_VECTOR_SUBTYPE);
    Ok(())
}

#[sqlite_entrypoint]
pub fn sqlite3_rembed_init(db: *mut sqlite3) -> Result<()> {
    let flags = FunctionFlags::UTF8
        | FunctionFlags::DETERMINISTIC
        | unsafe { FunctionFlags::from_bits_unchecked(0x001000000) };

    let c = Rc::new(RefCell::new(HashMap::new()));

    define_scalar_function(
        db,
        "rembed_version",
        0,
        rembed_version,
        FunctionFlags::UTF8 | FunctionFlags::DETERMINISTIC,
    )?;
    define_scalar_function(
        db,
        "rembed_debug",
        0,
        rembed_debug,
        FunctionFlags::UTF8 | FunctionFlags::DETERMINISTIC,
    )?;
    define_scalar_function_with_aux(db, "rembed", 2, rembed, flags, Rc::clone(&c))?;
    define_scalar_function_with_aux(db, "rembed", 3, rembed, flags, Rc::clone(&c))?;
    define_scalar_function(
        db,
        "rembed_client_options",
        -1,
        rembed_client_options,
        flags,
    )?;
    define_virtual_table_writeablex::<ClientsTable>(db, "rembed_clients", Some(Rc::clone(&c)))?;
    Ok(())
}
