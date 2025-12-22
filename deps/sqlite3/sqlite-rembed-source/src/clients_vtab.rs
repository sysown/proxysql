use sqlite_loadable::table::UpdateOperation;
use sqlite_loadable::{api, prelude::*, Error};
use sqlite_loadable::{
    api::ValueType,
    table::{IndexInfo, VTab, VTabArguments, VTabCursor, VTabWriteable},
    BestIndexError, Result,
};
use std::{cell::RefCell, collections::HashMap, marker::PhantomData, mem, os::raw::c_int, rc::Rc};

use crate::clients::MixedbreadClient;
use crate::{
    clients::{
        Client, CohereClient, JinaClient, LlamafileClient, NomicClient, OllamaClient, OpenAiClient,
    },
    CLIENT_OPTIONS_POINTER_NAME,
};

enum Columns {
    Name,
    Options,
}
fn column(index: i32) -> Option<Columns> {
    match index {
        0 => Some(Columns::Name),
        1 => Some(Columns::Options),
        _ => None,
    }
}
#[repr(C)]
pub struct ClientsTable {
    /// must be first
    base: sqlite3_vtab,
    clients: Rc<RefCell<HashMap<String, Client>>>,
}

impl<'vtab> VTab<'vtab> for ClientsTable {
    type Aux = Rc<RefCell<HashMap<String, Client>>>;
    type Cursor = ClientsCursor<'vtab>;

    fn create(
        db: *mut sqlite3,
        aux: Option<&Self::Aux>,
        args: VTabArguments,
    ) -> Result<(String, Self)> {
        Self::connect(db, aux, args)
    }
    fn connect(
        _db: *mut sqlite3,
        aux: Option<&Self::Aux>,
        _args: VTabArguments,
    ) -> Result<(String, ClientsTable)> {
        let base: sqlite3_vtab = unsafe { mem::zeroed() };
        let clients = aux.expect("Required aux").to_owned();

        let vtab = ClientsTable { base, clients };
        let sql = "create table x(name text primary key, options)".to_owned();

        Ok((sql, vtab))
    }
    fn destroy(&self) -> Result<()> {
        Ok(())
    }

    fn best_index(&self, mut info: IndexInfo) -> core::result::Result<(), BestIndexError> {
        info.set_estimated_cost(10000.0);
        info.set_estimated_rows(10000);
        info.set_idxnum(1);
        Ok(())
    }

    fn open(&'vtab mut self) -> Result<ClientsCursor<'vtab>> {
        ClientsCursor::new(self)
    }
}

impl<'vtab> VTabWriteable<'vtab> for ClientsTable {
    fn update(&'vtab mut self, operation: UpdateOperation<'_>, _p_rowid: *mut i64) -> Result<()> {
        match operation {
            UpdateOperation::Delete(_) => {
                return Err(Error::new_message(
                    "DELETE operations on rembed_clients is not supported yet",
                ))
            }
            UpdateOperation::Update { _values } => {
                return Err(Error::new_message(
                    "DELETE operations on rembed_clients is not supported yet",
                ))
            }
            UpdateOperation::Insert { values, rowid: _ } => {
                let name = api::value_text(&values[0])?;
                let client = match api::value_type(&values[1]) {
                    ValueType::Text => match api::value_text(&values[1])? {
                        "openai" => Client::OpenAI(OpenAiClient::new(name, None, None)?),
                        "mixedbread" => {
                            Client::Mixedbread(MixedbreadClient::new(name, None, None)?)
                        }
                        "jina" => Client::Jina(JinaClient::new(name, None, None)?),
                        "nomic" => Client::Nomic(NomicClient::new(name, None, None)?),
                        "cohere" => Client::Cohere(CohereClient::new(name, None, None)?),
                        "ollama" => Client::Ollama(OllamaClient::new(name, None)),
                        "llamafile" => Client::Llamafile(LlamafileClient::new(None)),
                        text => {
                            return Err(Error::new_message(format!(
                                "'{text}' is not a valid rembed client."
                            )))
                        }
                    },
                    ValueType::Null => unsafe {
                        if let Some(client) =
                            api::value_pointer::<Client>(&values[1], CLIENT_OPTIONS_POINTER_NAME)
                        {
                            (*client).clone()
                        } else {
                            return Err(Error::new_message("client options required"));
                        }
                    },
                    _ => return Err(Error::new_message("client options required")),
                };
                self.clients.borrow_mut().insert(name.to_owned(), client);
            }
        }
        Ok(())
    }
}

#[repr(C)]
pub struct ClientsCursor<'vtab> {
    /// Base class. Must be first
    base: sqlite3_vtab_cursor,
    keys: Vec<String>,
    rowid: i64,
    phantom: PhantomData<&'vtab ClientsTable>,
}
impl ClientsCursor<'_> {
    fn new(table: &mut ClientsTable) -> Result<ClientsCursor> {
        let base: sqlite3_vtab_cursor = unsafe { mem::zeroed() };
        let c = table.clients.borrow();
        let keys = c.keys().map(|k| k.to_string()).collect();
        let cursor = ClientsCursor {
            base,
            keys,
            rowid: 0,
            phantom: PhantomData,
        };
        Ok(cursor)
    }
}

impl VTabCursor for ClientsCursor<'_> {
    fn filter(
        &mut self,
        _idx_num: c_int,
        _idx_str: Option<&str>,
        _values: &[*mut sqlite3_value],
    ) -> Result<()> {
        Ok(())
    }

    fn next(&mut self) -> Result<()> {
        self.rowid += 1;
        Ok(())
    }

    fn eof(&self) -> bool {
        (self.rowid as usize) >= self.keys.len()
    }

    fn column(&self, context: *mut sqlite3_context, i: c_int) -> Result<()> {
        let key = self
            .keys
            .get(self.rowid as usize)
            .expect("Internal rembed_clients logic error");
        match column(i) {
            Some(Columns::Name) => api::result_text(context, key)?,
            Some(Columns::Options) => (),
            None => (),
        };
        Ok(())
    }

    fn rowid(&self) -> Result<i64> {
        Ok(self.rowid)
    }
}
