use sqlite_loadable::{Error, Result};

pub(crate) fn try_env_var(key: &str) -> Result<String> {
    std::env::var(key)
   .map_err(|_| Error::new_message(format!("{} environment variable not define. Alternatively, pass in an API key with rembed_client_options", DEFAULT_OPENAI_API_KEY_ENV)))
}

#[derive(Clone)]
pub struct OpenAiClient {
    model: String,
    url: String,
    key: String,
}
const DEFAULT_OPENAI_URL: &str = "https://api.openai.com/v1/embeddings";
const DEFAULT_OPENAI_API_KEY_ENV: &str = "OPENAI_API_KEY";

impl OpenAiClient {
    pub fn new<S: Into<String>>(
        model: S,
        url: Option<String>,
        key: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            model: model.into(),
            url: url.unwrap_or(DEFAULT_OPENAI_URL.to_owned()),
            key: match key {
                Some(key) => key,
                None => try_env_var(DEFAULT_OPENAI_API_KEY_ENV)?,
            },
        })
    }
    pub fn infer_single(&self, input: &str) -> Result<Vec<f32>> {
        let body = serde_json::json!({
            "input": input,
            "model": self.model
        });

        let data: serde_json::Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .set("Authorization", format!("Bearer {}", self.key).as_str())
            .send_bytes(
                serde_json::to_vec(&body)
                    .map_err(|error| {
                        Error::new_message(format!("Error serializing body to JSON: {error}"))
                    })?
                    .as_ref(),
            )
            .map_err(|error| Error::new_message(format!("Error sending HTTP request: {error}")))?
            .into_json()
            .map_err(|error| {
                Error::new_message(format!("Error parsing HTTP response as JSON: {error}"))
            })?;
        OpenAiClient::parse_single_response(data)
    }

    pub fn parse_single_response(value: serde_json::Value) -> Result<Vec<f32>> {
        value
            .get("data")
            .ok_or_else(|| Error::new_message("expected 'data' key in response body"))
            .and_then(|v| {
                v.get(0)
                    .ok_or_else(|| Error::new_message("expected 'data.0' path in response body"))
            })
            .and_then(|v| {
                v.get("embedding").ok_or_else(|| {
                    Error::new_message("expected 'data.0.embedding' path in response body")
                })
            })
            .and_then(|v| {
                v.as_array().ok_or_else(|| {
                    Error::new_message("expected 'data.0.embedding' path to be an array")
                })
            })
            .and_then(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_f64()
                            .ok_or_else(|| {
                                Error::new_message(
                                    "expected 'data.0.embedding' array to contain floats",
                                )
                            })
                            .map(|f| f as f32)
                    })
                    .collect()
            })
    }
}

#[derive(Clone)]
pub struct NomicClient {
    model: String,
    url: String,
    key: String,
}
const DEFAULT_NOMIC_URL: &str = "https://api-atlas.nomic.ai/v1/embedding/text";
const DEFAULT_NOMIC_API_KEY_ENV: &str = "NOMIC_API_KEY";

impl NomicClient {
    pub fn new<S: Into<String>>(
        model: S,
        url: Option<String>,
        key: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            model: model.into(),
            url: url.unwrap_or(DEFAULT_NOMIC_URL.to_owned()),
            key: match key {
                Some(key) => key,
                None => try_env_var(DEFAULT_NOMIC_API_KEY_ENV)?,
            },
        })
    }

    pub fn infer_single(&self, input: &str, input_type: Option<&str>) -> Result<Vec<f32>> {
        let mut body = serde_json::Map::new();
        body.insert("texts".to_owned(), vec![input.to_owned()].into());
        body.insert("model".to_owned(), self.model.to_owned().into());

        if let Some(input_type) = input_type {
            body.insert("input_type".to_owned(), input_type.to_owned().into());
        }

        let data: serde_json::Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .set("Authorization", format!("Bearer {}", self.key).as_str())
            .send_bytes(
                serde_json::to_vec(&body)
                    .map_err(|error| {
                        Error::new_message(format!("Error serializing body to JSON: {error}"))
                    })?
                    .as_ref(),
            )
            .map_err(|error| Error::new_message(format!("Error sending HTTP request: {error}")))?
            .into_json()
            .map_err(|error| {
                Error::new_message(format!("Error parsing HTTP response as JSON: {error}"))
            })?;
        NomicClient::parse_single_response(data)
    }
    pub fn parse_single_response(value: serde_json::Value) -> Result<Vec<f32>> {
        value
            .get("embeddings")
            .ok_or_else(|| Error::new_message("expected 'embeddings' key in response body"))
            .and_then(|v| {
                v.get(0).ok_or_else(|| {
                    Error::new_message("expected 'embeddings.0' path in response body")
                })
            })
            .and_then(|v| {
                v.as_array().ok_or_else(|| {
                    Error::new_message("expected 'embeddings.0' path to be an array")
                })
            })
            .and_then(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_f64()
                            .ok_or_else(|| {
                                Error::new_message(
                                    "expected 'embeddings.0' array to contain floats",
                                )
                            })
                            .map(|f| f as f32)
                    })
                    .collect()
            })
    }
}

#[derive(Clone)]
pub struct CohereClient {
    url: String,
    model: String,
    key: String,
}
const DEFAULT_COHERE_URL: &str = "https://api.cohere.com/v1/embed";
const DEFAULT_COHERE_API_KEY_ENV: &str = "CO_API_KEY";

impl CohereClient {
    pub fn new<S: Into<String>>(
        model: S,
        url: Option<String>,
        key: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            model: model.into(),
            url: url.unwrap_or(DEFAULT_COHERE_URL.to_owned()),
            key: match key {
                Some(key) => key,
                None => try_env_var(DEFAULT_COHERE_API_KEY_ENV)?,
            },
        })
    }

    pub fn infer_single(&self, input: &str, input_type: Option<&str>) -> Result<Vec<f32>> {
        let mut body = serde_json::Map::new();
        body.insert("texts".to_owned(), vec![input.to_owned()].into());
        body.insert("model".to_owned(), self.model.to_owned().into());

        if let Some(input_type) = input_type {
            body.insert("input_type".to_owned(), input_type.to_owned().into());
        }

        let data: serde_json::Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .set("Authorization", format!("Bearer {}", self.key).as_str())
            .send_bytes(
                serde_json::to_vec(&body)
                    .map_err(|error| {
                        Error::new_message(format!("Error serializing body to JSON: {error}"))
                    })?
                    .as_ref(),
            )
            .map_err(|error| Error::new_message(format!("Error sending HTTP request: {error}")))?
            .into_json()
            .map_err(|error| {
                Error::new_message(format!("Error parsing HTTP response as JSON: {error}"))
            })?;
        CohereClient::parse_single_response(data)
    }
    pub fn parse_single_response(value: serde_json::Value) -> Result<Vec<f32>> {
        value
            .get("embeddings")
            .ok_or_else(|| Error::new_message("expected 'embeddings' key in response body"))
            .and_then(|v| {
                v.get(0).ok_or_else(|| {
                    Error::new_message("expected 'embeddings.0' path in response body")
                })
            })
            .and_then(|v| {
                v.as_array().ok_or_else(|| {
                    Error::new_message("expected 'embeddings.0' path to be an array")
                })
            })
            .and_then(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_f64()
                            .ok_or_else(|| {
                                Error::new_message(
                                    "expected 'embeddings.0' array to contain floats",
                                )
                            })
                            .map(|f| f as f32)
                    })
                    .collect()
            })
    }
}
#[derive(Clone)]
pub struct JinaClient {
    url: String,
    model: String,
    key: String,
}
const DEFAULT_JINA_URL: &str = "https://api.jina.ai/v1/embeddings";
const DEFAULT_JINA_API_KEY_ENV: &str = "JINA_API_KEY";

impl JinaClient {
    pub fn new<S: Into<String>>(
        model: S,
        url: Option<String>,
        key: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            model: model.into(),
            url: url.unwrap_or(DEFAULT_JINA_URL.to_owned()),
            key: match key {
                Some(key) => key,
                None => try_env_var(DEFAULT_JINA_API_KEY_ENV)?,
            },
        })
    }

    pub fn infer_single(&self, input: &str) -> Result<Vec<f32>> {
        let mut body = serde_json::Map::new();
        body.insert("input".to_owned(), vec![input.to_owned()].into());
        body.insert("model".to_owned(), self.model.to_owned().into());

        let data: serde_json::Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .set("Authorization", format!("Bearer {}", self.key).as_str())
            .send_bytes(
                serde_json::to_vec(&body)
                    .map_err(|error| {
                        Error::new_message(format!("Error serializing body to JSON: {error}"))
                    })?
                    .as_ref(),
            )
            .map_err(|error| Error::new_message(format!("Error sending HTTP request: {error}")))?
            .into_json()
            .map_err(|error| {
                Error::new_message(format!("Error parsing HTTP response as JSON: {error}"))
            })?;
        JinaClient::parse_single_response(data)
    }
    pub fn parse_single_response(value: serde_json::Value) -> Result<Vec<f32>> {
        value
            .get("data")
            .ok_or_else(|| Error::new_message("expected 'data' key in response body"))
            .and_then(|v| {
                v.get(0)
                    .ok_or_else(|| Error::new_message("expected 'data.0' path in response body"))
            })
            .and_then(|v| {
                v.get("embedding").ok_or_else(|| {
                    Error::new_message("expected 'data.0.embedding' path in response body")
                })
            })
            .and_then(|v| {
                v.as_array().ok_or_else(|| {
                    Error::new_message("expected 'data.0.embedding' path to be an array")
                })
            })
            .and_then(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_f64()
                            .ok_or_else(|| {
                                Error::new_message(
                                    "expected 'data.0.embedding' array to contain floats",
                                )
                            })
                            .map(|f| f as f32)
                    })
                    .collect()
            })
    }
}
#[derive(Clone)]
pub struct MixedbreadClient {
    url: String,
    model: String,
    key: String,
}
const DEFAULT_MIXEDBREAD_URL: &str = "https://api.mixedbread.ai/v1/embeddings/";
const DEFAULT_MIXEDBREAD_API_KEY_ENV: &str = "MIXEDBREAD_API_KEY";

impl MixedbreadClient {
    pub fn new<S: Into<String>>(
        model: S,
        url: Option<String>,
        key: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            model: model.into(),
            url: url.unwrap_or(DEFAULT_MIXEDBREAD_URL.to_owned()),
            key: match key {
                Some(key) => key,
                None => try_env_var(DEFAULT_MIXEDBREAD_API_KEY_ENV)?,
            },
        })
    }

    pub fn infer_single(&self, input: &str) -> Result<Vec<f32>> {
        let mut body = serde_json::Map::new();
        body.insert("input".to_owned(), vec![input.to_owned()].into());
        body.insert("model".to_owned(), self.model.to_owned().into());

        let data: serde_json::Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .set("Authorization", format!("Bearer {}", self.key).as_str())
            .send_bytes(
                serde_json::to_vec(&body)
                    .map_err(|error| {
                        Error::new_message(format!("Error serializing body to JSON: {error}"))
                    })?
                    .as_ref(),
            )
            .map_err(|error| Error::new_message(format!("Error sending HTTP request: {error}")))?
            .into_json()
            .map_err(|error| {
                Error::new_message(format!("Error parsing HTTP response as JSON: {error}"))
            })?;
        JinaClient::parse_single_response(data)
    }
    pub fn parse_single_response(value: serde_json::Value) -> Result<Vec<f32>> {
        value
            .get("data")
            .ok_or_else(|| Error::new_message("expected 'data' key in response body"))
            .and_then(|v| {
                v.get(0)
                    .ok_or_else(|| Error::new_message("expected 'data.0' path in response body"))
            })
            .and_then(|v| {
                v.get("embedding").ok_or_else(|| {
                    Error::new_message("expected 'data.0.embedding' path in response body")
                })
            })
            .and_then(|v| {
                v.as_array().ok_or_else(|| {
                    Error::new_message("expected 'data.0.embedding' path to be an array")
                })
            })
            .and_then(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_f64()
                            .ok_or_else(|| {
                                Error::new_message(
                                    "expected 'data.0.embedding' array to contain floats",
                                )
                            })
                            .map(|f| f as f32)
                    })
                    .collect()
            })
    }
}

#[derive(Clone)]
pub struct OllamaClient {
    url: String,
    model: String,
}
const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434/api/embeddings";
impl OllamaClient {
    pub fn new<S: Into<String>>(model: S, url: Option<String>) -> Self {
        Self {
            model: model.into(),
            url: url.unwrap_or(DEFAULT_OLLAMA_URL.to_owned()),
        }
    }

    pub fn infer_single(&self, input: &str) -> Result<Vec<f32>> {
        let mut body = serde_json::Map::new();
        body.insert("prompt".to_owned(), input.to_owned().into());
        body.insert("model".to_owned(), self.model.to_owned().into());

        let data: serde_json::Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_bytes(
                serde_json::to_vec(&body)
                    .map_err(|error| {
                        Error::new_message(format!("Error serializing body to JSON: {error}"))
                    })?
                    .as_ref(),
            )
            .map_err(|error| Error::new_message(format!("Error sending HTTP request: {error}")))?
            .into_json()
            .map_err(|error| {
                Error::new_message(format!("Error parsing HTTP response as JSON: {error}"))
            })?;
        OllamaClient::parse_single_response(data)
    }
    pub fn parse_single_response(value: serde_json::Value) -> Result<Vec<f32>> {
        value
            .get("embedding")
            .ok_or_else(|| Error::new_message("expected 'embedding' key in response body"))
            .and_then(|v| {
                v.as_array()
                    .ok_or_else(|| Error::new_message("expected 'embedding' path to be an array"))
            })
            .and_then(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_f64()
                            .ok_or_else(|| {
                                Error::new_message("expected 'embedding' array to contain floats")
                            })
                            .map(|f| f as f32)
                    })
                    .collect()
            })
    }
}

#[derive(Clone)]
pub struct LlamafileClient {
    url: String,
}
const DEFAULT_LLAMAFILE_URL: &str = "http://localhost:8080/embedding";

impl LlamafileClient {
    pub fn new(url: Option<String>) -> Self {
        Self {
            url: url.unwrap_or(DEFAULT_LLAMAFILE_URL.to_owned()),
        }
    }

    pub fn infer_single(&self, input: &str) -> Result<Vec<f32>> {
        let mut body = serde_json::Map::new();
        body.insert("content".to_owned(), input.to_owned().into());

        let data: serde_json::Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_bytes(
                serde_json::to_vec(&body)
                    .map_err(|error| {
                        Error::new_message(format!("Error serializing body to JSON: {error}"))
                    })?
                    .as_ref(),
            )
            .map_err(|error| Error::new_message(format!("Error sending HTTP request: {error}")))?
            .into_json()
            .map_err(|error| {
                Error::new_message(format!("Error parsing HTTP response as JSON: {error}"))
            })?;
        OllamaClient::parse_single_response(data)
    }
}

#[derive(Clone)]
pub enum Client {
    OpenAI(OpenAiClient),
    Nomic(NomicClient),
    Cohere(CohereClient),
    Ollama(OllamaClient),
    Llamafile(LlamafileClient),
    Jina(JinaClient),
    Mixedbread(MixedbreadClient),
}
