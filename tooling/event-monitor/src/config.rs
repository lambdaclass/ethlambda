//! TOML configuration shape (CONTRACT.md §5).

use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::timing::TimingOverrides;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Collector bind address (the dashboard URL).
    pub listen: SocketAddr,
    /// Rolling window of slots the frontend keeps (initial value; adjustable
    /// live from the dashboard).
    #[serde(default = "default_window_slots")]
    pub window_slots: u32,
    /// How many slots of recent events the collector buffers in memory to
    /// backfill a freshly-opened dashboard via `GET /api/history`.
    #[serde(default = "default_history_slots")]
    pub history_slots: u32,
    /// Directory served at `GET /`.
    #[serde(default = "default_static_dir")]
    pub static_dir: String,
    /// Upstream SSE topics to subscribe to.
    #[serde(default = "default_topics")]
    pub topics: Vec<String>,
    /// Optional offline override for slot-0 wall-clock time (seconds).
    pub genesis_time: Option<u64>,
    /// Optional offline override for slot duration (milliseconds).
    pub ms_per_slot: Option<u64>,
    /// Nodes to dial for events.
    pub nodes: Vec<NodeConfig>,
}

/// Also `Serialize` so it can be embedded directly in the `/api/meta`
/// response's `nodes` array (CONTRACT.md §4), which mirrors this shape
/// exactly: `{ "name": ..., "url": ... }`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeConfig {
    pub name: String,
    pub url: String,
}

impl NodeConfig {
    /// Joins `path` (leading slash included) onto this node's base URL, the
    /// single place the trailing-slash-tolerant URL convention lives.
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.url.trim_end_matches('/'), path)
    }
}

fn default_window_slots() -> u32 {
    30
}

fn default_history_slots() -> u32 {
    64
}

fn default_static_dir() -> String {
    "web".to_string()
}

fn default_topics() -> Vec<String> {
    vec![
        "block".to_string(),
        "attestation".to_string(),
        "aggregate".to_string(),
    ]
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("config file {path} is invalid: {reason}")]
    Invalid { path: String, reason: String },
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let config: Config = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source: Box::new(source),
        })?;
        config.validate(path)?;
        Ok(config)
    }

    /// Rejects configs that would only fail later as an opaque retry loop.
    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        let invalid = |reason: &str| ConfigError::Invalid {
            path: path.display().to_string(),
            reason: reason.to_string(),
        };
        // Upstream requires a non-empty `topics`: an empty list produces
        // `?topics=`, which every node answers with 400, so the collector would
        // otherwise retry forever without ever saying why.
        if self.topics.is_empty() {
            return Err(invalid(
                "`topics` is empty; list at least one topic to subscribe to",
            ));
        }
        if self.nodes.is_empty() {
            return Err(invalid(
                "`nodes` is empty; add at least one [[nodes]] entry",
            ));
        }
        // `static_dir` is relative to the *working directory*, not to this config
        // file, and it defaults to `web` — so every invocation from outside
        // `tooling/event-monitor/` hits this. Without the check the collector
        // starts, logs that the dashboard is ready, and answers `GET /` with a
        // 404 no one is watching for.
        let index_html = Path::new(&self.static_dir).join("index.html");
        if !index_html.is_file() {
            return Err(invalid(&format!(
                "`static_dir` is {:?} but {} does not exist; \
                 the path is relative to the working directory, not to this file",
                self.static_dir,
                index_html.display()
            )));
        }
        Ok(())
    }

    pub fn timing_overrides(&self) -> TimingOverrides {
        TimingOverrides {
            genesis_time: self.genesis_time,
            ms_per_slot: self.ms_per_slot,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_omitted() {
        let toml_str = r#"
            listen = "127.0.0.1:8080"

            [[nodes]]
            name = "node-2"
            url = "http://127.0.0.1:5052"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.window_slots, 30);
        assert_eq!(cfg.history_slots, 64);
        assert_eq!(cfg.static_dir, "web");
        assert_eq!(cfg.topics, vec!["block", "attestation", "aggregate"]);
        assert_eq!(cfg.nodes.len(), 1);
        assert!(cfg.genesis_time.is_none());
        assert!(cfg.ms_per_slot.is_none());
    }

    /// The real `web/` directory, by absolute path. `validate` checks
    /// `static_dir` against the filesystem, so fixtures must not depend on the
    /// test process's working directory.
    fn web_dir() -> String {
        format!("{}/web", env!("CARGO_MANIFEST_DIR"))
    }

    /// Parses `toml_str` with a valid absolute `static_dir` prepended, for the
    /// fixtures that go on to call [`Config::validate`].
    fn parse(toml_str: &str) -> Config {
        let with_static_dir = format!("static_dir = {:?}\n{toml_str}", web_dir());
        toml::from_str(&with_static_dir).expect("fixture should parse")
    }

    #[test]
    fn empty_topics_is_rejected_rather_than_retried_forever() {
        let cfg = parse(
            r#"
            listen = "127.0.0.1:8080"
            topics = []

            [[nodes]]
            name = "node-2"
            url = "http://127.0.0.1:5052"
        "#,
        );
        let err = cfg.validate(Path::new("config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }));
    }

    #[test]
    fn empty_nodes_is_rejected() {
        // `nodes` has no serde default, so omitting it fails deserialization
        // before validation ever runs; an explicit empty list is the only way to
        // express this, and it is what the check exists for.
        let cfg = parse(
            r#"
            listen = "127.0.0.1:8080"
            nodes = []
        "#,
        );
        let err = cfg.validate(Path::new("config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }));
    }

    #[test]
    fn a_config_without_a_nodes_key_fails_to_parse() {
        let err = toml::from_str::<Config>(r#"listen = "127.0.0.1:8080""#).unwrap_err();
        assert!(err.to_string().contains("nodes"), "unexpected error: {err}");
    }

    #[test]
    fn a_populated_config_passes_validation() {
        let cfg = parse(
            r#"
            listen = "127.0.0.1:8080"

            [[nodes]]
            name = "node-2"
            url = "http://127.0.0.1:5052"
        "#,
        );
        assert!(cfg.validate(Path::new("config.toml")).is_ok());
    }

    #[test]
    fn a_static_dir_without_an_index_html_is_rejected() {
        // Regression: this used to start cleanly, log "dashboard ready", and
        // answer GET / with a 404. It fires on any invocation from outside
        // `tooling/event-monitor/`, since `static_dir` defaults to `web`.
        let cfg: Config = toml::from_str(
            r#"
            listen = "127.0.0.1:8080"
            static_dir = "definitely-not-a-real-directory"

            [[nodes]]
            name = "node-2"
            url = "http://127.0.0.1:5052"
        "#,
        )
        .expect("fixture should parse");
        let err = cfg.validate(Path::new("config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }));
        assert!(
            err.to_string().contains("index.html"),
            "the error should name the file it looked for: {err}"
        );
    }

    #[test]
    fn overrides_and_multiple_nodes_parse() {
        let toml_str = r#"
            listen = "127.0.0.1:8080"
            window_slots = 10
            history_slots = 128
            static_dir = "public"
            topics = ["block"]
            genesis_time = 1770407233
            ms_per_slot = 4000

            [[nodes]]
            name = "node-2"
            url = "http://127.0.0.1:5052"

            [[nodes]]
            name = "node-3"
            url = "http://127.0.0.1:5053"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.window_slots, 10);
        assert_eq!(cfg.history_slots, 128);
        assert_eq!(cfg.static_dir, "public");
        assert_eq!(cfg.topics, vec!["block"]);
        assert_eq!(cfg.genesis_time, Some(1770407233));
        assert_eq!(cfg.ms_per_slot, Some(4000));
        assert_eq!(cfg.nodes.len(), 2);
        assert_eq!(cfg.nodes[1].name, "node-3");
    }
}
