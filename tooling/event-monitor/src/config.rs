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
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source: Box::new(source),
        })
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
