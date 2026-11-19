#![no_main]

//! ENR text from `--bootnodes`, a network's `bootstrap_nodes.yaml`, or a
//! discv5 crawl.
//!
//! `parse_enrs` skips entries it cannot read, so the only property is that
//! it never panics. The input is fed three ways: as the raw text, with the
//! `enr:` prefix so the base64 decoder is reached, and base64url-encoded so
//! the RLP decoder behind it sees the fuzzer's bytes as the record itself.

use base64::Engine as _;
use ethlambda_p2p::parse_enrs;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
    let mut entries = vec![format!("enr:{encoded}")];
    if let Ok(text) = std::str::from_utf8(data) {
        entries.push(text.to_string());
        entries.push(format!("enr:{text}"));
    }
    let _ = parse_enrs(entries);
});
