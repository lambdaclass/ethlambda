//! A trace loaded into memory, validators decoded, so nothing is read or
//! decoded while a library is being timed.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

use ethlambda_types::beacon::containers::Validator;
use libssz::SszDecode;

use crate::format::{self, Header, Roots, StepKind, TraceReader, ValidatorBytes};

pub use format::Writes;

/// The five lists a trace starts from.
#[derive(Clone)]
pub struct Initial {
    pub validators: Vec<Validator>,
    pub balances: Vec<u64>,
    pub previous: Vec<u8>,
    pub current: Vec<u8>,
    pub inactivity: Vec<u64>,
}

pub struct Step {
    pub kind: StepKind,
    pub slot: u64,
    /// See `format::Step::rotation`.
    pub rotation: Option<usize>,
    pub validators: Writes<Validator>,
    pub balances: Writes<u64>,
    pub previous: Writes<u8>,
    pub current: Writes<u8>,
    pub inactivity: Writes<u64>,
    pub roots: Roots,
}

impl Step {
    /// Elements written per list, in `format::LIST_NAMES` order.
    pub fn counts(&self) -> [usize; 5] {
        [
            self.validators.count(),
            self.balances.count(),
            self.previous.count(),
            self.current.count(),
            self.inactivity.count(),
        ]
    }
}

pub struct Trace {
    pub header: Header,
    pub initial: Initial,
    pub initial_roots: Roots,
    pub steps: Vec<Step>,
}

pub fn load(path: &Path, max_steps: Option<usize>) -> io::Result<Trace> {
    let file = BufReader::new(File::open(path)?);
    let (mut reader, lists, initial_roots) = TraceReader::new(file)?;
    let initial = Initial {
        validators: lists
            .validators
            .iter()
            .map(decode_validator)
            .collect::<io::Result<_>>()?,
        balances: lists.balances,
        previous: lists.previous_participation,
        current: lists.current_participation,
        inactivity: lists.inactivity_scores,
    };
    let mut steps = Vec::new();
    while max_steps.is_none_or(|max| steps.len() < max) {
        let Some(step) = reader.next_step()? else {
            break;
        };
        steps.push(Step {
            kind: step.kind,
            slot: step.slot,
            rotation: step.rotation.map(|len| len as usize),
            validators: Writes {
                len: step.validators.len,
                indices: step.validators.indices,
                values: step
                    .validators
                    .values
                    .iter()
                    .map(decode_validator)
                    .collect::<io::Result<_>>()?,
            },
            balances: step.balances,
            previous: step.previous_participation,
            current: step.current_participation,
            inactivity: step.inactivity_scores,
            roots: step.roots,
        });
    }
    Ok(Trace {
        header: reader.header,
        initial,
        initial_roots,
        steps,
    })
}

fn decode_validator(bytes: &ValidatorBytes) -> io::Result<Validator> {
    Validator::from_ssz_bytes(bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}")))
}
