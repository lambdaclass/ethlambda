//! Graded SG healing (PROTOCOL.md figure `alg:fc-full`, appendix A.8, A.11,
//! A.12, A.13): relative-majority grades at three cutoff pairs, saved once
//! per round, and the readers built on them.
//!
//! # The relative majority, per validator
//!
//! For a validator `v`, let `E_v` and `L_v` be its votes in the window `I_r`
//! resolved by the early and the late cutoff (a resolved vote has an empty
//! safe value, or a processed safe block compatible with `Σ.F` and stamped
//! before the cutoff), and `R_v` its votes merely received before the late
//! cutoff. With `u` the latest vote in `E_v`:
//!
//! * `v` supports `B` iff `u` covers `B`, `R_v` holds no equivocation at or
//!   after `u.round`, and every later vote in `L_v` covers `B`. Covering is
//!   ancestry, so the supported blocks are exactly the ancestors of the
//!   deepest common ancestor of those heads: one *support tip* per validator.
//! * `v` opposes `B` iff some vote in `L_v` at or after every round of `E_v`
//!   does not cover `B`, or `R_v` equivocates there. That is "everything" (an
//!   equivocation, or an empty safe value), or every block except the
//!   ancestors of the deepest common ancestor of those heads.
//!
//! Support only grows and opposition only shrinks towards the root, so the
//! graded blocks lie on one chain and the deepest one is found by marking
//! ancestors of the support tips (`A.8`: "the blocks holding a relative
//! majority therefore lie on one chain").

use std::collections::{BTreeMap, HashMap};

use ethlambda_types::primitives::H256;

use crate::params::Grade;
use crate::store::Store;
use crate::types::{Round, Tick, ValidatorIndex};

/// One round's saved grades. `None` is pending (not yet completed);
/// `Some(None)` is completed with no graded block; `Some(Some(root))` is the
/// deepest graded block at completion time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Frame {
    pub g0: Option<Option<H256>>,
    pub g1: Option<Option<H256>>,
    pub g2: Option<Option<H256>>,
}

impl Frame {
    fn completed_empty() -> Self {
        Self {
            g0: Some(None),
            g1: Some(None),
            g2: Some(None),
        }
    }

    fn slot(&mut self, grade: Grade) -> &mut Option<Option<H256>> {
        match grade {
            Grade::G0 => &mut self.g0,
            Grade::G1 => &mut self.g1,
            Grade::G2 => &mut self.g2,
        }
    }

    pub fn get(&self, grade: Grade) -> Option<Option<H256>> {
        match grade {
            Grade::G0 => self.g0,
            Grade::G1 => self.g1,
            Grade::G2 => self.g2,
        }
    }

    pub fn all_closed(&self) -> bool {
        self.g0.is_some() && self.g1.is_some() && self.g2.is_some()
    }
}

/// The saved grades of the current round and the next one: grade 2 of round
/// `r + 1` completes at `T_{r+1} − Δ`, inside round `r`, so both frames must
/// coexist until the opening tick rotates them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GradeCache {
    pub round: Round,
    pub current: Frame,
    pub next: Frame,
}

impl GradeCache {
    /// At the anchor's round every grade is completed and empty (round 0
    /// reads no votes); the next round's are pending.
    pub fn initial(round: Round) -> Self {
        Self {
            round,
            current: Frame::completed_empty(),
            next: Frame::default(),
        }
    }

    /// Rotate to `round`. A skipped round starts pending; nothing missed is
    /// reconstructed.
    fn align(&mut self, round: Round) {
        if round == self.round {
            return;
        }
        if round == self.round + 1 {
            self.current = self.next;
        } else {
            self.current = Frame::default();
        }
        self.next = Frame::default();
        self.round = round;
    }

    fn frame(&self, round: Round) -> Frame {
        if round == self.round {
            self.current
        } else if round == self.round + 1 {
            self.next
        } else {
            Frame::default()
        }
    }
}

/// What one validator's window of votes says about every block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opposition {
    Nothing,
    Everything,
    /// Every block that is not an ancestor-or-self of this one.
    AllExcept(H256),
}

#[derive(Debug, Clone, Copy)]
struct Stance {
    support: Option<H256>,
    opposition: Opposition,
}

/// A vote token `(round, safe)` with its receipt stamp.
#[derive(Debug, Clone, Copy)]
struct Token {
    round: Round,
    key: Option<H256>,
    stamp: Tick,
}

impl Store {
    /// `update_grades(Σ, t)` (§2.2): at a completion time, evaluate the grade
    /// over the processed tree and save the deepest graded block. Runs at
    /// every tick, before the clock advances.
    pub(crate) fn update_grades(&mut self, t: Tick) {
        let round = self.params.round_of(crate::params::slot_of(t));
        self.grades.align(round);
        for frame_round in [round, round + 1] {
            for grade in Grade::ALL {
                let completion = self.params.round_start(frame_round) + grade.completion_offset();
                if t != completion {
                    continue;
                }
                let pending = match frame_round == self.grades.round {
                    true => self.grades.current.get(grade).is_none(),
                    false => self.grades.next.get(grade).is_none(),
                };
                if !pending {
                    continue;
                }
                let early = self.params.round_start(frame_round) + grade.early_offset();
                let late = self.params.round_start(frame_round) + grade.late_offset();
                let result = self.graded_block(frame_round, early, late);
                let frame = match frame_round == self.grades.round {
                    true => &mut self.grades.current,
                    false => &mut self.grades.next,
                };
                *frame.slot(grade) = Some(result);
            }
        }
    }

    /// The round's saved frame, every block clipped to `Σ.F` (the finality
    /// clip of `update_finality`, applied at read time).
    pub(crate) fn read_frame(&self, round: Round) -> Frame {
        let clip = |g: Option<Option<H256>>| g.map(|g| g.map(|root| self.clip_to_finalized(&root)));
        let frame = self.grades.frame(round);
        Frame {
            g0: clip(frame.g0),
            g1: clip(frame.g1),
            g2: clip(frame.g2),
        }
    }

    /// The current round's saved grades, for diagnostics.
    pub fn saved_grades(&self) -> Frame {
        self.read_frame(self.current_round())
    }

    /// `graded_block(Σ, r, h, e)`: the deepest block of the processed tree
    /// holding a relative majority over `I_r` at cutoffs `(early, late)`.
    pub(crate) fn graded_block(&self, round: Round, early: Tick, late: Tick) -> Option<H256> {
        let stances = self.stances(round, early, late);
        if stances.is_empty() {
            return None;
        }
        let finalized_depth = self.blocks[&self.finalized].depth;

        // Weights marked on blocks at or below `Σ.F` (descendants of it): the
        // support each block collects and the opposition it escapes.
        let mut support: HashMap<H256, u64> = HashMap::new();
        let mut spared: HashMap<H256, u64> = HashMap::new();
        let mut support_any = 0u64;
        let mut opposes_everything = 0u64;
        let mut opposes_some = 0u64;
        for (validator, stance) in &stances {
            let weight = self.electorate.weight(*validator);
            if let Some(tip) = stance.support {
                support_any += weight;
                self.mark_down_to_finalized(&tip, finalized_depth, weight, &mut support);
            }
            match stance.opposition {
                Opposition::Nothing => {}
                Opposition::Everything => opposes_everything += weight,
                Opposition::AllExcept(tip) => {
                    opposes_some += weight;
                    self.mark_down_to_finalized(&tip, finalized_depth, weight, &mut spared);
                }
            }
        }

        let graded = |block: &H256| {
            let pos = support.get(block).copied().unwrap_or(0);
            let opp = opposes_everything + opposes_some - spared.get(block).copied().unwrap_or(0);
            pos > opp
        };
        let deepest = support
            .keys()
            .filter(|block| graded(block))
            .copied()
            .reduce(|best, block| {
                if self.deeper(&block, &best) {
                    block
                } else {
                    best
                }
            });
        if deepest.is_some() {
            return deepest;
        }
        // Nothing at or below `Σ.F` is graded. Grades are monotone towards the
        // root, so an ancestor of `Σ.F` is graded iff the anchor is; every
        // supporter covers the anchor, and only "everything" opposes it. The
        // anchor then stands for that ancestor (see `clip_to_finalized`).
        (support_any > opposes_everything).then_some(self.anchor)
    }

    /// Add `weight` to `tip` and its ancestors down to depth `floor`, if `tip`
    /// descends from `Σ.F`. A tip that is a strict ancestor of `Σ.F` marks
    /// nothing at or below it.
    fn mark_down_to_finalized(
        &self,
        tip: &H256,
        floor: u64,
        weight: u64,
        marks: &mut HashMap<H256, u64>,
    ) {
        if !self.is_ancestor(&self.finalized, tip) {
            return;
        }
        let mut cursor = *tip;
        loop {
            *marks.entry(cursor).or_default() += weight;
            let node = &self.blocks[&cursor];
            if node.depth <= floor {
                break;
            }
            cursor = node.parent.expect("a descendant of F has a parent");
        }
    }

    /// Each window voter's support tip and opposition.
    fn stances(&self, round: Round, early: Tick, late: Tick) -> BTreeMap<ValidatorIndex, Stance> {
        let mut tokens: BTreeMap<ValidatorIndex, Vec<Token>> = BTreeMap::new();
        for window_round in self.params.grade_window(round) {
            let Some(pool) = self.attestations.get(&window_round) else {
                continue;
            };
            for pooled in pool {
                if pooled.stamp >= late {
                    continue;
                }
                tokens
                    .entry(pooled.attestation.validator)
                    .or_default()
                    .push(Token {
                        round: window_round,
                        key: pooled.attestation.data.safe(),
                        stamp: pooled.stamp,
                    });
            }
        }
        tokens
            .into_iter()
            .map(|(validator, raw)| (validator, self.stance(&raw, early, late)))
            .collect()
    }

    /// A token is resolved by `cutoff` when it arrived before it and its safe
    /// value is empty, or a processed block compatible with `Σ.F` that was
    /// also processed before it.
    fn resolved_by(&self, token: &Token, cutoff: Tick) -> bool {
        if token.stamp >= cutoff {
            return false;
        }
        match token.key {
            None => true,
            Some(root) => self.node(&root).is_some_and(|block| {
                block.stamp < cutoff && self.compatible(&root, &self.finalized)
            }),
        }
    }

    fn stance(&self, raw: &[Token], early: Tick, late: Tick) -> Stance {
        let early_votes: Vec<&Token> = raw.iter().filter(|t| self.resolved_by(t, early)).collect();
        let late_votes: Vec<&Token> = raw.iter().filter(|t| self.resolved_by(t, late)).collect();
        let k0 = early_votes.iter().map(|t| t.round).max();
        let equivocates_from = |from: Round| {
            raw.iter().any(|x| {
                x.round >= from && raw.iter().any(|y| y.round == x.round && y.key != x.key)
            })
        };

        let support = k0.and_then(|latest_round| {
            let mut latest = early_votes.iter().filter(|t| t.round == latest_round);
            let u = latest.next()?;
            if latest.any(|other| other.key != u.key) || equivocates_from(latest_round) {
                return None;
            }
            let mut tip = u.key?;
            for later in late_votes.iter().filter(|t| t.round > latest_round) {
                tip = self.meet(&tip, &later.key?)?;
            }
            Some(tip)
        });

        let from = k0.unwrap_or(0);
        let opposition = if equivocates_from(from) {
            Opposition::Everything
        } else {
            let mut tip: Option<H256> = None;
            let mut everything = false;
            for x in late_votes.iter().filter(|t| t.round >= from) {
                match x.key {
                    None => everything = true,
                    Some(head) => {
                        tip = Some(match tip {
                            None => head,
                            Some(current) => self.meet(&current, &head).unwrap_or(self.anchor),
                        })
                    }
                }
            }
            match (everything, tip) {
                (true, _) => Opposition::Everything,
                (false, Some(tip)) => Opposition::AllExcept(tip),
                (false, None) => Opposition::Nothing,
            }
        };
        Stance {
            support,
            opposition,
        }
    }

    /// `active_prefix(Σ, g)`: the deepest block of the filtered tree that is
    /// an ancestor-or-self of `g`.
    pub(crate) fn active_prefix(&self, g: Option<H256>) -> Option<H256> {
        let g = g?;
        let tree = self.filtered_tree(None);
        let root_depth = self.depth(&self.fg_root())?;
        let mut cursor = g;
        loop {
            if tree.contains(&cursor) {
                return Some(cursor);
            }
            let node = self.node(&cursor)?;
            if node.depth <= root_depth {
                return None;
            }
            cursor = node.parent?;
        }
    }

    /// `G0_compatible(Σ, B)`: true while grade 0 is empty or pending.
    pub(crate) fn g0_compatible(&self, frame: &Frame, block: &H256) -> bool {
        match frame.g0 {
            Some(Some(g0)) => self.compatible(block, &g0),
            _ => true,
        }
    }

    /// `get_sg_root(Σ)` (§2.2, A.13): the active prefix of the saved grade-1
    /// block, else the FG root.
    pub fn sg_root(&self) -> H256 {
        let frame = self.read_frame(self.current_round());
        match frame.g1 {
            Some(Some(g1)) => self
                .active_prefix(Some(g1))
                .unwrap_or_else(|| self.fg_root()),
            _ => self.fg_root(),
        }
    }

    /// `A_G2`: the active prefix of the saved grade-2 block, once all three
    /// grades of the round are complete.
    pub(crate) fn grade2_block(&self, frame: &Frame) -> Option<H256> {
        if !frame.all_closed() {
            return None;
        }
        self.active_prefix(frame.g2.flatten())
    }

    /// The deepest block `B` on `C`'s chain with `floor ⪯ B ⪯ C` that is
    /// grade-0 compatible.
    ///
    /// Walking up from `C`, the first compatible block is the deepest one:
    /// the blocks of a chain compatible with a fixed block are a prefix of it
    /// plus, when that block is on the chain, everything below it.
    pub(crate) fn deepest_clear(&self, floor: &H256, c: &H256, frame: &Frame) -> Option<H256> {
        if !self.is_ancestor(floor, c) {
            return None;
        }
        let floor_depth = self.depth(floor)?;
        let mut cursor = *c;
        loop {
            if self.g0_compatible(frame, &cursor) {
                return Some(cursor);
            }
            let node = self.node(&cursor)?;
            if node.depth <= floor_depth {
                return None;
            }
            cursor = node.parent?;
        }
    }

    /// `stable_root(Σ)`: the active prefix of the saved grade-2 block, else
    /// the FG root. Never empty.
    pub(crate) fn stable_root(&self) -> H256 {
        let frame = self.read_frame(self.current_round());
        self.active_prefix(frame.g2.flatten())
            .unwrap_or_else(|| self.fg_root())
    }
}
