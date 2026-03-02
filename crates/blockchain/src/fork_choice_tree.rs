use std::collections::HashMap;
use std::fmt::Write;

use ethlambda_types::{ShortRoot, checkpoint::Checkpoint, primitives::H256};

/// Maximum depth of the tree to display before truncating with `...`.
const MAX_DISPLAY_DEPTH: usize = 20;

/// Format the fork choice tree as an ASCII art string for terminal logging.
///
/// Renders a tree showing the chain structure with Unicode connectors,
/// missing-slot indicators, weight annotations, and head markers.
pub(crate) fn format_fork_choice_tree(
    blocks: &HashMap<H256, (u64, H256)>,
    weights: &HashMap<H256, u64>,
    head: H256,
    justified: Checkpoint,
    finalized: Checkpoint,
) -> String {
    let mut output = String::new();

    // Header
    writeln!(output, "Fork Choice Tree:").unwrap();
    writeln!(
        output,
        "  Finalized: slot {} | root {}",
        finalized.slot,
        ShortRoot(&finalized.root.0)
    )
    .unwrap();
    writeln!(
        output,
        "  Justified: slot {} | root {}",
        justified.slot,
        ShortRoot(&justified.root.0)
    )
    .unwrap();
    writeln!(
        output,
        "  Head:      slot {} | root {}",
        blocks.get(&head).map(|(slot, _)| *slot).unwrap_or(0),
        ShortRoot(&head.0)
    )
    .unwrap();

    if blocks.is_empty() {
        writeln!(output, "\n  (empty)").unwrap();
        return output;
    }

    // Build children map
    let mut children_map: HashMap<H256, Vec<H256>> = HashMap::new();
    for (root, &(_, parent_root)) in blocks {
        if !parent_root.is_zero() && blocks.contains_key(&parent_root) {
            children_map.entry(parent_root).or_default().push(*root);
        }
    }

    // Sort children by weight descending, tiebreaker on root hash descending
    for children in children_map.values_mut() {
        children.sort_by(|a, b| {
            let wa = weights.get(a).copied().unwrap_or(0);
            let wb = weights.get(b).copied().unwrap_or(0);
            wb.cmp(&wa).then_with(|| b.cmp(a))
        });
    }

    let renderer = TreeRenderer {
        blocks,
        children_map: &children_map,
        weights,
        head,
    };

    // Find root node (block whose parent is not in the blocks map)
    let tree_root = find_tree_root(blocks);

    // Render linear trunk from root until a fork or leaf
    output.push('\n');
    let (trunk_tip, trunk_depth) = renderer.render_trunk(&mut output, tree_root);

    // Render branching subtree from the fork point
    let children = children_map.get(&trunk_tip).cloned().unwrap_or_default();
    if children.len() > 1 {
        let branch_count = children.len();
        writeln!(output, " \u{2500} {branch_count} branches").unwrap();
        renderer.render_branches(&mut output, &children, "  ", trunk_depth);
    } else if trunk_tip == head {
        writeln!(output, " *").unwrap();
    } else {
        writeln!(output).unwrap();
    }

    output
}

/// Holds shared tree data to avoid passing many arguments through recursive calls.
struct TreeRenderer<'a> {
    blocks: &'a HashMap<H256, (u64, H256)>,
    children_map: &'a HashMap<H256, Vec<H256>>,
    weights: &'a HashMap<H256, u64>,
    head: H256,
}

impl TreeRenderer<'_> {
    /// Render the linear trunk (chain without forks) starting from `root`.
    /// Returns the last rendered node and current depth.
    fn render_trunk(&self, output: &mut String, root: H256) -> (H256, usize) {
        let mut current = root;
        let mut depth = 0;
        let mut prev_slot: Option<u64> = None;

        write!(output, "  ").unwrap();

        loop {
            let &(slot, _) = &self.blocks[&current];

            // Insert missing slot indicators
            render_gap(output, prev_slot, slot, &mut depth);

            // Render current node
            write!(output, "{}({slot})", ShortRoot(&current.0)).unwrap();
            depth += 1;

            if depth >= MAX_DISPLAY_DEPTH {
                write!(output, "\u{2500}\u{2500} ...").unwrap();
                return (current, depth);
            }

            let children = self.children_map.get(&current);
            match children.map(|c| c.len()) {
                Some(1) => {
                    write!(output, "\u{2500}\u{2500} ").unwrap();
                    prev_slot = Some(slot);
                    current = children.unwrap()[0];
                }
                _ => {
                    // Fork point or leaf — stop trunk rendering
                    return (current, depth);
                }
            }
        }
    }

    /// Render branches from a fork point using tree connectors.
    fn render_branches(&self, output: &mut String, children: &[H256], prefix: &str, depth: usize) {
        for (i, &child) in children.iter().enumerate() {
            let is_last = i == children.len() - 1;
            let connector = if is_last {
                "\u{2514}\u{2500}\u{2500} "
            } else {
                "\u{251c}\u{2500}\u{2500} "
            };
            let continuation = if is_last { "    " } else { "\u{2502}   " };

            write!(output, "{prefix}{connector}").unwrap();
            self.render_branch_line(output, child, prefix, continuation, depth);
        }
    }

    /// Render a single branch line, following the chain until a fork or leaf.
    fn render_branch_line(
        &self,
        output: &mut String,
        start: H256,
        prefix: &str,
        continuation: &str,
        mut depth: usize,
    ) {
        let mut current = start;
        let parent_slot = self
            .blocks
            .get(&current)
            .and_then(|&(_, parent)| self.blocks.get(&parent))
            .map(|&(slot, _)| slot);
        let mut prev_slot = parent_slot;

        loop {
            let &(slot, _) = &self.blocks[&current];

            // Insert missing slot indicators
            render_gap(output, prev_slot, slot, &mut depth);

            let is_head = current == self.head;
            write!(output, "{}({slot})", ShortRoot(&current.0)).unwrap();
            depth += 1;

            if depth >= MAX_DISPLAY_DEPTH {
                writeln!(output, "\u{2500}\u{2500} ...").unwrap();
                return;
            }

            let node_children = self.children_map.get(&current).map(|c| c.as_slice());

            match node_children.unwrap_or_default() {
                [] => {
                    // Leaf node — show head marker and weight
                    let head_marker = if is_head { " *" } else { "" };
                    let w = self.weights.get(&current).copied().unwrap_or(0);
                    writeln!(output, "{head_marker}  [w:{w}]").unwrap();
                    return;
                }
                [only_child] => {
                    // Continue linear chain
                    if is_head {
                        write!(output, " *").unwrap();
                    }
                    write!(output, "\u{2500}\u{2500} ").unwrap();
                    prev_slot = Some(slot);
                    current = *only_child;
                }
                children => {
                    // Sub-fork
                    if is_head {
                        write!(output, " *").unwrap();
                    }
                    let branch_count = children.len();
                    writeln!(output, " \u{2500} {branch_count} branches").unwrap();
                    let new_prefix = format!("{prefix}{continuation}");
                    self.render_branches(output, children, &new_prefix, depth);
                    return;
                }
            }
        }
    }
}

/// Find the root of the tree (block whose parent is not in the map).
fn find_tree_root(blocks: &HashMap<H256, (u64, H256)>) -> H256 {
    blocks
        .iter()
        .filter(|(_, (_, parent))| parent.is_zero() || !blocks.contains_key(parent))
        .min_by_key(|(_, (slot, _))| *slot)
        .map(|(root, _)| *root)
        .expect("blocks is non-empty")
}

/// Write missing-slot indicators between `prev_slot` and `slot`.
fn render_gap(output: &mut String, prev_slot: Option<u64>, slot: u64, depth: &mut usize) {
    if let Some(ps) = prev_slot {
        let gap = slot.saturating_sub(ps).saturating_sub(1);
        if gap == 1 {
            write!(output, "[ ]\u{2500}\u{2500} ").unwrap();
            *depth += 1;
        } else if gap > 1 {
            write!(output, "[{gap}]\u{2500}\u{2500} ").unwrap();
            *depth += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

    fn cp(root: H256, slot: u64) -> Checkpoint {
        Checkpoint { root, slot }
    }

    #[test]
    fn linear_chain() {
        // root(0) -> a(1) -> b(2) -> c(3)
        let root = h(1);
        let a = h(2);
        let b = h(3);
        let c = h(4);

        let mut blocks = HashMap::new();
        blocks.insert(root, (0, H256::ZERO));
        blocks.insert(a, (1, root));
        blocks.insert(b, (2, a));
        blocks.insert(c, (3, b));

        let weights = HashMap::new();
        let result = format_fork_choice_tree(&blocks, &weights, c, cp(root, 0), cp(root, 0));

        assert!(result.contains("Fork Choice Tree:"));
        // Should show nodes in sequence
        assert!(result.contains(&format!("{}(0)", ShortRoot(&root.0))));
        assert!(result.contains(&format!("{}(3)", ShortRoot(&c.0))));
        // Head should be marked
        assert!(result.contains("*"));
    }

    #[test]
    fn fork_with_two_branches() {
        // root(0) -> a(1) -> b(2) [fork point]
        //                    ├── c(3) [head, w:3]
        //                    └── d(3) [w:1]
        let root = h(1);
        let a = h(2);
        let b = h(3);
        let c = h(4);
        let d = h(5);

        let mut blocks = HashMap::new();
        blocks.insert(root, (0, H256::ZERO));
        blocks.insert(a, (1, root));
        blocks.insert(b, (2, a));
        blocks.insert(c, (3, b));
        blocks.insert(d, (3, b));

        let mut weights = HashMap::new();
        weights.insert(c, 3);
        weights.insert(d, 1);

        let result = format_fork_choice_tree(&blocks, &weights, c, cp(root, 0), cp(root, 0));

        assert!(
            result.contains("\u{251c}\u{2500}\u{2500}")
                || result.contains("\u{2514}\u{2500}\u{2500}")
        );
        assert!(result.contains("2 branches"));
        assert!(result.contains("[w:3]"));
        assert!(result.contains("[w:1]"));
        assert!(result.contains("*"));
    }

    #[test]
    fn missing_single_slot() {
        // root(0) -> a(2) (slot 1 missing)
        let root = h(1);
        let a = h(2);

        let mut blocks = HashMap::new();
        blocks.insert(root, (0, H256::ZERO));
        blocks.insert(a, (2, root));

        let weights = HashMap::new();
        let result = format_fork_choice_tree(&blocks, &weights, a, cp(root, 0), cp(root, 0));

        assert!(result.contains("[ ]"));
    }

    #[test]
    fn missing_multiple_slots() {
        // root(0) -> a(4) (slots 1-3 missing)
        let root = h(1);
        let a = h(2);

        let mut blocks = HashMap::new();
        blocks.insert(root, (0, H256::ZERO));
        blocks.insert(a, (4, root));

        let weights = HashMap::new();
        let result = format_fork_choice_tree(&blocks, &weights, a, cp(root, 0), cp(root, 0));

        assert!(result.contains("[3]"));
    }

    #[test]
    fn empty_blocks() {
        let blocks = HashMap::new();
        let weights = HashMap::new();
        let result = format_fork_choice_tree(
            &blocks,
            &weights,
            H256::ZERO,
            cp(H256::ZERO, 0),
            cp(H256::ZERO, 0),
        );

        assert!(result.contains("Fork Choice Tree:"));
        assert!(result.contains("(empty)"));
    }

    #[test]
    fn single_block_chain() {
        let root = h(1);

        let mut blocks = HashMap::new();
        blocks.insert(root, (0, H256::ZERO));

        let weights = HashMap::new();
        let result = format_fork_choice_tree(&blocks, &weights, root, cp(root, 0), cp(root, 0));

        assert!(result.contains(&format!("{}(0)", ShortRoot(&root.0))));
        assert!(result.contains("*"));
    }

    #[test]
    fn depth_truncation() {
        // Build a chain of 25 blocks (exceeds MAX_DISPLAY_DEPTH=20)
        let nodes: Vec<H256> = (1..=25).map(h).collect();

        let mut blocks = HashMap::new();
        blocks.insert(nodes[0], (0, H256::ZERO));
        for i in 1..25 {
            blocks.insert(nodes[i], (i as u64, nodes[i - 1]));
        }

        let weights = HashMap::new();
        let head = nodes[24];
        let result =
            format_fork_choice_tree(&blocks, &weights, head, cp(nodes[0], 0), cp(nodes[0], 0));

        assert!(
            result.contains("..."),
            "long chain should be truncated with ..."
        );
        // The last node (slot 24) should NOT appear since we truncate at depth 20
        assert!(
            !result.contains("(24)"),
            "slot 24 should not appear due to truncation"
        );
    }

    #[test]
    fn nested_fork() {
        // root(0) -> a(1) -> b(2) [fork]
        //                    ├── c(3) -> e(4) [sub-fork]
        //                    │   ├── f(5) [head, w:4]
        //                    │   └── g(5) [w:1]
        //                    └── d(3) [w:2]
        let root = h(1);
        let a = h(2);
        let b = h(3);
        let c = h(4);
        let d = h(5);
        let e = h(6);
        let f = h(7);
        let g = h(8);

        let mut blocks = HashMap::new();
        blocks.insert(root, (0, H256::ZERO));
        blocks.insert(a, (1, root));
        blocks.insert(b, (2, a));
        blocks.insert(c, (3, b));
        blocks.insert(d, (3, b));
        blocks.insert(e, (4, c));
        blocks.insert(f, (5, e));
        blocks.insert(g, (5, e));

        let mut weights = HashMap::new();
        weights.insert(c, 5);
        weights.insert(d, 2);
        weights.insert(e, 4);
        weights.insert(f, 4);
        weights.insert(g, 1);

        let result = format_fork_choice_tree(&blocks, &weights, f, cp(root, 0), cp(root, 0));

        // Should have two levels of branching
        assert!(result.contains("2 branches"), "should show outer fork");
        // Nested fork should also show branches
        let branch_count = result.matches("2 branches").count();
        assert_eq!(branch_count, 2, "should show both outer and inner fork");
        assert!(result.contains("[w:4]"));
        assert!(result.contains("[w:1]"));
        assert!(result.contains("[w:2]"));
    }

    #[test]
    fn head_marker_on_correct_node() {
        // root(0) -> a(1) -> b(2) [fork]
        //                    ├── c(3) [head]
        //                    └── d(3)
        let root = h(1);
        let a = h(2);
        let b = h(3);
        let c = h(4);
        let d = h(5);

        let mut blocks = HashMap::new();
        blocks.insert(root, (0, H256::ZERO));
        blocks.insert(a, (1, root));
        blocks.insert(b, (2, a));
        blocks.insert(c, (3, b));
        blocks.insert(d, (3, b));

        let mut weights = HashMap::new();
        weights.insert(c, 5);
        weights.insert(d, 2);

        let result = format_fork_choice_tree(&blocks, &weights, c, cp(root, 0), cp(root, 0));

        // The head node c should have * after it
        let c_repr = format!("{}(3)", ShortRoot(&c.0));
        let c_pos = result.find(&c_repr).expect("c should appear in output");
        let after_c = &result[c_pos + c_repr.len()..];
        assert!(
            after_c.starts_with(" *"),
            "head marker should follow node c, got: {after_c:?}"
        );
    }
}
