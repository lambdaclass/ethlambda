/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import EthLambdaProofs.Justifiability.Classification

/-!
# Density Bound for Justifiable Slots
-/

noncomputable instance : DecidablePred Justifiable := fun _ => Classical.dec _
noncomputable instance : DecidablePred IsPronic := fun _ => Classical.dec _

private theorem squares_count_le (N : ℕ) :
    ((Finset.range N).filter (fun d => IsSquare d)).card ≤ Nat.sqrt N + 1 := by
  calc ((Finset.range N).filter (fun d => IsSquare d)).card
      ≤ ((Finset.range (Nat.sqrt N + 1)).image (· ^ 2)).card := by
        apply Finset.card_le_card
        intro d hd
        simp only [Finset.mem_filter, Finset.mem_range] at hd
        simp only [Finset.mem_image, Finset.mem_range]
        obtain ⟨hlt, ⟨r, hr⟩⟩ := hd
        refine ⟨r, ?_, by nlinarith⟩
        have : r ≤ Nat.sqrt N := Nat.le_sqrt.mpr (by nlinarith)
        omega
    _ ≤ (Finset.range (Nat.sqrt N + 1)).card := Finset.card_image_le
    _ = Nat.sqrt N + 1 := Finset.card_range _

private theorem pronics_count_le (N : ℕ) :
    ((Finset.range N).filter (fun d => IsPronic d)).card ≤ Nat.sqrt N + 1 := by
  calc ((Finset.range N).filter (fun d => IsPronic d)).card
      ≤ ((Finset.range (Nat.sqrt N + 1)).image (fun n => n * (n + 1))).card := by
        apply Finset.card_le_card
        intro d hd
        simp only [Finset.mem_filter, Finset.mem_range] at hd
        simp only [Finset.mem_image, Finset.mem_range]
        obtain ⟨hlt, ⟨n, hn⟩⟩ := hd
        refine ⟨n, ?_, hn.symm⟩
        have : n ≤ Nat.sqrt N := Nat.le_sqrt.mpr (by nlinarith)
        omega
    _ ≤ (Finset.range (Nat.sqrt N + 1)).card := Finset.card_image_le
    _ = Nat.sqrt N + 1 := Finset.card_range _

private theorem small_count_le (N : ℕ) :
    ((Finset.range N).filter (fun d => d ≤ 5)).card ≤ 6 := by
  calc ((Finset.range N).filter (fun d => d ≤ 5)).card
      ≤ ((Finset.range 6).filter (fun d => d ≤ 5)).card := by
        apply Finset.card_le_card
        intro d hd
        simp only [Finset.mem_filter, Finset.mem_range] at hd ⊢
        exact ⟨by omega, hd.2⟩
    _ ≤ (Finset.range 6).card := Finset.card_filter_le _ _
    _ = 6 := Finset.card_range _

/-- Justifiable deltas up to `N` grow as `O(√N)`. -/
theorem justifiable_density (N : ℕ) :
    ((Finset.range N).filter (fun d => Justifiable d)).card
      ≤ 2 * Nat.sqrt N + 8 := by
  have hsub : (Finset.range N).filter (fun d => Justifiable d) ⊆
      ((Finset.range N).filter (fun d => d ≤ 5)) ∪
      ((Finset.range N).filter (fun d => IsSquare d)) ∪
      ((Finset.range N).filter (fun d => IsPronic d)) := by
    intro d hd
    simp only [Finset.mem_filter, Finset.mem_range, Finset.mem_union] at hd ⊢
    obtain ⟨hlt, h1 | h2 | h3⟩ := hd
    · left; left; exact ⟨hlt, h1⟩
    · left; right; exact ⟨hlt, h2⟩
    · right; exact ⟨hlt, h3⟩
  calc ((Finset.range N).filter (fun d => Justifiable d)).card
      ≤ (((Finset.range N).filter (fun d => d ≤ 5)) ∪
         ((Finset.range N).filter (fun d => IsSquare d)) ∪
         ((Finset.range N).filter (fun d => IsPronic d))).card :=
        Finset.card_le_card hsub
    _ ≤ (((Finset.range N).filter (fun d => d ≤ 5)) ∪
         ((Finset.range N).filter (fun d => IsSquare d))).card +
        ((Finset.range N).filter (fun d => IsPronic d)).card :=
        Finset.card_union_le _ _
    _ ≤ (((Finset.range N).filter (fun d => d ≤ 5)).card +
         ((Finset.range N).filter (fun d => IsSquare d)).card) +
        ((Finset.range N).filter (fun d => IsPronic d)).card := by
        linarith [Finset.card_union_le
          ((Finset.range N).filter (fun d => d ≤ 5))
          ((Finset.range N).filter (fun d => IsSquare d))]
    _ ≤ (6 + (Nat.sqrt N + 1)) + (Nat.sqrt N + 1) := by
        linarith [small_count_le N, squares_count_le N, pronics_count_le N]
    _ = 2 * Nat.sqrt N + 8 := by ring
