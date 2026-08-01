{-# OPTIONS --safe --without-K #-}
module HardwarePlan where

open import Agda.Builtin.Equality using (_≡_; refl)

data Trust : Set where
  unsigned signed : Trust

data MatchState : Set where
  unmatched matched : MatchState

data Repository : Set where
  native hardware raw-git crates : Repository

data Scope : Set where
  system driver firmware : Scope

data CompilerFeature : Set where
  sse2 avx2 neon : CompilerFeature

data Observed : CompilerFeature → Set where
  observed-sse2 : Observed sse2
  observed-avx2 : Observed avx2

data Allowed : CompilerFeature → Set where
  allowed-sse2 : Allowed sse2
  allowed-avx2 : Allowed avx2

data SelectedFeature : CompilerFeature → Set where
  bounded-feature : {feature : CompilerFeature} →
                    Observed feature → Allowed feature → SelectedFeature feature

record Profile : Set where
  constructor profile
  field
    trust : Trust
    match-state : MatchState

data Eligible : Profile → Set where
  hard-match : Eligible (profile signed matched)

data Authority : Scope → Repository → Set where
  native-system : Authority system native
  hardware-driver : Authority driver hardware
  hardware-firmware : Authority firmware hardware

data ⊥ : Set where

unsigned-cannot-plan : Eligible (profile unsigned matched) → ⊥
unsigned-cannot-plan ()

unmatched-cannot-plan : Eligible (profile signed unmatched) → ⊥
unmatched-cannot-plan ()

driver-cannot-use-git : Authority driver raw-git → ⊥
driver-cannot-use-git ()

driver-cannot-use-crates : Authority driver crates → ⊥
driver-cannot-use-crates ()

unobserved-feature-cannot-cross : SelectedFeature neon → ⊥
unobserved-feature-cannot-cross (bounded-feature () allowed)

signed-match-unique : (proof : Eligible (profile signed matched)) →
                      proof ≡ hard-match
signed-match-unique hard-match = refl
