module HardwarePlan

%default total

public export
data Trust = Unsigned | Signed

public export
data MatchState = Unmatched | Matched

public export
data Repository = Native | Hardware | RawGit | Crates

public export
data Scope = System | Driver | Firmware

public export
record Profile where
  constructor MkProfile
  profileId : String
  priority : Nat
  advisoryRank : Nat
  trust : Trust
  matchState : MatchState

public export
data Eligible : Profile -> Type where
  HardMatch : {profileId : String} -> {priority, advisoryRank : Nat} ->
              Eligible (MkProfile profileId priority advisoryRank Signed Matched)

public export
data Authority : Scope -> Repository -> Type where
  NativeSystem : Authority System Native
  HardwareDriver : Authority Driver Hardware
  HardwareFirmware : Authority Firmware Hardware

public export
data AbiCompatible = Compatible

public export
data CompilerFeature = Sse2 | Avx2 | Neon

public export
data Observed : CompilerFeature -> Type where
  ObservedSse2 : Observed Sse2
  ObservedAvx2 : Observed Avx2

public export
data Allowed : CompilerFeature -> Type where
  AllowedSse2 : Allowed Sse2
  AllowedAvx2 : Allowed Avx2

public export
data SelectedFeature : CompilerFeature -> Type where
  BoundedFeature : Observed feature -> Allowed feature -> SelectedFeature feature

public export
record Plan where
  constructor MkPlan
  profile : Profile
  eligible : Eligible profile
  abi : AbiCompatible

public export
eligible : (profile : Profile) -> Maybe (Eligible profile)
eligible (MkProfile profileId priority advisoryRank Unsigned Unmatched) = Nothing
eligible (MkProfile profileId priority advisoryRank Unsigned Matched) = Nothing
eligible (MkProfile profileId priority advisoryRank Signed Unmatched) = Nothing
eligible (MkProfile profileId priority advisoryRank Signed Matched) = Just HardMatch

public export
driverCannotUseGit : Authority Driver RawGit -> Void
driverCannotUseGit value impossible

public export
driverCannotUseCrates : Authority Driver Crates -> Void
driverCannotUseCrates value impossible

public export
unobservedFeatureCannotCross : SelectedFeature Neon -> Void
unobservedFeatureCannotCross (BoundedFeature observed allowed) impossible

public export
data Selection = NoProfile | Selected Profile | Ambiguous Nat Nat

isEligible : Profile -> Bool
isEligible profile =
  case eligible profile of
    Nothing => False
    Just _ => True

consider : Selection -> Profile -> Selection
consider NoProfile candidate = Selected candidate
consider (Selected current) candidate =
  if candidate.priority > current.priority then Selected candidate
  else if candidate.priority < current.priority then Selected current
  else if candidate.advisoryRank > current.advisoryRank then Selected candidate
  else if candidate.advisoryRank < current.advisoryRank then Selected current
  else Ambiguous candidate.priority candidate.advisoryRank
consider (Ambiguous priority rank) candidate =
  if candidate.priority > priority then Selected candidate
  else if candidate.priority < priority then Ambiguous priority rank
  else if candidate.advisoryRank > rank then Selected candidate
  else Ambiguous priority rank

public export
select : List Profile -> Selection
select profiles = foldl consider NoProfile (filter isEligible profiles)

public export
unsignedIsNeverSelected :
  select [MkProfile "unsigned" 100 100 Unsigned Matched] = NoProfile
unsignedIsNeverSelected = Refl

public export
unmatchedIsNeverSelected :
  select [MkProfile "unmatched" 100 100 Signed Unmatched] = NoProfile
unmatchedIsNeverSelected = Refl

public export
equalEvidenceIsAmbiguous :
  select [ MkProfile "first" 10 5 Signed Matched
         , MkProfile "second" 10 5 Signed Matched
         ] = Ambiguous 10 5
equalEvidenceIsAmbiguous = Refl
