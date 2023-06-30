// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    error::{DagError, DagResult},
    serde::NarwhalBitmap,
    CertificateDigestProto,
};
use bytes::Bytes;
use config::{AuthorityIdentifier, Committee, Epoch, Stake, WorkerCache, WorkerId, WorkerInfo};
use crypto::{
    to_intent_message, AggregateSignature, Digest, Hash, NarwhalAuthorityAggregateSignature,
    NarwhalAuthoritySignature, NetworkPublicKey, PrivateKey, PublicKey, Signature,
    SignatureService,
};
use dag::node_dag::Affiliated;
use derive_builder::Builder;
use enum_dispatch::enum_dispatch;
use indexmap::IndexMap;
use once_cell::sync::OnceCell;
use proptest_derive::Arbitrary;
use rand::{rngs::StdRng, thread_rng, SeedableRng};
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use snarkvm_console::prelude::ToBytes;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime},
};

use tracing::warn;

/// The round number.
pub type Round = u64;

/// The epoch UNIX timestamp in milliseconds
pub type TimestampMs = u64;

pub trait Timestamp {
    // Returns the time elapsed between the timestamp
    // and "now". The result is a Duration.
    fn elapsed(&self) -> Duration;
}

impl Timestamp for TimestampMs {
    fn elapsed(&self) -> Duration {
        let diff = now().saturating_sub(*self);
        Duration::from_millis(diff)
    }
}
// Returns the current time expressed as UNIX
// timestamp in milliseconds
pub fn now() -> TimestampMs {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_millis() as TimestampMs,
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

// Additional metadata information for an entity.
//
// The structure as a whole is not signed. As a result this data
// should not be treated as trustworthy data and should be used
// for NON CRITICAL purposes only. For example should not be used
// for any processes that are part of our protocol that can affect
// safety or liveness.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Arbitrary)]
pub struct Metadata {
    // timestamp of when the entity created. This is generated
    // by the node which creates the entity.
    pub created_at: TimestampMs,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata { created_at: now() }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Arbitrary)]
#[enum_dispatch(BatchAPI)]
pub enum Batch {
    V1(BatchV1),
}

// TODO: Revisit if we should not impl Default for batch
impl Default for Batch {
    fn default() -> Self {
        Self::V1(BatchV1::default())
    }
}

impl Batch {
    pub fn new(transactions: Vec<Transaction>) -> Self {
        Self::V1(BatchV1::new(transactions))
    }

    pub fn size(&self) -> usize {
        match self {
            Batch::V1(data) => data.size(),
        }
    }
}

impl Hash for Batch {
    type TypedDigest = BatchDigest;

    fn digest(&self) -> BatchDigest {
        match self {
            Batch::V1(data) => data.digest(),
        }
    }
}

#[enum_dispatch]
pub trait BatchAPI {
    fn transactions(&self) -> &Vec<Transaction>;
    fn transactions_mut(&mut self) -> &mut Vec<Transaction>;
    fn metadata(&self) -> &Metadata;
    fn metadata_mut(&mut self) -> &mut Metadata;
}

pub type Transaction = Vec<u8>;
#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq, Eq, Arbitrary)]
pub struct BatchV1 {
    pub transactions: Vec<Transaction>,
    pub metadata: Metadata,
}

impl BatchAPI for BatchV1 {
    fn transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }

    fn transactions_mut(&mut self) -> &mut Vec<Transaction> {
        &mut self.transactions
    }

    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }
}

impl BatchV1 {
    pub fn new(transactions: Vec<Transaction>) -> Self {
        Self {
            transactions,
            metadata: Metadata::default(),
        }
    }

    pub fn size(&self) -> usize {
        self.transactions.iter().map(|t| t.len()).sum()
    }
}

#[derive(
    Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Arbitrary,
)]
pub struct BatchDigest(pub Digest);

impl fmt::Debug for BatchDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(self.0))
    }
}

impl fmt::Display for BatchDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode(self.0).get(0..16).ok_or(fmt::Error)?
        )
    }
}

impl From<BatchDigest> for Digest {
    fn from(digest: BatchDigest) -> Self {
        digest.0
    }
}

impl BatchDigest {
    pub fn new(val: Digest) -> BatchDigest {
        BatchDigest(val)
    }
}

impl Hash for BatchV1 {
    type TypedDigest = BatchDigest;

    fn digest(&self) -> Self::TypedDigest {
        BatchDigest::new(crypto::DefaultHashFunction::digest_iterator(
            self.transactions.iter(),
        ))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[enum_dispatch(HeaderAPI)]
pub enum Header {
    V1(HeaderV1),
}

impl Header {
    // TODO: Add version number and match on that.
    pub async fn new(
        author: AuthorityIdentifier,
        round: Round,
        epoch: Epoch,
        payload: IndexMap<BatchDigest, (WorkerId, TimestampMs)>,
        parents: BTreeSet<CertificateDigest>,
    ) -> Self {
        Header::V1(HeaderV1 {
            author,
            round,
            epoch,
            payload,
            parents,
            digest: Default::default(),
            created_at: now(),
        })
    }

    pub fn digest(&self) -> HeaderDigest {
        match self {
            Header::V1(data) => data.digest(),
        }
    }

    pub fn validate(&self, committee: &Committee, worker_cache: &WorkerCache) -> DagResult<()> {
        match self {
            Header::V1(data) => data.validate(committee, worker_cache),
        }
    }
}

impl Hash for Header {
    type TypedDigest = HeaderDigest;

    fn digest(&self) -> HeaderDigest {
        match self {
            Header::V1(data) => data.digest(),
        }
    }
}

#[enum_dispatch]
pub trait HeaderAPI {
    fn author(&self) -> AuthorityIdentifier;
    fn round(&self) -> Round;
    fn epoch(&self) -> Epoch;
    fn created_at(&self) -> &TimestampMs;
    fn payload(&self) -> &IndexMap<BatchDigest, (WorkerId, TimestampMs)>;
    fn parents(&self) -> &BTreeSet<CertificateDigest>;

    // Used for testing.
    fn update_payload(&mut self, new_payload: IndexMap<BatchDigest, (WorkerId, TimestampMs)>);
    fn update_round(&mut self, new_round: Round);
    fn clear_parents(&mut self);
}

#[derive(Builder, Clone, Deserialize, Serialize)]
#[builder(pattern = "owned", build_fn(skip))]
pub struct HeaderV1 {
    // Primary that created the header. Must be the same primary that broadcasted the header.
    // Validation is at: https://github.com/MystenLabs/sui/blob/f0b80d9eeef44edd9fbe606cee16717622b68651/narwhal/primary/src/primary.rs#L713-L719
    pub author: AuthorityIdentifier,
    pub round: Round,
    pub epoch: Epoch,
    pub created_at: TimestampMs,
    #[serde(with = "indexmap::map::serde_seq")]
    pub payload: IndexMap<BatchDigest, (WorkerId, TimestampMs)>,
    pub parents: BTreeSet<CertificateDigest>,
    #[serde(skip)]
    digest: OnceCell<HeaderDigest>,
    // TODO: Add signature
}

impl HeaderV1 {
    /// Create a signed header from an unsigned one.
    /// Computes the `digest` and `signature` in the process.
    fn from_unsigned(unsigned_header: UnsignedHeaderV1, signer: &PrivateKey) -> Self {
        let digest = Hash::digest(&unsigned_header);
        unsigned_header.digest.set(digest).unwrap();
        let _signature = signer
            .sign_bytes(digest.0.as_ref(), &mut thread_rng())
            .expect("Signing failed");
        Self {
            author: unsigned_header.author,
            round: unsigned_header.round,
            epoch: unsigned_header.epoch,
            created_at: unsigned_header.created_at,
            payload: unsigned_header.payload,
            parents: unsigned_header.parents,
            digest: unsigned_header.digest,
            // TODO: Add signature
        }
    }

    fn for_author(author: AuthorityIdentifier) -> Self {
        let h = UnsignedHeaderV1 {
            author,
            round: 0,
            epoch: 0,
            created_at: now(),
            payload: IndexMap::new(),
            parents: BTreeSet::new(),
            digest: OnceCell::default(),
        };
        let digest = Hash::digest(&h);
        h.digest.set(digest).unwrap();
        let signer = PrivateKey::default();
        let mut rng = StdRng::seed_from_u64(42);
        let _signature = signer
            .sign_bytes(Digest::from(digest).as_ref(), &mut rng)
            .unwrap();
        HeaderV1 {
            author: h.author,
            round: h.round,
            epoch: h.epoch,
            created_at: h.created_at,
            payload: h.payload,
            parents: h.parents,
            digest: h.digest,
            // TODO: Add signature
        }
    }
}

struct UnsignedHeaderV1 {
    author: AuthorityIdentifier,
    round: Round,
    epoch: Epoch,
    created_at: TimestampMs,
    payload: IndexMap<BatchDigest, (WorkerId, TimestampMs)>,
    parents: BTreeSet<CertificateDigest>,
    digest: OnceCell<HeaderDigest>,
}

impl Hash for UnsignedHeaderV1 {
    type TypedDigest = HeaderDigest;

    fn digest(&self) -> HeaderDigest {
        let mut hasher = crypto::DefaultHashFunction::new();
        // SAFETY: this conversion can't fail, the result is just a side-effect of the `ToBytes`
        // trait design in snarkVM.
        hasher.update(&self.author.0.to_bytes_le().unwrap());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.created_at.to_le_bytes());
        for (x, (y, z)) in self.payload.iter() {
            hasher.update(Digest::from(*x));
            hasher.update(y.to_le_bytes());
            hasher.update(z.to_le_bytes());
        }
        for x in self.parents.iter() {
            hasher.update(Digest::from(*x))
        }
        HeaderDigest(hasher.finalize())
    }
}

impl HeaderAPI for HeaderV1 {
    fn author(&self) -> AuthorityIdentifier {
        self.author
    }
    fn round(&self) -> Round {
        self.round
    }
    fn epoch(&self) -> Epoch {
        self.epoch
    }
    fn created_at(&self) -> &TimestampMs {
        &self.created_at
    }
    fn payload(&self) -> &IndexMap<BatchDigest, (WorkerId, TimestampMs)> {
        &self.payload
    }
    fn parents(&self) -> &BTreeSet<CertificateDigest> {
        &self.parents
    }

    // Used for testing.
    fn update_payload(&mut self, new_payload: IndexMap<BatchDigest, (WorkerId, TimestampMs)>) {
        self.payload = new_payload;
    }
    fn update_round(&mut self, new_round: Round) {
        self.round = new_round;
    }
    fn clear_parents(&mut self) {
        self.parents.clear();
    }
}

impl HeaderV1Builder {
    pub fn build(self) -> HeaderV1 {
        let h = HeaderV1 {
            author: self.author.unwrap(),
            round: self.round.unwrap(),
            epoch: self.epoch.unwrap(),
            created_at: self.created_at.unwrap_or(now()),
            payload: self.payload.unwrap(),
            parents: self.parents.unwrap(),
            digest: OnceCell::default(),
            // TODO: Add signature
            // signature: self.signature.expect("The header isn't signed"),
        };
        h.digest.set(Hash::digest(&h)).unwrap();
        h
    }

    /// This should be the last method called on the builder before `build`.
    pub fn signed(mut self, _signer: &PrivateKey) -> Self {
        let unsigned_header = UnsignedHeaderV1 {
            author: self.author.unwrap_or_default(),
            round: self.round.unwrap_or_default(),
            epoch: self.epoch.unwrap_or_default(),
            created_at: self.created_at.unwrap_or(now()),
            payload: self.payload.clone().unwrap_or_default(),
            parents: self.parents.clone().unwrap_or_default(),
            digest: self.digest.unwrap_or_default(),
        };
        let digest = Hash::digest(&unsigned_header);
        unsigned_header.digest.set(digest).unwrap();
        self.digest = Some(digest.into());
        // let signature = signer.sign_bytes(digest.0.as_ref(), &mut thread_rng()).expect("Signing failed");
        // TODO: Add signature
        // self.signature = Some(signature);
        self
    }

    // helper method to set directly values to the payload
    pub fn with_payload_batch(
        mut self,
        batch: Batch,
        worker_id: WorkerId,
        created_at: TimestampMs,
    ) -> Self {
        if self.payload.is_none() {
            self.payload = Some(Default::default());
        }
        let payload = self.payload.as_mut().unwrap();

        payload.insert(batch.digest(), (worker_id, created_at));

        self
    }
}

impl HeaderV1 {
    pub async fn new(
        author: AuthorityIdentifier,
        round: Round,
        epoch: Epoch,
        payload: IndexMap<BatchDigest, (WorkerId, TimestampMs)>,
        parents: BTreeSet<CertificateDigest>,
        // signer: &PrivateKey,
    ) -> Self {
        let header = UnsignedHeaderV1 {
            author,
            round,
            epoch,
            created_at: now(),
            payload,
            parents,
            digest: OnceCell::default(),
        };
        let digest = Hash::digest(&header);
        header.digest.set(digest).unwrap();
        // let signature = signer.sign_bytes(digest.0.as_ref(), &mut thread_rng()).expect("Signing failed");
        Self {
            author: header.author,
            round: header.round,
            epoch: header.epoch,
            created_at: header.created_at,
            payload: header.payload,
            parents: header.parents,
            digest: header.digest,
            // TODO: Add signature
        }
    }

    pub fn digest(&self) -> HeaderDigest {
        *self.digest.get_or_init(|| Hash::digest(self))
    }

    pub fn validate(&self, committee: &Committee, worker_cache: &WorkerCache) -> DagResult<()> {
        // Ensure the header is from the correct epoch.
        ensure!(
            self.epoch == committee.epoch(),
            DagError::InvalidEpoch {
                expected: committee.epoch(),
                received: self.epoch
            }
        );

        // Ensure the header digest is well formed.
        ensure!(
            Hash::digest(self) == self.digest(),
            DagError::InvalidHeaderDigest
        );

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake_by_id(self.author);
        ensure!(
            voting_rights > 0,
            DagError::UnknownAuthority(self.author.to_string())
        );

        // Ensure all worker ids are correct.
        for (worker_id, _) in self.payload.values() {
            worker_cache
                .worker(
                    committee.authority(&self.author).unwrap().protocol_key(),
                    worker_id,
                )
                .map_err(|_| DagError::HeaderHasBadWorkerIds(self.digest()))?;
        }

        Ok(())
    }
}

#[derive(
    Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Arbitrary,
)]
pub struct HeaderDigest(Digest);

impl From<HeaderDigest> for Digest {
    fn from(hd: HeaderDigest) -> Self {
        hd.0
    }
}

impl fmt::Debug for HeaderDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(self.0))
    }
}

impl fmt::Display for HeaderDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode(self.0).get(0..16).ok_or(fmt::Error)?
        )
    }
}

impl Hash for HeaderV1 {
    type TypedDigest = HeaderDigest;

    fn digest(&self) -> HeaderDigest {
        let mut hasher = crypto::DefaultHashFunction::new();
        hasher.update(bcs::to_bytes(&self).expect("Serialization should not fail"));
        HeaderDigest(hasher.finalize())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::V1(data) => {
                write!(
                    f,
                    "{}: B{}({}, E{}, {}B)",
                    data.digest.get().cloned().unwrap_or_default(),
                    data.round,
                    data.author,
                    data.epoch,
                    data.payload.keys().map(|_| Digest::size()).sum::<usize>(),
                )
            }
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::V1(data) => {
                write!(f, "B{}({})", data.round, data.author)
            }
        }
    }
}

impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::V1(data) => data.digest() == other.digest(),
        }
    }
}

/// A Vote on a Header is a claim by the voting authority that all payloads and the full history
/// of Certificates included in the Header are available.
#[derive(Clone, Serialize, Deserialize)]
#[enum_dispatch(VoteAPI)]
pub enum Vote {
    V1(VoteV1),
}

impl Vote {
    // TODO: Add version number and match on that
    pub async fn new(
        header: &Header,
        author: &AuthorityIdentifier,
        signature_service: &SignatureService,
    ) -> Self {
        Vote::V1(VoteV1::new(header, author, signature_service).await)
    }

    pub fn new_with_signer(
        header: &Header,
        author: &AuthorityIdentifier,
        signer: &PrivateKey,
    ) -> Self {
        Vote::V1(VoteV1::new_with_signer(header, author, signer))
    }
}

impl Hash for Vote {
    type TypedDigest = VoteDigest;

    fn digest(&self) -> VoteDigest {
        match self {
            Vote::V1(data) => data.digest(),
        }
    }
}

#[enum_dispatch]
pub trait VoteAPI {
    fn header_digest(&self) -> HeaderDigest;
    fn round(&self) -> Round;
    fn epoch(&self) -> Epoch;
    fn origin(&self) -> AuthorityIdentifier;
    fn author(&self) -> AuthorityIdentifier;
    fn signature(&self) -> &Signature;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VoteV1 {
    // HeaderDigest, round, epoch and origin for the header being voted on.
    pub header_digest: HeaderDigest,
    pub round: Round,
    pub epoch: Epoch,
    pub origin: AuthorityIdentifier,
    // Author of this vote.
    pub author: AuthorityIdentifier,
    pub signature: Signature,
}

pub struct UnsignedVoteV1 {
    pub digest: HeaderDigest,
    pub round: Round,
    pub epoch: Epoch,
    pub origin: AuthorityIdentifier,
    pub author: AuthorityIdentifier,
}

impl VoteAPI for VoteV1 {
    fn header_digest(&self) -> HeaderDigest {
        self.header_digest
    }
    fn round(&self) -> Round {
        self.round
    }
    fn epoch(&self) -> Epoch {
        self.epoch
    }
    fn origin(&self) -> AuthorityIdentifier {
        self.origin
    }
    fn author(&self) -> AuthorityIdentifier {
        self.author
    }
    fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl VoteV1 {
    pub async fn new(
        header: &Header,
        author: &AuthorityIdentifier,
        signature_service: &SignatureService,
    ) -> Self {
        let unsigned_vote = UnsignedVoteV1 {
            digest: header.digest(),
            round: header.round(),
            epoch: header.epoch(),
            origin: header.author(),
            author: *author,
        };
        let signature = signature_service
            .request_signature(unsigned_vote.digest.into())
            .await;
        Self {
            header_digest: unsigned_vote.digest,
            round: unsigned_vote.round,
            epoch: unsigned_vote.epoch,
            origin: unsigned_vote.origin,
            author: unsigned_vote.author,
            signature,
        }
    }

    pub fn new_with_signer(
        header: &Header,
        author: &AuthorityIdentifier,
        signer: &PrivateKey,
    ) -> Self {
        let unsigned_vote = UnsignedVoteV1 {
            digest: header.digest(),
            round: header.round(),
            epoch: header.epoch(),
            origin: header.author(),
            author: *author,
        };
        let vote_digest: Digest = unsigned_vote.digest.into();
        let signature = Signature::new_secure(&to_intent_message(vote_digest), signer);

        Self {
            header_digest: unsigned_vote.digest,
            round: unsigned_vote.round,
            epoch: unsigned_vote.epoch,
            origin: unsigned_vote.origin,
            author: unsigned_vote.author,
            signature,
        }
    }
}
#[derive(
    Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Arbitrary,
)]
pub struct VoteDigest(Digest);

impl From<VoteDigest> for Digest {
    fn from(hd: VoteDigest) -> Self {
        hd.0
    }
}

impl fmt::Debug for VoteDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(self.0))
    }
}

impl fmt::Display for VoteDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode(self.0).get(0..16).ok_or(fmt::Error)?
        )
    }
}

impl Hash for VoteV1 {
    type TypedDigest = VoteDigest;

    fn digest(&self) -> VoteDigest {
        VoteDigest(self.header_digest().0)
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {}, E{})",
            self.digest(),
            self.round(),
            self.author(),
            self.origin(),
            self.epoch()
        )
    }
}

impl PartialEq for Vote {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[enum_dispatch(CertificateAPI)]
pub enum Certificate {
    V1(CertificateV1),
}

impl Certificate {
    // TODO: Add version number and match on that
    pub fn genesis(committee: &Committee, signer: &PrivateKey) -> Vec<Self> {
        CertificateV1::genesis(committee, signer)
            .into_iter()
            .map(Self::V1)
            .collect()
    }

    pub fn new_unverified(
        committee: &Committee,
        header: Header,
        votes: Vec<(AuthorityIdentifier, Signature)>,
    ) -> DagResult<Certificate> {
        CertificateV1::new_unverified(committee, header, votes)
    }

    pub fn new_unsigned(
        committee: &Committee,
        header: Header,
        votes: Vec<(AuthorityIdentifier, Signature)>,
    ) -> DagResult<Certificate> {
        CertificateV1::new_unsigned(committee, header, votes)
    }

    pub fn new_test_empty(author: AuthorityIdentifier) -> Self {
        CertificateV1::new_test_empty(author)
    }

    /// This function requires that certificate was verified against given committee
    pub fn signed_authorities(&self, committee: &Committee) -> Vec<PublicKey> {
        match self {
            Certificate::V1(certificate) => certificate.signed_authorities(committee),
        }
    }

    pub fn signed_by(&self, committee: &Committee) -> (Stake, Vec<PublicKey>) {
        match self {
            Certificate::V1(certificate) => certificate.signed_by(committee),
        }
    }

    pub fn verify(
        &self,
        committee: &Committee,
        worker_cache: &WorkerCache,
        genesis_certs: &[Certificate],
    ) -> DagResult<()> {
        match self {
            Certificate::V1(certificate) => {
                certificate.verify(committee, worker_cache, genesis_certs)
            }
        }
    }

    pub fn round(&self) -> Round {
        match self {
            Certificate::V1(certificate) => certificate.round(),
        }
    }

    pub fn epoch(&self) -> Epoch {
        match self {
            Certificate::V1(certificate) => certificate.epoch(),
        }
    }

    pub fn origin(&self) -> AuthorityIdentifier {
        match self {
            Certificate::V1(certificate) => certificate.origin(),
        }
    }
}

impl Hash for Certificate {
    type TypedDigest = CertificateDigest;

    fn digest(&self) -> CertificateDigest {
        match self {
            Certificate::V1(data) => data.digest(),
        }
    }
}

#[enum_dispatch]
pub trait CertificateAPI {
    fn header(&self) -> &Header;
    fn aggregated_signature(&self) -> &AggregateSignature;
    fn signed_authorities(&self) -> &roaring::RoaringBitmap;
    fn metadata(&self) -> &Metadata;

    // Used for testing.
    fn update_header(&mut self, header: Header);
    fn header_mut(&mut self) -> &mut Header;
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct CertificateV1 {
    pub header: Header,
    pub aggregated_signature: AggregateSignature,
    #[serde_as(as = "NarwhalBitmap")]
    signed_authorities: roaring::RoaringBitmap,
    pub metadata: Metadata,
}

impl CertificateAPI for CertificateV1 {
    fn header(&self) -> &Header {
        &self.header
    }

    fn aggregated_signature(&self) -> &AggregateSignature {
        &self.aggregated_signature
    }

    fn signed_authorities(&self) -> &roaring::RoaringBitmap {
        &self.signed_authorities
    }

    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    // Used for testing.
    fn update_header(&mut self, header: Header) {
        self.header = header;
    }

    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

impl CertificateV1 {
    pub fn genesis(committee: &Committee, signer: &PrivateKey) -> Vec<Self> {
        committee
            .authorities()
            .map(|authority| {
                let unsigned_header = UnsignedHeaderV1 {
                    author: authority.id(),
                    round: Default::default(),
                    epoch: committee.epoch(),
                    created_at: Default::default(),
                    payload: Default::default(),
                    parents: Default::default(),
                    digest: Default::default(),
                };
                Self {
                    header: Header::V1(HeaderV1::from_unsigned(unsigned_header, signer)),
                    aggregated_signature: Default::default(),
                    signed_authorities: Default::default(),
                    metadata: Default::default(),
                }
            })
            .collect()
    }

    pub fn new_unverified(
        committee: &Committee,
        header: Header,
        votes: Vec<(AuthorityIdentifier, Signature)>,
    ) -> DagResult<Certificate> {
        Self::new_unsafe(committee, header, votes, true)
    }

    pub fn new_unsigned(
        committee: &Committee,
        header: Header,
        votes: Vec<(AuthorityIdentifier, Signature)>,
    ) -> DagResult<Certificate> {
        Self::new_unsafe(committee, header, votes, false)
    }

    pub fn new_test_empty(author: AuthorityIdentifier) -> Certificate {
        let header = Header::V1(HeaderV1::for_author(author));
        Certificate::V1(CertificateV1 {
            header,
            aggregated_signature: Default::default(),
            signed_authorities: Default::default(),
            metadata: Default::default(),
        })
    }

    fn new_unsafe(
        committee: &Committee,
        header: Header,
        votes: Vec<(AuthorityIdentifier, Signature)>,
        check_stake: bool,
    ) -> DagResult<Certificate> {
        let mut votes = votes;
        votes.sort_by_key(|(pk, _)| *pk);
        let mut votes: VecDeque<_> = votes.into_iter().collect();

        let mut weight = 0;
        let mut sigs = Vec::new();

        let filtered_votes = committee
            .authorities()
            .enumerate()
            .filter(|(_, authority)| {
                if !votes.is_empty() && authority.id() == votes.front().unwrap().0 {
                    sigs.push(votes.pop_front().unwrap());
                    weight += authority.stake();
                    // If there are repeats, also remove them
                    while !votes.is_empty() && votes.front().unwrap() == sigs.last().unwrap() {
                        votes.pop_front().unwrap();
                    }
                    return true;
                }
                false
            })
            .map(|(index, _)| index as u32);

        let signed_authorities= roaring::RoaringBitmap::from_sorted_iter(filtered_votes)
            .map_err(|_| DagError::InvalidBitmap("Failed to convert votes into a bitmap of authority keys. Something is likely very wrong...".to_string()))?;

        // Ensure that all authorities in the set of votes are known
        ensure!(
            votes.is_empty(),
            DagError::UnknownAuthority(votes.front().unwrap().0.to_string())
        );

        // Ensure that the authorities have enough weight
        ensure!(
            !check_stake || weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        let aggregated_signature = if sigs.is_empty() {
            AggregateSignature::default()
        } else {
            AggregateSignature(sigs.into_iter().map(|(_author, sig)| sig).collect())
        };

        Ok(Certificate::V1(CertificateV1 {
            header,
            aggregated_signature,
            signed_authorities,
            metadata: Metadata::default(),
        }))
    }

    /// This function requires that certificate was verified against given committee
    pub fn signed_authorities(&self, committee: &Committee) -> Vec<PublicKey> {
        assert_eq!(committee.epoch(), self.epoch());
        let (_stake, pks) = self.signed_by(committee);
        pks
    }

    pub fn signed_by(&self, committee: &Committee) -> (Stake, Vec<PublicKey>) {
        // Ensure the certificate has a quorum.
        let mut weight = 0;

        let auth_indexes = self.signed_authorities.iter().collect::<Vec<_>>();
        let mut auth_iter = 0;
        let pks = committee
            .authorities()
            .enumerate()
            .filter(|(i, authority)| match auth_indexes.get(auth_iter) {
                Some(index) if *index == *i as u32 => {
                    weight += authority.stake();
                    auth_iter += 1;
                    true
                }
                _ => false,
            })
            .map(|(_, authority)| authority.protocol_key().clone())
            .collect();
        (weight, pks)
    }

    /// Verifies the validity of the certificate.
    /// TODO: Output a different type, similar to Sui VerifiedCertificate.
    pub fn verify(
        &self,
        committee: &Committee,
        worker_cache: &WorkerCache,
        genesis_certs: &[Certificate],
    ) -> DagResult<()> {
        // Ensure the header is from the correct epoch.
        ensure!(
            self.epoch() == committee.epoch(),
            DagError::InvalidEpoch {
                expected: committee.epoch(),
                received: self.epoch()
            }
        );

        // Genesis certificates are always valid.
        if self.round() == 0 && genesis_certs.contains(&Certificate::V1(self.clone())) {
            return Ok(());
        }

        // Save signature verifications when the header is invalid.
        self.header.validate(committee, worker_cache)?;

        let (weight, pks) = self.signed_by(committee);

        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        // Verify the signatures
        let certificate_digest: Digest = Digest::from(self.digest());
        self.aggregated_signature
            .verify_secure(&to_intent_message(certificate_digest), &pks[..])
            .map_err(|_| DagError::InvalidSignature)?;

        Ok(())
    }

    pub fn round(&self) -> Round {
        self.header.round()
    }

    pub fn epoch(&self) -> Epoch {
        self.header.epoch()
    }

    pub fn origin(&self) -> AuthorityIdentifier {
        self.header.author()
    }
}

#[derive(
    Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Arbitrary,
)]

pub struct CertificateDigest(Digest);

impl CertificateDigest {
    pub fn new(digest: Digest) -> CertificateDigest {
        CertificateDigest(digest)
    }
}

impl AsRef<[u8]> for CertificateDigest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<CertificateDigest> for Digest {
    fn from(hd: CertificateDigest) -> Self {
        hd.0
    }
}
impl From<CertificateDigest> for CertificateDigestProto {
    fn from(hd: CertificateDigest) -> Self {
        CertificateDigestProto {
            digest: Bytes::from(hd.0.to_vec()),
        }
    }
}

impl fmt::Debug for CertificateDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(self.0))
    }
}

impl fmt::Display for CertificateDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode(self.0).get(0..16).ok_or(fmt::Error)?
        )
    }
}

impl Hash for CertificateV1 {
    type TypedDigest = CertificateDigest;

    fn digest(&self) -> CertificateDigest {
        CertificateDigest(self.header.digest().0)
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Certificate::V1(data) => write!(
                f,
                "{}: C{}({}, {}, E{})",
                data.digest(),
                data.round(),
                data.origin(),
                data.header.digest(),
                data.epoch()
            ),
        }
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Certificate::V1(data), Certificate::V1(other_data)) => data.eq(other_data),
        }
    }
}

impl PartialEq for CertificateV1 {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.header().digest() == other.header().digest();
        ret &= self.round() == other.round();
        ret &= self.epoch() == other.epoch();
        ret &= self.origin() == other.origin();
        ret
    }
}

impl Affiliated for Certificate {
    fn parents(&self) -> Vec<<Self as Hash>::TypedDigest> {
        match self {
            Certificate::V1(data) => data.header().parents().iter().cloned().collect(),
        }
    }

    // This makes the genesis certificate and empty blocks compressible,
    // so that they will never be reported by a DAG walk
    // (`read_causal`, `node_read_causal`).
    fn compressible(&self) -> bool {
        match self {
            Certificate::V1(data) => data.header().payload().is_empty(),
        }
    }
}

/// Request for broadcasting certificates to peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendCertificateRequest {
    pub certificate: Certificate,
}

/// Response from peers after receiving a certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendCertificateResponse {
    pub accepted: bool,
}

/// Used by the primary to request a vote from other primaries on newly produced headers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestVoteRequest {
    pub header: Header,

    // Optional parent certificates provided by the requester, in case this primary doesn't yet
    // have them and requires them in order to offer a vote.
    pub parents: Vec<Certificate>,
}

/// Used by the primary to reply to RequestVoteRequest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    pub vote: Option<Vote>,

    // Indicates digests of missing certificates without which a vote cannot be provided.
    pub missing: Vec<CertificateDigest>,
}

/// Used by the primary to get specific certificates from other primaries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetCertificatesRequest {
    pub digests: Vec<CertificateDigest>,
}

/// Used by the primary to reply to GetCertificatesRequest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetCertificatesResponse {
    pub certificates: Vec<Certificate>,
}

/// Used by the primary to fetch certificates from other primaries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchCertificatesRequest {
    /// The exclusive lower bound is a round number where each primary should return certificates above that.
    /// This corresponds to the GC round at the requestor.
    pub exclusive_lower_bound: Round,
    /// This contains per authority serialized RoaringBitmap for the round diffs between
    /// - rounds of certificates to be skipped from the response and
    /// - the GC round.
    /// These rounds are skipped because the requestor already has them.
    pub skip_rounds: Vec<(AuthorityIdentifier, Vec<u8>)>,
    /// Maximum number of certificates that should be returned.
    pub max_items: usize,
}

impl FetchCertificatesRequest {
    #[allow(clippy::mutable_key_type)]
    pub fn get_bounds(&self) -> (Round, BTreeMap<AuthorityIdentifier, BTreeSet<Round>>) {
        let skip_rounds: BTreeMap<AuthorityIdentifier, BTreeSet<Round>> = self
            .skip_rounds
            .iter()
            .filter_map(|(k, serialized)| {
                match RoaringBitmap::deserialize_from(&mut &serialized[..]) {
                    Ok(bitmap) => {
                        let rounds: BTreeSet<Round> = bitmap
                            .into_iter()
                            .map(|r| self.exclusive_lower_bound + r as Round)
                            .collect();
                        Some((*k, rounds))
                    }
                    Err(e) => {
                        warn!("Failed to deserialize RoaringBitmap {e}");
                        None
                    }
                }
            })
            .collect();
        (self.exclusive_lower_bound, skip_rounds)
    }

    #[allow(clippy::mutable_key_type)]
    pub fn set_bounds(
        mut self,
        gc_round: Round,
        skip_rounds: BTreeMap<AuthorityIdentifier, BTreeSet<Round>>,
    ) -> Self {
        self.exclusive_lower_bound = gc_round;
        self.skip_rounds = skip_rounds
            .into_iter()
            .map(|(k, rounds)| {
                let mut serialized = Vec::new();
                rounds
                    .into_iter()
                    .map(|v| u32::try_from(v - gc_round).unwrap())
                    .collect::<RoaringBitmap>()
                    .serialize_into(&mut serialized)
                    .unwrap();
                (k, serialized)
            })
            .collect();
        self
    }

    pub fn set_max_items(mut self, max_items: usize) -> Self {
        self.max_items = max_items;
        self
    }
}

/// Used by the primary to reply to FetchCertificatesRequest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FetchCertificatesResponse {
    /// Certificates sorted from lower to higher rounds.
    pub certificates: Vec<Certificate>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PayloadAvailabilityRequest {
    pub certificate_digests: Vec<CertificateDigest>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PayloadAvailabilityResponse {
    pub payload_availability: Vec<(CertificateDigest, bool)>,
}

impl PayloadAvailabilityResponse {
    pub fn available_certificates(&self) -> Vec<CertificateDigest> {
        self.payload_availability
            .iter()
            .filter_map(|(digest, available)| available.then_some(*digest))
            .collect()
    }
}

/// Used by the primary to request that the worker sync the target missing batches.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerSynchronizeMessage {
    pub digests: Vec<BatchDigest>,
    pub target: AuthorityIdentifier,
    // Used to indicate to the worker that it does not need to fully validate
    // the batch it receives because it is part of a certificate. Only digest
    // verification is required.
    pub is_certified: bool,
}

/// Used by the primary to request that the worker fetch the missing batches and reply
/// with all of the content.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchBatchesRequest {
    pub digests: HashSet<BatchDigest>,
    pub known_workers: HashSet<NetworkPublicKey>,
}

/// All batches requested by the primary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchBatchesResponse {
    pub batches: HashMap<BatchDigest, Batch>,
}

/// Used by the primary to request that the worker delete the specified batches.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerDeleteBatchesMessage {
    pub digests: Vec<BatchDigest>,
}

#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct BatchMessage {
    // TODO: revisit including the digest here [see #188]
    pub digest: BatchDigest,
    pub batch: Batch,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BlockErrorKind {
    BlockNotFound,
    BatchTimeout,
    BatchError,
}

pub type BlockResult<T> = Result<T, BlockError>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BlockError {
    pub digest: CertificateDigest,
    pub error: BlockErrorKind,
}

impl<T> From<BlockError> for BlockResult<T> {
    fn from(error: BlockError) -> Self {
        Err(error)
    }
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "block digest: {}, error type: {}",
            self.digest, self.error
        )
    }
}

impl fmt::Display for BlockErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Used by worker to inform primary it sealed a new batch.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct WorkerOurBatchMessage {
    pub digest: BatchDigest,
    pub worker_id: WorkerId,
    pub metadata: Metadata,
}

/// Used by worker to inform primary it received a batch from another authority.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct WorkerOthersBatchMessage {
    pub digest: BatchDigest,
    pub worker_id: WorkerId,
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct WorkerInfoResponse {
    /// Map of workers' id and their network addresses.
    pub workers: BTreeMap<WorkerId, WorkerInfo>,
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
#[enum_dispatch(VoteInfoAPI)]
pub enum VoteInfo {
    V1(VoteInfoV1),
}

#[enum_dispatch]
pub trait VoteInfoAPI {
    fn epoch(&self) -> Epoch;
    fn round(&self) -> Round;
    fn vote_digest(&self) -> VoteDigest;
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct VoteInfoV1 {
    /// The latest Epoch for which a vote was sent to given authority
    pub epoch: Epoch,
    /// The latest round for which a vote was sent to given authority
    pub round: Round,
    /// The hash of the vote used to ensure equality
    pub vote_digest: VoteDigest,
}

impl VoteInfoAPI for VoteInfoV1 {
    fn epoch(&self) -> Epoch {
        self.epoch
    }

    fn round(&self) -> Round {
        self.round
    }

    fn vote_digest(&self) -> VoteDigest {
        self.vote_digest
    }
}

impl From<&VoteV1> for VoteInfoV1 {
    fn from(vote: &VoteV1) -> Self {
        VoteInfoV1 {
            epoch: vote.epoch(),
            round: vote.round(),
            vote_digest: vote.digest(),
        }
    }
}

impl From<&Vote> for VoteInfo {
    fn from(vote: &Vote) -> Self {
        match vote {
            Vote::V1(vote) => VoteInfo::V1(VoteInfoV1::from(vote)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Batch, BatchAPI, BatchV1, Metadata, Timestamp};
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_elapsed() {
        let batch = Batch::new(vec![]);
        assert!(batch.metadata().created_at > 0);

        sleep(Duration::from_secs(2)).await;

        assert!(batch.metadata().created_at.elapsed().as_secs_f64() >= 2.0);
    }

    #[test]
    fn test_elapsed_when_newer_than_now() {
        let batch = Batch::V1(BatchV1 {
            transactions: vec![],
            metadata: Metadata {
                created_at: 2999309726980, // something in the future - Fri Jan 16 2065 05:35:26
            },
        });

        assert_eq!(batch.metadata().created_at.elapsed().as_secs_f64(), 0.0);
    }
}
