// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{errors::SubscriberResult, ExecutionState};

use config::{AuthorityIdentifier, Committee, WorkerCache, WorkerId};
use crypto::{Hash, NetworkPublicKey};
use futures::stream::FuturesOrdered;
use futures::StreamExt;
use network::client::NetworkClient;
use network::PrimaryToWorkerClient;
use std::collections::HashMap;
use std::collections::HashSet;
use std::{sync::Arc, time::Duration, vec};
use tokio::{
    sync::mpsc::{channel, Receiver, Sender},
    task::JoinHandle,
};
use tracing::{debug, error, info};
use types::FetchBatchesRequest;
use types::{
    Batch, BatchDigest, Certificate, CertificateAPI, CommittedSubDag, ConditionalBroadcastReceiver,
    ConsensusOutput, HeaderAPI, Timestamp,
};

#[cfg(feature = "metrics")]
use snarkos_metrics::histogram;

/// The `Subscriber` receives certificates sequenced by the consensus and waits until the
/// downloaded all the transactions references by the certificates; it then
/// forward the certificates to the Executor.
pub struct Subscriber {
    /// Receiver for shutdown
    rx_shutdown: ConditionalBroadcastReceiver,
    /// A channel to receive sequenced consensus messages.
    rx_sequence: Receiver<CommittedSubDag>,
    /// Inner state.
    inner: Arc<Inner>,
}

struct Inner {
    authority_id: AuthorityIdentifier,
    worker_cache: WorkerCache,
    committee: Committee,
    client: NetworkClient,
}

pub fn spawn_subscriber<State: ExecutionState + Send + Sync + 'static>(
    authority_id: AuthorityIdentifier,
    worker_cache: WorkerCache,
    committee: Committee,
    client: NetworkClient,
    mut shutdown_receivers: Vec<ConditionalBroadcastReceiver>,
    rx_sequence: Receiver<CommittedSubDag>,
    restored_consensus_output: Vec<CommittedSubDag>,
    state: State,
) -> Vec<JoinHandle<()>> {
    // This is ugly but has to be done this way for now
    // Currently network incorporate both server and client side of RPC interface
    // To construct server side we need to set up routes first, which requires starting Primary
    // Some cleanup is needed

    let (tx_notifier, rx_notifier) = channel(primary::CHANNEL_CAPACITY);

    let rx_shutdown_notify = shutdown_receivers
        .pop()
        .unwrap_or_else(|| panic!("Not enough shutdown receivers"));
    let rx_shutdown_subscriber = shutdown_receivers
        .pop()
        .unwrap_or_else(|| panic!("Not enough shutdown receivers"));

    vec![
        tokio::spawn(run_notify(state, rx_notifier, rx_shutdown_notify)),
        tokio::spawn(create_and_run_subscriber(
            authority_id,
            worker_cache,
            committee,
            rx_shutdown_subscriber,
            rx_sequence,
            client,
            restored_consensus_output,
            tx_notifier,
        )),
    ]
}

async fn run_notify<State: ExecutionState + Send + Sync + 'static>(
    state: State,
    mut rx_notify: Receiver<ConsensusOutput>,
    mut rx_shutdown: ConditionalBroadcastReceiver,
) {
    loop {
        tokio::select! {
            Some(message) = rx_notify.recv() => {
                state.handle_consensus_output(message).await;
            }

            _ = rx_shutdown.receiver.recv() => {
                return
            }

        }
    }
}

async fn create_and_run_subscriber(
    authority_id: AuthorityIdentifier,
    worker_cache: WorkerCache,
    committee: Committee,
    rx_shutdown: ConditionalBroadcastReceiver,
    rx_sequence: Receiver<CommittedSubDag>,
    client: NetworkClient,
    restored_consensus_output: Vec<CommittedSubDag>,
    tx_notifier: Sender<ConsensusOutput>,
) {
    info!("Starting subscriber");
    let subscriber = Subscriber {
        rx_shutdown,
        rx_sequence,
        inner: Arc::new(Inner {
            authority_id,
            committee,
            worker_cache,
            client,
        }),
    };
    subscriber
        .run(restored_consensus_output, tx_notifier)
        .await
        .expect("Failed to run subscriber")
}

impl Subscriber {
    /// Returns the max number of sub-dag to fetch payloads concurrently.
    const MAX_PENDING_PAYLOADS: usize = 1000;

    /// Main loop connecting to the consensus to listen to sequence messages.
    async fn run(
        mut self,
        restored_consensus_output: Vec<CommittedSubDag>,
        tx_notifier: Sender<ConsensusOutput>,
    ) -> SubscriberResult<()> {
        // It's important to have the futures in ordered fashion as we want
        // to guarantee that will deliver to the executor the certificates
        // in the same order we received from rx_sequence. So it doesn't
        // matter if we somehow managed to fetch the batches from a later
        // certificate. Unless the earlier certificate's payload has been
        // fetched, no later certificate will be delivered.
        let mut waiting = FuturesOrdered::new();

        // First handle any consensus output messages that were restored due to a restart.
        // This needs to happen before we start listening on rx_sequence and receive messages sequenced after these.
        for message in restored_consensus_output {
            let future = Self::fetch_batches(self.inner.clone(), message);
            waiting.push_back(future);

            // TODO(metrics): Increment `subscriber_recovered_certificates_count`
        }

        // Listen to sequenced consensus message and process them.
        loop {
            tokio::select! {
                // Receive the ordered sequence of consensus messages from a consensus node.
                Some(sub_dag) = self.rx_sequence.recv(), if waiting.len() < Self::MAX_PENDING_PAYLOADS => {
                    // We can schedule more then MAX_PENDING_PAYLOADS payloads but
                    // don't process more consensus messages when more
                    // then MAX_PENDING_PAYLOADS is pending
                    waiting.push_back(Self::fetch_batches(self.inner.clone(), sub_dag));
                },

                // Receive here consensus messages for which we have downloaded all transactions data.
                Some(message) = waiting.next() => {
                    if let Err(e) = tx_notifier.send(message).await {
                        error!("tx_notifier closed: {}", e);
                        return Ok(());
                    }
                },

                _ = self.rx_shutdown.receiver.recv() => {
                    return Ok(())
                }

            }

            // TODO(metrics): Set `waiting_elements_subscriber` to `waiting.len() as i64`
        }
    }

    /// Returns ordered vector of futures for downloading batches for certificates
    /// Order of futures returned follows order of batches in the certificates.
    /// See BatchFetcher for more details.
    async fn fetch_batches(inner: Arc<Inner>, deliver: CommittedSubDag) -> ConsensusOutput {
        let num_batches = deliver.num_batches();
        let num_certs = deliver.len();
        if num_batches == 0 {
            debug!("No batches to fetch, payload is empty");
            return ConsensusOutput {
                sub_dag: Arc::new(deliver),
                batches: vec![],
            };
        }

        let sub_dag = Arc::new(deliver);
        let mut subscriber_output = ConsensusOutput {
            sub_dag: sub_dag.clone(),
            batches: Vec::with_capacity(num_certs),
        };

        let mut batch_digests_and_workers: HashMap<
            NetworkPublicKey,
            (HashSet<BatchDigest>, HashSet<NetworkPublicKey>),
        > = HashMap::new();

        for cert in &sub_dag.certificates {
            for (digest, (worker_id, _)) in cert.header().payload().iter() {
                let own_worker_name = inner
                    .worker_cache
                    .worker(
                        inner
                            .committee
                            .authority(&inner.authority_id)
                            .unwrap()
                            .protocol_key(),
                        worker_id,
                    )
                    .unwrap_or_else(|_| panic!("worker_id {worker_id} is not in the worker cache"))
                    .name;
                let workers = Self::workers_for_certificate(&inner, cert, worker_id);
                let (batch_set, worker_set) = batch_digests_and_workers
                    .entry(own_worker_name)
                    .or_default();
                batch_set.insert(*digest);
                worker_set.extend(workers);
            }
        }

        // TODO(metrics): Start `batch_fetch_for_committed_subdag_total_latency` timer
        // TODO(metrics): Observe `num_batches as f64` on `committed_subdag_batch_count`
        let fetched_batches =
            Self::fetch_batches_from_workers(&inner, batch_digests_and_workers).await;
        // TODO(metrics): Stop `batch_fetch_for_committed_subdag_total_latency` timer

        // Map all fetched batches to their respective certificates and submit as
        // consensus output
        for cert in &sub_dag.certificates {
            let mut output_batches = Vec::with_capacity(cert.header().payload().len());
            let output_cert = cert.clone();

            // TODO(metrics): Set `subscriber_current_round` to `cert.round() as i64`
            // TODO(metrics): Observe `cert.metadata().created_at.elapsed().as_secs_f64()` on `subscriber_certificate_latency`

            #[cfg(feature = "metrics")]
            histogram!(
                snarkos_metrics::subscribers::CERTIFICATE_LATENCY,
                cert.metadata().created_at.elapsed().as_secs_f64(),
            );

            for (digest, (_, _)) in cert.header().payload().iter() {
                // TODO(metrics): Increment `subscriber_processed_batches`
                let batch = fetched_batches
                    .get(digest)
                    .expect("[Protocol violation] Batch not found in fetched batches from workers of certificate signers");

                debug!(
                    "Adding fetched batch {digest} from certificate {} to consensus output",
                    cert.digest()
                );
                output_batches.push(batch.clone());
            }
            subscriber_output
                .batches
                .push((output_cert, output_batches));
        }
        subscriber_output
    }

    fn workers_for_certificate(
        inner: &Inner,
        certificate: &Certificate,
        worker_id: &WorkerId,
    ) -> Vec<NetworkPublicKey> {
        // Can include own authority and worker, but worker will always check local storage when
        // fetching paylods.
        let authorities = certificate.signed_authorities(&inner.committee);
        authorities
            .into_iter()
            .filter_map(|authority| {
                let worker = inner.worker_cache.worker(&authority, worker_id);
                match worker {
                    Ok(worker) => Some(worker.name),
                    Err(err) => {
                        error!(
                            "Worker {} not found for authority {}: {:?}",
                            worker_id, authority, err
                        );
                        None
                    }
                }
            })
            .collect()
    }

    async fn fetch_batches_from_workers(
        inner: &Inner,
        batch_digests_and_workers: HashMap<
            NetworkPublicKey,
            (HashSet<BatchDigest>, HashSet<NetworkPublicKey>),
        >,
    ) -> HashMap<BatchDigest, Batch> {
        let mut fetched_batches = HashMap::new();

        for (worker_name, (digests, known_workers)) in batch_digests_and_workers {
            debug!(
                "Attempting to fetch {} digests from {} known workers, {worker_name}'s",
                digests.len(),
                known_workers.len()
            );
            // TODO: Can further parallelize this by worker if necessary. Maybe move the logic
            // to NetworkClient.
            // Only have one worker for now so will leave this for a future
            // optimization.
            let request = FetchBatchesRequest {
                digests,
                known_workers,
            };
            let batches = loop {
                match inner
                    .client
                    .fetch_batches(worker_name.clone(), request.clone())
                    .await
                {
                    Ok(resp) => break resp.batches,
                    Err(e) => {
                        error!("Failed to fetch batches from worker {worker_name}: {e:?}");
                        // Loop forever on failure. During shutdown, this should get cancelled.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            };
            for (digest, batch) in batches {
                // let batch_fetch_duration = batch.metadata().created_at.elapsed().as_secs_f64();
                // TODO(metrics): Observe `batch_fetch_duration` on `batch_fetch_latency`

                fetched_batches.insert(digest, batch);
            }
        }

        fetched_batches
    }
}

// TODO: add a unit test
