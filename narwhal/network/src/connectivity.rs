// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anemo::types::PeerEvent;
use anemo::PeerId;
use dashmap::DashMap;
use futures::future;
use quinn_proto::ConnectionStats;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time;
use types::ConditionalBroadcastReceiver;

#[cfg(feature = "metrics")]
use snarkos_metrics::gauge;

const CONNECTION_STAT_COLLECTION_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
}

pub struct ConnectionMonitor {
    network: anemo::NetworkRef,
    peer_id_types: HashMap<PeerId, String>,
    connection_statuses: Arc<DashMap<PeerId, ConnectionStatus>>,
    rx_shutdown: Option<ConditionalBroadcastReceiver>,
}

impl ConnectionMonitor {
    #[must_use]
    pub fn spawn(
        network: anemo::NetworkRef,
        peer_id_types: HashMap<PeerId, String>,
        rx_shutdown: Option<ConditionalBroadcastReceiver>,
    ) -> (JoinHandle<()>, Arc<DashMap<PeerId, ConnectionStatus>>) {
        let connection_statuses_outer = Arc::new(DashMap::new());
        let connection_statuses = connection_statuses_outer.clone();
        (
            tokio::spawn(
                Self {
                    network,
                    peer_id_types,
                    connection_statuses,
                    rx_shutdown,
                }
                .run(),
            ),
            connection_statuses_outer,
        )
    }

    async fn run(mut self) {
        let (mut subscriber, connected_peers) = {
            if let Some(network) = self.network.upgrade() {
                let Ok((subscriber, active_peers)) = network.subscribe() else {
                    return;
                };
                (subscriber, active_peers)
            } else {
                return;
            }
        };

        // we report first all the known peers as disconnected - so we can see
        // their labels in the metrics reporting tool
        let mut known_peers = Vec::new();
        for (peer_id, _ty) in &self.peer_id_types {
            known_peers.push(*peer_id);
            // TODO(metrics): Set `network_peer_connected` to 0.
        }

        // now report the connected peers
        for peer_id in connected_peers.iter() {
            self.handle_peer_status_change(*peer_id, ConnectionStatus::Connected)
                .await;
        }

        let mut connection_stat_collection_interval =
            time::interval(CONNECTION_STAT_COLLECTION_INTERVAL);

        async fn wait_for_shutdown(
            rx_shutdown: &mut Option<ConditionalBroadcastReceiver>,
        ) -> Result<(), tokio::sync::broadcast::error::RecvError> {
            if let Some(rx) = rx_shutdown.as_mut() {
                rx.receiver.recv().await
            } else {
                // If no shutdown receiver is provided, wait forever.
                let future = future::pending();
                #[allow(clippy::let_unit_value)]
                let () = future.await;
                Ok(())
            }
        }

        loop {
            tokio::select! {
                _ = connection_stat_collection_interval.tick() => {
                    if let Some(network) = self.network.upgrade() {
                        for peer_id in known_peers.iter() {
                            if let Some(connection) = network.peer(*peer_id) {
                                let stats = connection.connection_stats();
                                self.update_quinn_metrics_for_peer(&format!("{peer_id}"), &stats);
                            }
                        }
                    } else {
                        continue;
                    }
                }
                Ok(event) = subscriber.recv() => {
                    match event {
                        PeerEvent::NewPeer(peer_id) => {
                            self.handle_peer_status_change(peer_id, ConnectionStatus::Connected).await;
                        }
                        PeerEvent::LostPeer(peer_id, _) => {
                            self.handle_peer_status_change(peer_id, ConnectionStatus::Disconnected).await;
                        }
                    }
                }
                _ = wait_for_shutdown(&mut self.rx_shutdown) => {
                    return;
                }
            }
        }
    }

    async fn handle_peer_status_change(
        &self,
        peer_id: PeerId,
        connection_status: ConnectionStatus,
    ) {
        if let Some(network) = self.network.upgrade() {
            // TODO(metrics): Set `network_peers` to `network.peers().len() as i64`
        } else {
            return;
        }

        if let Some(ty) = self.peer_id_types.get(&peer_id) {
            let int_status = match connection_status {
                ConnectionStatus::Connected => 1,
                ConnectionStatus::Disconnected => 0,
            };

            // TODO(metrics): Set `network_peer_connected` to `int_status`
        }

        #[cfg(feature = "metrics")]
        {
            let peer_count = self
                .connection_statuses
                .iter()
                .filter(|entry| entry.value() == &ConnectionStatus::Connected)
                .count();
            gauge!(snarkos_metrics::network::NETWORK_PEERS, peer_count as f64);
        }

        // TODO(metrics):
        // if let PeerEvent::LostPeer(_, reason) = peer_event {
        //     self.connection_metrics
        //         .network_peer_disconnects
        //         .with_label_values(&[&peer_id_str, &format!("{reason:?}")])
        //         .inc();
        // }
    }

    // TODO: Replace this with ClosureMetric
    fn update_quinn_metrics_for_peer(&self, peer_id: &str, stats: &ConnectionStats) {
        // Update PathStats
        // self.connection_metrics
        //     .network_peer_rtt
        //     .with_label_values(&[peer_id])
        //     .set(stats.path.rtt.as_millis() as i64);
        // self.connection_metrics
        //     .network_peer_lost_packets
        //     .with_label_values(&[peer_id])
        //     .set(stats.path.lost_packets as i64);
        // self.connection_metrics
        //     .network_peer_lost_bytes
        //     .with_label_values(&[peer_id])
        //     .set(stats.path.lost_bytes as i64);
        // self.connection_metrics
        //     .network_peer_sent_packets
        //     .with_label_values(&[peer_id])
        //     .set(stats.path.sent_packets as i64);
        // self.connection_metrics
        //     .network_peer_congestion_events
        //     .with_label_values(&[peer_id])
        //     .set(stats.path.congestion_events as i64);
        // self.connection_metrics
        //     .network_peer_congestion_window
        //     .with_label_values(&[peer_id])
        //     .set(stats.path.cwnd as i64);

        // Update FrameStats
        // self.connection_metrics
        //     .network_peer_max_data
        //     .with_label_values(&[peer_id, "transmitted"])
        //     .set(stats.frame_tx.max_data as i64);
        // self.connection_metrics
        //     .network_peer_max_data
        //     .with_label_values(&[peer_id, "received"])
        //     .set(stats.frame_rx.max_data as i64);
        // self.connection_metrics
        //     .network_peer_closed_connections
        //     .with_label_values(&[peer_id, "transmitted"])
        //     .set(stats.frame_tx.connection_close as i64);
        // self.connection_metrics
        //     .network_peer_closed_connections
        //     .with_label_values(&[peer_id, "received"])
        //     .set(stats.frame_rx.connection_close as i64);
        // self.connection_metrics
        //     .network_peer_data_blocked
        //     .with_label_values(&[peer_id, "transmitted"])
        //     .set(stats.frame_tx.data_blocked as i64);
        // self.connection_metrics
        //     .network_peer_data_blocked
        //     .with_label_values(&[peer_id, "received"])
        //     .set(stats.frame_rx.data_blocked as i64);

        // Update UDPStats
        // self.connection_metrics
        //     .network_peer_udp_datagrams
        //     .with_label_values(&[peer_id, "transmitted"])
        //     .set(stats.udp_tx.datagrams as i64);
        // self.connection_metrics
        //     .network_peer_udp_datagrams
        //     .with_label_values(&[peer_id, "received"])
        //     .set(stats.udp_rx.datagrams as i64);
        // self.connection_metrics
        //     .network_peer_udp_bytes
        //     .with_label_values(&[peer_id, "transmitted"])
        //     .set(stats.udp_tx.bytes as i64);
        // self.connection_metrics
        //     .network_peer_udp_bytes
        //     .with_label_values(&[peer_id, "received"])
        //     .set(stats.udp_rx.bytes as i64);
        // self.connection_metrics
        //     .network_peer_udp_transmits
        //     .with_label_values(&[peer_id, "transmitted"])
        //     .set(stats.udp_tx.transmits as i64);
        // self.connection_metrics
        //     .network_peer_udp_transmits
        //     .with_label_values(&[peer_id, "received"])
        //     .set(stats.udp_rx.transmits as i64);
    }
}

#[cfg(test)]
mod tests {
    use crate::connectivity::{ConnectionMonitor, ConnectionStatus};
    use anemo::{Network, Request, Response};
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};
    use tower::util::BoxCloneService;

    #[tokio::test]
    async fn test_connectivity() {
        // GIVEN
        let network_1 = build_network().unwrap();
        let network_2 = build_network().unwrap();
        let network_3 = build_network().unwrap();

        // AND we connect to peer 2
        let peer_2 = network_1.connect(network_2.local_addr()).await.unwrap();

        let mut peer_types = HashMap::new();
        peer_types.insert(network_2.peer_id(), "other_network".to_string());
        peer_types.insert(network_3.peer_id(), "other_network".to_string());

        // WHEN bring up the monitor
        let (_h, statuses) = ConnectionMonitor::spawn(network_1.downgrade(), peer_types, None);

        // THEN peer 2 should be already connected
        // assert_network_peers(metrics.clone(), 1).await;

        // AND we should have collected connection stats
        let mut labels = HashMap::new();
        let peer_2_str = format!("{peer_2}");
        labels.insert("peer_id", peer_2_str.as_str());
        assert_eq!(
            *statuses.get(&peer_2).unwrap().value(),
            ConnectionStatus::Connected
        );

        // WHEN connect to peer 3
        let peer_3 = network_1.connect(network_3.local_addr()).await.unwrap();

        // THEN
        // assert_network_peers(metrics.clone(), 2).await;
        assert_eq!(
            *statuses.get(&peer_3).unwrap().value(),
            ConnectionStatus::Connected
        );

        // AND disconnect peer 2
        network_1.disconnect(peer_2).unwrap();

        // THEN
        // assert_network_peers(metrics.clone(), 1).await;
        assert_eq!(
            *statuses.get(&peer_2).unwrap().value(),
            ConnectionStatus::Disconnected
        );

        // AND disconnect peer 3
        network_1.disconnect(peer_3).unwrap();

        // THEN
        // assert_network_peers(metrics.clone(), 0).await;
        assert_eq!(
            *statuses.get(&peer_3).unwrap().value(),
            ConnectionStatus::Disconnected
        );
    }

    fn build_network() -> anyhow::Result<Network> {
        let network = Network::bind("localhost:0")
            .private_key(random_private_key())
            .server_name("test")
            .start(echo_service())?;
        Ok(network)
    }

    fn echo_service() -> BoxCloneService<Request<Bytes>, Response<Bytes>, Infallible> {
        let handle = move |request: Request<Bytes>| async move {
            let response = Response::new(request.into_body());
            Result::<Response<Bytes>, Infallible>::Ok(response)
        };

        tower::ServiceExt::boxed_clone(tower::service_fn(handle))
    }

    fn random_private_key() -> [u8; 32] {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut bytes[..]);

        bytes
    }
}
