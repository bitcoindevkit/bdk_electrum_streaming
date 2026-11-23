use std::{
    io::{BufReader, ErrorKind, Read, Write},
    sync::{
        atomic::{self, AtomicBool},
        mpsc,
    },
};

use anyhow::Context;
use bdk_core::bitcoin::{ScriptBuf, Txid};
use electrum_streaming_client::{BatchRequest, RawIncoming, RawRequest, RequestExt};
use miniscript::{Descriptor, DescriptorPublicKey};

use crate::{ClientAction, ReqQueue, State, Update};

#[derive(Debug)]
pub struct BlockingClient<K> {
    client_tx: mpsc::Sender<ClientAction<K>>,
}

pub type BlockingReceiver<K> = mpsc::Receiver<ClientAction<K>>;

impl<K: Sync + Send + 'static> BlockingClient<K> {
    pub fn new() -> (BlockingClient<K>, BlockingReceiver<K>) {
        let (client_tx, client_rx) = mpsc::channel::<ClientAction<K>>();
        (Self { client_tx }, client_rx)
    }

    /// Queues a batch of Electrum requests without waiting for their responses.
    ///
    /// Returns `Ok(true)` when the batch is queued, or `Ok(false)` if it is empty.
    ///
    /// # Errors
    ///
    /// Returns an error if the state machine's request channel is closed.
    ///
    /// # Callback warning
    ///
    /// [`BatchRequest::request`] callbacks run inline. Waiting for a reply from the
    /// same client (e.g., via [`Self::send_request`]) inside a callback will deadlock.
    pub fn send_batch_request(&self, batch_req: BatchRequest) -> anyhow::Result<bool> {
        match batch_req.into_inner() {
            Some(batch) => Ok(self
                .client_tx
                .send(ClientAction::Request(batch))
                .map(|_| true)?),
            None => Ok(false),
        }
    }

    pub fn send_request<Req>(&self, req: Req) -> anyhow::Result<Req::Response>
    where
        Req: RequestExt + Send + Sync + 'static,
    {
        let mut batch = BatchRequest::new();
        let resp_rx = batch.request_blocking(req);
        self.send_batch_request(batch)
            .context("failed to send request to state machine")?;
        Ok(resp_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("request got cancelled by the state machine"))??)
    }

    /// Track `descriptor` under `keychain` through `next_index` plus lookahead.
    ///
    /// `expected_spk_txids` are the txids we expect the server to report for the spks this
    /// registers; see
    /// [`DerivedSpkTracker::insert_descriptor`](crate::DerivedSpkTracker::insert_descriptor).
    pub fn track_descriptor(
        &self,
        keychain: K,
        descriptor: Descriptor<DescriptorPublicKey>,
        next_index: u32,
        expected_spk_txids: impl IntoIterator<Item = (ScriptBuf, Txid)>,
    ) -> anyhow::Result<()> {
        let descriptor = Box::new(descriptor);
        Ok(self.client_tx.send(ClientAction::AddDescriptor {
            keychain,
            descriptor,
            next_index,
            expected_spk_txids: expected_spk_txids.into_iter().collect(),
        })?)
    }

    pub fn stop(self) -> anyhow::Result<()> {
        Ok(self.client_tx.send(ClientAction::Stop)?)
    }
}

enum StateAction<K> {
    FromServer(RawIncoming),
    FromClient(ClientAction<K>),
}

pub fn run_blocking<'env, K, R, W>(
    state: &'env mut State<K>,
    shutdown: &'env AtomicBool,
    update_tx: &'env mut mpsc::Sender<Update<K>>,
    client_rx: &'env mut BlockingReceiver<K>,
    read: R,
    mut write: W,
) -> anyhow::Result<()>
where
    K: Ord + Clone + Send + 'env,
    R: Read + Send + 'env,
    W: Write + Send + 'env,
{
    shutdown.store(false, atomic::Ordering::Relaxed);

    fn shutdown_on_return<F, T>(shutdown: &AtomicBool, f: F) -> impl FnOnce() -> T + use<'_, F, T>
    where
        F: FnOnce() -> T,
    {
        move || {
            let r = f();
            shutdown.store(true, atomic::Ordering::Relaxed);
            r
        }
    }

    std::thread::scope::<'env>(|s| -> anyhow::Result<()> {
        let read_stream = electrum_streaming_client::io::ReadStreamer::new(BufReader::new(read));

        let mut req_queue = ReqQueue::new();
        state.start(&mut req_queue);

        // For sending to the write thread.
        let (write_tx, write_rx) = mpsc::channel::<RawRequest>();
        // For sending to the state thread.
        let (state_tx, state_rx) = mpsc::channel::<StateAction<K>>();

        // Read thread.
        // Only errors on failed read.
        let read_state_tx = state_tx.clone();
        let read_join = s.spawn(shutdown_on_return(shutdown, move || {
            for r in read_stream {
                let raw = match r {
                    Err(e)
                        if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock =>
                    {
                        if shutdown.load(atomic::Ordering::Relaxed) {
                            break;
                        } else {
                            tracing::debug!("Read timeout");
                            continue;
                        }
                    }
                    other_result => other_result?,
                };

                // Purely for logging.
                match &raw {
                    RawIncoming::Notification(raw_notification) => {
                        tracing::trace!(
                            method = &*raw_notification.method,
                            params = raw_notification.params.to_string(),
                            "read_thread: got notification",
                        );
                    }
                    RawIncoming::Response(raw_response) => {
                        tracing::trace!(
                            id = raw_response.id,
                            is_ok = raw_response.result.is_ok(),
                            "read_thread: got response"
                        );
                    }
                };
                if read_state_tx.send(StateAction::FromServer(raw)).is_err() {
                    break;
                };
            }
            tracing::trace!("read_thread: finished cleanly");
            anyhow::Ok(())
        }));

        // Write thread.
        // Only errors on failed writes.
        let write_join = s.spawn(shutdown_on_return(shutdown, move || {
            while let Ok(req) = write_rx.recv() {
                if shutdown.load(atomic::Ordering::Relaxed) {
                    break;
                }
                tracing::trace!(method = &*req.method, id = req.id, "write_thread: writing");
                electrum_streaming_client::io::blocking_write(&mut write, req)?;
            }
            tracing::trace!("write_thread: finished cleanly");
            anyhow::Ok(())
        }));

        // Client thread.
        let _client_join = s.spawn(shutdown_on_return(shutdown, move || {
            while let Ok(batch) = client_rx.recv() {
                if shutdown.load(atomic::Ordering::Relaxed) {
                    break;
                }
                if state_tx.send(StateAction::FromClient(batch)).is_err() {
                    break;
                }
            }
            tracing::trace!("client_thread: finished cleanly");
        }));

        // State thread.
        let state_join = s.spawn(shutdown_on_return(shutdown, move || {
            loop {
                while let Some(req) = req_queue.pop_front() {
                    write_tx.send(req)?;
                }
                if shutdown.load(atomic::Ordering::Relaxed) {
                    break;
                }
                let action = match state_rx.recv() {
                    Ok(action) => action,
                    Err(_) => break,
                };
                match action {
                    StateAction::FromServer(raw) => {
                        if let Some(update) = state.poll(&mut req_queue, raw)? {
                            update_tx
                                .send(update)
                                .map_err(|err| anyhow::anyhow!(err.to_string()))
                                .context("Failed to send to update channel")?;
                        }
                    }
                    StateAction::FromClient(ClientAction::Request(batch)) => {
                        state.user_request(&mut req_queue, batch);
                    }
                    StateAction::FromClient(ClientAction::AddDescriptor {
                        keychain,
                        descriptor,
                        next_index,
                        expected_spk_txids,
                    }) => {
                        state.insert_descriptor(
                            &mut req_queue,
                            keychain,
                            *descriptor,
                            next_index,
                            expected_spk_txids,
                        );
                    }
                    StateAction::FromClient(ClientAction::Stop) => {
                        drop(write_tx);
                        drop(state_rx);
                        break;
                    }
                }
            }
            tracing::trace!("state_thread: finished cleanly");
            anyhow::Ok(())
        }));

        read_join
            .join()
            .expect("read thread failed")
            .context("read thread stopped")?;
        write_join
            .join()
            .expect("write thread failed")
            .context("write thread stopped")?;
        state_join
            .join()
            .expect("state thread failed")
            .context("state thread stopped")?;
        Ok(())
    })
}
