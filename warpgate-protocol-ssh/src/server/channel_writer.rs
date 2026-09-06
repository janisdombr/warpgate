use std::sync::Arc;

use anyhow::{Result, anyhow};
use russh::ChannelId;
use russh::server::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

/// How much target output may be outstanding towards the client at once.
///
/// A slot must be claimed by the session event loop *before* it takes a
/// target-side event off its queue, never by parking inside the write. The
/// loop is what completes the russh handler callbacks, and the russh reader —
/// blocked for as long as a callback is outstanding — is the only thing that
/// can process the client's `CHANNEL_WINDOW_ADJUST`. A loop parked on a write
/// that only the client's window can release deadlocks the session (#2494).
const OUTBOUND_DATA_SLOTS: usize = 64;

#[derive(Debug)]
enum ChannelWriteOperation {
    /// The permit rides along so it is released once the write has actually
    /// reached russh, not when it was queued.
    Data(Handle, ChannelId, Vec<u8>, Option<OwnedSemaphorePermit>),
    ExtendedData(
        Handle,
        ChannelId,
        u32,
        Vec<u8>,
        Option<OwnedSemaphorePermit>,
    ),
    Eof(Handle, ChannelId),
    Close(Handle, ChannelId),
    Success(Handle, ChannelId),
    Failure(Handle, ChannelId),
    ExitStatus(Handle, ChannelId, u32),
    ExitSignal(Handle, ChannelId, russh::Sig, bool, String, String),
    Flush(oneshot::Sender<()>),
}

/// Sequences everything the session sends to the client through one queue, so
/// per-channel ordering (data before EOF before close) holds without callers
/// flushing by hand, and runs the writes in the background so a stalled client
/// window never parks the session event loop.
///
/// The queue is unbounded because enqueueing must not block; what bounds it is
/// [`OUTBOUND_DATA_SLOTS`] on the one operation with unbounded rate. The rest
/// are one per client request or per channel.
pub struct ChannelWriter {
    tx: mpsc::UnboundedSender<ChannelWriteOperation>,
    data_slots: Arc<Semaphore>,
}

impl ChannelWriter {
    pub fn new() -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<ChannelWriteOperation>();
        // STALLCHAIN-INSTRUMENTATION: throwaway, strip before committing.
        let data_slots = Arc::new(Semaphore::new(OUTBOUND_DATA_SLOTS));
        let sc_slots = data_slots.clone();
        let sc_weak = Arc::downgrade(&data_slots);
        tokio::spawn(async move {
            let mut tick: u64 = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                tick += 1;
                let Some(s) = sc_weak.upgrade() else { break };
                tracing::info!(
                    t_ms = crate::stallchain_ms(),
                    tick,
                    permits = s.available_permits(),
                    "STALLCHAIN slots-tick"
                );
            }
        });
        tokio::spawn(async move {
            let mut seq: u64 = 0;
            while let Some(operation) = rx.recv().await {
                seq += 1;
                match operation {
                    ChannelWriteOperation::Data(handle, channel, data, _slot) => {
                        let len = data.len();
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Data", len, held_slot = _slot.is_some(), permits = sc_slots.available_permits(), "STALLCHAIN writer-enter");
                        let _ = handle.data(channel, data).await;
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Data", permits = sc_slots.available_permits(), "STALLCHAIN writer-exit");
                    }
                    ChannelWriteOperation::ExtendedData(handle, channel, ext, data, _slot) => {
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "ExtendedData", held_slot = _slot.is_some(), permits = sc_slots.available_permits(), "STALLCHAIN writer-enter");
                        let _ = handle.extended_data(channel, ext, data).await;
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "ExtendedData", permits = sc_slots.available_permits(), "STALLCHAIN writer-exit");
                    }
                    ChannelWriteOperation::Eof(handle, channel) => {
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Eof", permits = sc_slots.available_permits(), "STALLCHAIN writer-enter");
                        let _ = handle.eof(channel).await;
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Eof", permits = sc_slots.available_permits(), "STALLCHAIN writer-exit");
                    }
                    ChannelWriteOperation::Close(handle, channel) => {
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Close", permits = sc_slots.available_permits(), "STALLCHAIN writer-enter");
                        let _ = handle.close(channel).await;
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Close", permits = sc_slots.available_permits(), "STALLCHAIN writer-exit");
                    }
                    ChannelWriteOperation::Success(handle, channel) => {
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Success", "STALLCHAIN writer-enter");
                        let _ = handle.channel_success(channel).await;
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Success", "STALLCHAIN writer-exit");
                    }
                    ChannelWriteOperation::Failure(handle, channel) => {
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Failure", "STALLCHAIN writer-enter");
                        let _ = handle.channel_failure(channel).await;
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Failure", "STALLCHAIN writer-exit");
                    }
                    ChannelWriteOperation::ExitStatus(handle, channel, status) => {
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "ExitStatus", "STALLCHAIN writer-enter");
                        let _ = handle.exit_status_request(channel, status).await;
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "ExitStatus", "STALLCHAIN writer-exit");
                    }
                    ChannelWriteOperation::ExitSignal(
                        handle,
                        channel,
                        signal,
                        core_dumped,
                        message,
                        lang_tag,
                    ) => {
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "ExitSignal", "STALLCHAIN writer-enter");
                        let _ = handle
                            .exit_signal_request(channel, signal, core_dumped, message, lang_tag)
                            .await;
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "ExitSignal", "STALLCHAIN writer-exit");
                    }
                    ChannelWriteOperation::Flush(reply) => {
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Flush", "STALLCHAIN writer-enter");
                        let _ = reply.send(());
                        tracing::info!(t_ms = crate::stallchain_ms(), seq, op = "Flush", "STALLCHAIN writer-exit");
                    }
                }
            }
            tracing::info!(t_ms = crate::stallchain_ms(), "STALLCHAIN writer-task-ended");
        });
        Self { tx, data_slots }
    }

    /// The outbound data budget, to be claimed before accepting target-side
    /// work. See [`OUTBOUND_DATA_SLOTS`].
    pub fn data_slots(&self) -> Arc<Semaphore> {
        self.data_slots.clone()
    }

    fn enqueue(&self, operation: ChannelWriteOperation) -> Result<()> {
        self.tx
            .send(operation)
            .map_err(|_| anyhow!("ChannelWriter task has stopped"))
    }

    /// `slot` is the budget claimed for target output. Warpgate's own output
    /// (service messages, the target menu) passes `None`: it is emitted per
    /// user interaction, not per target byte, so it needs no budget and must
    /// never wait for one.
    pub fn write<D: Into<Vec<u8>>>(
        &self,
        handle: Handle,
        channel: ChannelId,
        data: D,
        slot: Option<OwnedSemaphorePermit>,
    ) -> Result<()> {
        self.enqueue(ChannelWriteOperation::Data(
            handle,
            channel,
            data.into(),
            slot,
        ))
    }

    pub fn write_extended<D: Into<Vec<u8>>>(
        &self,
        handle: Handle,
        channel: ChannelId,
        ext: u32,
        data: D,
        slot: Option<OwnedSemaphorePermit>,
    ) -> Result<()> {
        self.enqueue(ChannelWriteOperation::ExtendedData(
            handle,
            channel,
            ext,
            data.into(),
            slot,
        ))
    }

    pub fn eof(&self, handle: Handle, channel: ChannelId) -> Result<()> {
        self.enqueue(ChannelWriteOperation::Eof(handle, channel))
    }

    pub fn close(&self, handle: Handle, channel: ChannelId) -> Result<()> {
        self.enqueue(ChannelWriteOperation::Close(handle, channel))
    }

    pub fn channel_success(&self, handle: Handle, channel: ChannelId) -> Result<()> {
        self.enqueue(ChannelWriteOperation::Success(handle, channel))
    }

    pub fn channel_failure(&self, handle: Handle, channel: ChannelId) -> Result<()> {
        self.enqueue(ChannelWriteOperation::Failure(handle, channel))
    }

    pub fn exit_status(&self, handle: Handle, channel: ChannelId, status: u32) -> Result<()> {
        self.enqueue(ChannelWriteOperation::ExitStatus(handle, channel, status))
    }

    pub fn exit_signal(
        &self,
        handle: Handle,
        channel: ChannelId,
        signal: russh::Sig,
        core_dumped: bool,
        message: String,
        lang_tag: String,
    ) -> Result<()> {
        self.enqueue(ChannelWriteOperation::ExitSignal(
            handle,
            channel,
            signal,
            core_dumped,
            message,
            lang_tag,
        ))
    }

    /// Returns once all previously queued operations have completed. Only safe
    /// off the event loop, or under a timeout: a stalled client window holds
    /// the queue up indefinitely.
    pub async fn flush(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.enqueue(ChannelWriteOperation::Flush(tx))?;
        rx.await
            .map_err(|_| anyhow!("ChannelWriter flush failed"))?;
        Ok(())
    }
}
