//! Asynchronous I/O utilities.
//!
//! Contains functions designed for copying data between asynchronous readers
//! and writers, with support for bidirectional transfers and error mapping.

use std::{error, fmt, io};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinError, JoinSet};

/// Represents a failure during a low-level asynchronous copy operation.
///
/// Can indicate an error on the read side or the write side.
#[derive(Debug)]
pub enum CopyError {
    /// An I/O error occurred while reading from the source stream.
    Read(io::Error),
    /// An I/O error occurred while writing to or flushing the destination sink.
    Write(io::Error),
}

impl fmt::Display for CopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(e) => write!(f, "Read error: {e}"),
            Self::Write(e) => write!(f, "Write error: {e}"),
        }
    }
}

impl error::Error for CopyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Read(e) => Some(e),
            Self::Write(e) => Some(e),
        }
    }
}

impl CopyError {
    fn map_err_mode(self, mode: TransferMode) -> TransferError<Self> {
        match (mode, &self) {
            (TransferMode::NetworkToApplication, Self::Read(_))
            | (TransferMode::ApplicationToNetwork, Self::Write(_)) => TransferError::Network(self),

            (TransferMode::NetworkToApplication, Self::Write(_))
            | (TransferMode::ApplicationToNetwork, Self::Read(_)) => {
                TransferError::Application(self)
            }
        }
    }
}

impl From<CopyError> for io::Error {
    fn from(value: CopyError) -> Self {
        match value {
            CopyError::Read(error) => error,
            CopyError::Write(error) => error,
        }
    }
}

/// Copies data from a reader to a writer asynchronously.
///
/// This function reads from `reader` and writes to `writer` using an internal 8KB buffer
/// until the reader reaches EOF.
///
/// # Arguments
///
/// * `reader` - An object implementing [`AsyncRead`] and [`Unpin`].
/// * `writer` - An object implementing [`AsyncWrite`] and [`Unpin`].
/// * `error_on_eof` - If provided, this error will be returned instead of the total
///   bytes copied when the end of the stream is reached.
///
/// # Errors
///
/// Returns a [`CopyError`] if:
/// * An I/O error occurs while reading ([`CopyError::Read`]).
/// * An I/O error occurs while writing or flushing ([`CopyError::Write`]).
/// * `error_on_eof` is set, triggered upon reaching the end of the stream.
///
/// # Returns
///
/// On success, returns the total number of bytes copied as a `usize`.
pub async fn copy<R, W>(
    reader: R,
    writer: W,
    error_on_eof: Option<io::Error>,
) -> Result<usize, CopyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy_inner(reader, writer, error_on_eof, false).await
}

/// Identical to `copy`, except that it flushes the writer and yields to the
/// runtime scheduler on every iteration of the copy loop.
pub async fn yielding_copy<R, W>(
    reader: R,
    writer: W,
    error_on_eof: Option<io::Error>,
) -> Result<usize, CopyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy_inner(reader, writer, error_on_eof, true).await
}

async fn copy_inner<R, W>(
    mut reader: R,
    mut writer: W,
    error_on_eof: Option<io::Error>,
    yielding: bool,
) -> Result<usize, CopyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut total = 0;
    loop {
        let n = reader.read(&mut buf).await.map_err(CopyError::Read)?;
        if n == 0 {
            break;
        }
        writer
            .write_all(&buf[..n])
            .await
            .map_err(CopyError::Write)?;
        total += n;
        if yielding {
            writer.flush().await.map_err(CopyError::Write)?;
            tokio::task::yield_now().await;
        }
    }
    if total > 0 {
        writer.flush().await.map_err(CopyError::Write)?;
    }
    error_on_eof.map_or(Ok(total), |e| Err(CopyError::Read(e)))
}

/// Represents a higher-level failure during a bidirectional data transfer.
///
/// Categorized into `Network` errors (potentially recoverable via resumption) and `Application` errors.
#[derive(Debug)]
pub enum TransferError<E> {
    /// A network error occurred, indicating a dropped connection that might be resumable.
    Network(E),
    /// A fatal application error occurred, such as a protocol violation or bad state.
    Application(E),
    /// An error occurred that is unrelated to a network or application read, write, or EOF.
    Internal(E),
    /// The transfer was interrupted or failed to complete due to a task joining error.
    Unfinished(JoinError),
}

impl<E: fmt::Display> fmt::Display for TransferError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(e) => write!(f, "Network-side error: {e}"),
            Self::Application(e) => write!(f, "Application-side error: {e}"),
            Self::Internal(e) => write!(f, "Internal error: {e}"),
            Self::Unfinished(e) => write!(f, "Transfer unfinished due to task error: {e}"),
        }
    }
}

impl<E: error::Error + 'static> error::Error for TransferError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Network(e) => Some(e),
            Self::Application(e) => Some(e),
            Self::Internal(e) => Some(e),
            Self::Unfinished(e) => Some(e),
        }
    }
}

impl<E> From<TransferError<E>> for io::Error
where
    io::Error: From<E>,
{
    fn from(value: TransferError<E>) -> Self {
        match value {
            TransferError::Network(error) => error.into(),
            TransferError::Application(error) => error.into(),
            TransferError::Internal(error) => error.into(),
            TransferError::Unfinished(error) => error.into(),
        }
    }
}

/// Dictates how I/O errors are categorized during a data transfer operation.
///
/// Helps distinguish between underlying network failures and local application protocol errors.
///
/// This helps distinguish between underlying network failures (which may be recoverable)
/// and local application protocol errors (which are fatal).
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum TransferMode {
    /// Data is moving from the network (reader) to the application (writer).
    NetworkToApplication,
    /// Data is moving from the application (reader) to the network (writer).
    ApplicationToNetwork,
}

/// Asynchronously transfers data between a reader and a writer, mapping errors
/// to a specific [`TransferMode`].
///
/// This function wraps the underlying `copy` logic and categorizes any
/// resulting [`CopyError`] as either a [`TransferError::Network`] or
/// [`TransferError::Application`] failure based on the provided `mode`.
///
/// # Inputs
///
/// * `reader` - The source of the data.
/// * `writer` - The destination for the data.
/// * `mode` - The [`TransferMode`] used to determine how to map read/write errors.
/// * `error_on_eof` - An optional error to trigger immediately upon reaching EOF.
///
/// # Returns
///
/// A `Result` containing the number of bytes transferred or a [`TransferError`]
/// if the underlying copy operation fails.
pub async fn transfer<R, W>(
    mut reader: R,
    mut writer: W,
    mode: TransferMode,
    error_on_eof: Option<io::Error>,
) -> Result<usize, TransferError<CopyError>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy(&mut reader, &mut writer, error_on_eof)
        .await
        .map_err(|e| e.map_err_mode(mode))
}

/// Performs a bidirectional data transfer between an application and a network,
/// waiting for both directions to finish.
///
/// This function runs two concurrent transfers:
/// 1. **Network-to-Application**: Reads from `net_reader` and writes to `app_writer`.
/// 2. **Application-to-Network**: Reads from `app_reader` and writes to `net_writer`.
///
/// Because it uses `tokio::join!`, both transfers will run to completion (or
/// failure) before the function returns, regardless of whether one side fails
/// early.
///
/// # Returns
///
/// A tuple containing the results of both transfers:
/// `(Network-to-Application Result, Application-to-Network Result)`.
pub async fn copy_join<AppR, AppW, NetR, NetW>(
    mut app_reader: AppR,
    mut app_writer: AppW,
    mut net_reader: NetR,
    mut net_writer: NetW,
    error_on_app_eof: Option<io::Error>,
    error_on_net_eof: Option<io::Error>,
) -> (
    Result<usize, TransferError<CopyError>>,
    Result<usize, TransferError<CopyError>>,
)
where
    AppR: AsyncRead + Unpin,
    AppW: AsyncWrite + Unpin,
    NetR: AsyncRead + Unpin,
    NetW: AsyncWrite + Unpin,
{
    tokio::join!(
        transfer(
            &mut net_reader,
            &mut app_writer,
            TransferMode::NetworkToApplication,
            error_on_net_eof
        ),
        transfer(
            &mut app_reader,
            &mut net_writer,
            TransferMode::ApplicationToNetwork,
            error_on_app_eof
        )
    )
}

/// Performs a bidirectional data transfer between an application and a network,
/// returning early if either side fails.
///
/// Similar to [`copy_join`], this manages concurrent transfers in both
/// directions. However, it uses `tokio::try_join!`, meaning if one transfer
/// returns an error, the other is immediately aborted and the error is
/// returned.
///
/// # Errors
///
/// Returns the first [`TransferError`] encountered by either direction.
///
/// # Returns
///
/// On success, returns a tuple containing the total bytes moved in each direction:
/// `(Network-to-Application count, Application-to-Network count)`.
/// On error, returns the first [`TransferError`] encountered by either transfer direction.
pub async fn copy_try_join<AppR, AppW, NetR, NetW>(
    mut app_reader: AppR,
    mut app_writer: AppW,
    mut net_reader: NetR,
    mut net_writer: NetW,
    error_on_app_eof: Option<io::Error>,
    error_on_net_eof: Option<io::Error>,
) -> Result<(usize, usize), TransferError<CopyError>>
where
    AppR: AsyncRead + Unpin,
    AppW: AsyncWrite + Unpin,
    NetR: AsyncRead + Unpin,
    NetW: AsyncWrite + Unpin,
{
    tokio::try_join!(
        transfer(
            &mut net_reader,
            &mut app_writer,
            TransferMode::NetworkToApplication,
            error_on_net_eof
        ),
        transfer(
            &mut app_reader,
            &mut net_writer,
            TransferMode::ApplicationToNetwork,
            error_on_app_eof
        )
    )
}

/// Performs a bidirectional data transfer using the provided transfer objects,
/// waiting for both directions to finish.
///
/// This function runs two concurrent transfers:
/// 1. **Network-to-Application**: Executes the `net_to_app` transfer.
/// 2. **Application-to-Network**: Executes the `app_to_net` transfer.
///
/// Because it uses `tokio::join!`, both transfers will run to completion (or
/// failure) before the function returns, regardless of whether one side fails
/// early.
///
/// # Returns
///
/// A tuple containing the results of both transfers:
/// `(Network-to-Application Result, Application-to-Network Result)`.
pub async fn transfer_join<T, U>(
    mut app_to_net: T,
    mut net_to_app: U,
) -> (
    Result<usize, TransferError<T::Error>>,
    Result<usize, TransferError<T::Error>>,
)
where
    T: Transfer + Unpin,
    U: Transfer<Error = T::Error> + Unpin,
{
    tokio::join!(net_to_app.transfer(), app_to_net.transfer())
}

/// Performs a bidirectional data transfer using the provided transfer objects,
/// returning early if either side fails.
///
/// Similar to [`transfer_join`], this manages concurrent transfers in both
/// directions. However, it uses `tokio::try_join!`, meaning if one transfer
/// returns an error, the other is immediately aborted and the error is
/// returned.
///
/// # Errors
///
/// Returns the first [`TransferError`] encountered by either direction.
///
/// # Returns
///
/// On success, returns a tuple containing the total bytes moved in each direction:
/// `(Network-to-Application count, Application-to-Network count)`.
/// On error, returns the first `TransferError` encountered by either transfer direction.
pub async fn transfer_try_join<T, U>(
    mut app_to_net: T,
    mut net_to_app: U,
) -> Result<(usize, usize), TransferError<T::Error>>
where
    T: Transfer + Unpin,
    U: Transfer<Error = T::Error> + Unpin,
{
    tokio::try_join!(net_to_app.transfer(), app_to_net.transfer())
}

/// Spawns bidirectional transfer tasks on the Tokio runtime and waits for both
/// to complete, returning the original io objects and the results from both
/// directions.
///
/// Provides the same functionality as [`transfer_spawn_join`], using internal
/// objects that implement the [`Transfer`] trait to copy data between the
/// network and the application.
///
/// # Returns
///
/// A tuple containing:
/// 1. The original I/O objects: `(app_reader, app_writer, net_reader, net_writer)`.
/// 2. The result of the **Network-to-Application** transfer.
/// 3. The result of the **Application-to-Network** transfer.
pub async fn copy_spawn_join<AppR, AppW, NetR, NetW>(
    app_reader: AppR,
    app_writer: AppW,
    net_reader: NetR,
    net_writer: NetW,
    error_on_app_eof: Option<io::Error>,
    error_on_net_eof: Option<io::Error>,
) -> (
    (AppR, AppW, NetR, NetW),
    Result<usize, TransferError<CopyError>>,
    Result<usize, TransferError<CopyError>>,
)
where
    AppR: AsyncRead + Unpin + Send + 'static,
    AppW: AsyncWrite + Unpin + Send + 'static,
    NetR: AsyncRead + Unpin + Send + 'static,
    NetW: AsyncWrite + Unpin + Send + 'static,
{
    let (app_to_net, net_to_app) = copiers_from_io(
        app_reader,
        app_writer,
        net_reader,
        net_writer,
        error_on_app_eof,
        error_on_net_eof,
    );

    let (io_objects, net_to_app_res, app_to_net_res) =
        transfer_spawn_join(app_to_net, net_to_app).await;

    (io_from_copiers(io_objects), net_to_app_res, app_to_net_res)
}

/// Spawns bidirectional transfer tasks on the Tokio runtime and returns early
/// with the original io objects if either direction encounters an error. If one
/// direction fails, the remaining task is aborted immediately.
///
/// Provides the same functionality as [`transfer_spawn_try_join`], using
/// internal objects that implement the [`Transfer`] trait to copy data between
/// the network and the application.
///
/// # Errors
///
/// Returns the first [`TransferError`] encountered.
///
/// # Returns
///
/// A tuple containing:
/// 1. The original I/O objects: `(app_reader, app_writer, net_reader, net_writer)`.
/// 2. A `Result` containing the bytes transferred in each direction:
///    `(Network-to-Application count, Application-to-Network count)`,
///    or the first error that occurred.
pub async fn copy_spawn_try_join<AppR, AppW, NetR, NetW>(
    app_reader: AppR,
    app_writer: AppW,
    net_reader: NetR,
    net_writer: NetW,
    error_on_app_eof: Option<io::Error>,
    error_on_net_eof: Option<io::Error>,
) -> (
    (AppR, AppW, NetR, NetW),
    Result<(usize, usize), TransferError<CopyError>>,
)
where
    AppR: AsyncRead + Unpin + Send + 'static,
    AppW: AsyncWrite + Unpin + Send + 'static,
    NetR: AsyncRead + Unpin + Send + 'static,
    NetW: AsyncWrite + Unpin + Send + 'static,
{
    let (app_to_net, net_to_app) = copiers_from_io(
        app_reader,
        app_writer,
        net_reader,
        net_writer,
        error_on_app_eof,
        error_on_net_eof,
    );

    let (io_objects, result) = transfer_spawn_try_join(app_to_net, net_to_app).await;

    (io_from_copiers(io_objects), result)
}

/// Spawns bidirectional transfer tasks on the Tokio runtime and waits for both
/// to complete, returning the original Transfer wrappers and individual
/// results.
///
/// This function uses a `JoinSet` to run transfers concurrently. This "spawn"
/// variant allows
/// 1. the transfers to run in parallel if supported by the runtime,
/// 2. Transfer wrappers to be recovered even if the tasks are aborted or fail,
///    thanks to an internal recovery mechanism.
///
/// # Returns
///
/// A tuple containing:
/// 1. The original Transfer wrappers: `(app_to_net, net_to_app)`.
/// 2. The result of the **Network-to-Application** transfer.
/// 3. The result of the **Application-to-Network** transfer.
pub async fn transfer_spawn_join<T, U>(
    app_to_net: T,
    net_to_app: U,
) -> (
    (T, U),
    Result<usize, TransferError<T::Error>>,
    Result<usize, TransferError<T::Error>>,
)
where
    T: Transfer + Send + 'static,
    <T as Transfer>::Error: Send,
    U: Transfer<Error = T::Error> + Send + 'static,
{
    let (io_objects, first, second) =
        transfer_spawn_join_inner(app_to_net, net_to_app, false).await;

    let (mode_first, res_first) = first;
    let (_, res_second) = second;

    if mode_first == TransferMode::NetworkToApplication {
        (io_objects, res_first, res_second)
    } else {
        (io_objects, res_second, res_first)
    }
}

/// Spawns bidirectional transfer tasks on the Tokio runtime and returns early
/// with the Transfer wrappers if either direction encounters an error. If one
/// direction fails, the remaining task is aborted immediately.
///
/// This function uses a `JoinSet` to run transfers concurrently. This "spawn"
/// variant allows
/// 1. the transfers to run in parallel if supported by the runtime,
/// 2. Transfer wrappers to be recovered even if the tasks are aborted or fail,
///    thanks to an internal recovery mechanism.
///
/// # Errors
///
/// Returns the first [`TransferError`] encountered.
///
/// # Returns
///
/// A tuple containing:
/// 1. The original Transfer wrappers: `(app_to_net, net_to_app)`.
/// 2. A `Result` containing the bytes transferred in each direction:
///    `(Network-to-Application count, Application-to-Network count)`,
///    or the first error that occurred.
pub async fn transfer_spawn_try_join<T, U>(
    app_to_net: T,
    net_to_app: U,
) -> ((T, U), Result<(usize, usize), TransferError<T::Error>>)
where
    T: Transfer + Send + 'static,
    <T as Transfer>::Error: Send,
    U: Transfer<Error = T::Error> + Send + 'static,
{
    let (io_objects, first, second) = transfer_spawn_join_inner(app_to_net, net_to_app, true).await;

    let (mode_first, res_first) = first;
    let (_, res_second) = second;

    let n_first = match res_first {
        Ok(n) => n,
        Err(e) => return (io_objects, Err(e)),
    };

    let n_second = match res_second {
        Ok(n) => n,
        Err(e) => return (io_objects, Err(e)),
    };

    if mode_first == TransferMode::NetworkToApplication {
        (io_objects, Ok((n_first, n_second)))
    } else {
        (io_objects, Ok((n_second, n_first)))
    }
}

/// Defines an asynchronous data transfer operation.
///
/// This trait allows callers to encapsulate custom transfer logic and state
/// (such as I/O streams, modes, and configuration parameters) into a single
/// object. It abstracts the underlying copy mechanism, enabling custom
/// transfer implementations to be driven by higher-level concurrent functions
/// like [`transfer_spawn_join`] and [`transfer_spawn_try_join`].
pub trait Transfer {
    /// The specific error type returned by the underlying transfer implementation.
    type Error;

    /// Executes the data transfer asynchronously.
    ///
    /// # Returns
    ///
    /// A future that resolves to:
    /// * `Ok(usize)`: The total number of bytes successfully transferred.
    /// * `Err(TransferError<Self::Error>)`: An error encountered during the transfer,
    ///   wrapping the associated `Error` type.
    fn transfer(
        &mut self,
    ) -> impl Future<Output = Result<usize, TransferError<Self::Error>>> + Send;
}

struct Copier<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    reader: R,
    writer: W,
    mode: TransferMode,
    error_on_eof: Option<io::Error>,
}

impl<R, W> Copier<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub fn new(reader: R, writer: W, mode: TransferMode, error_on_eof: Option<io::Error>) -> Self {
        Self {
            reader,
            writer,
            mode,
            error_on_eof,
        }
    }

    pub fn into_inner(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

impl<R, W> Transfer for Copier<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    type Error = CopyError;

    async fn transfer(&mut self) -> Result<usize, TransferError<Self::Error>> {
        copy(&mut self.reader, &mut self.writer, self.error_on_eof.take())
            .await
            .map_err(|e| e.map_err_mode(self.mode))
    }
}

fn io_from_copiers<AppR, AppW, NetR, NetW>(
    copiers: (Copier<AppR, NetW>, Copier<NetR, AppW>),
) -> (AppR, AppW, NetR, NetW)
where
    AppR: AsyncRead + Unpin + Send,
    AppW: AsyncWrite + Unpin + Send,
    NetR: AsyncRead + Unpin + Send,
    NetW: AsyncWrite + Unpin + Send,
{
    let (app_to_net, net_to_app) = copiers;
    let (app_reader, net_writer) = app_to_net.into_inner();
    let (net_reader, app_writer) = net_to_app.into_inner();
    (app_reader, app_writer, net_reader, net_writer)
}

fn copiers_from_io<AppR, AppW, NetR, NetW>(
    app_reader: AppR,
    app_writer: AppW,
    net_reader: NetR,
    net_writer: NetW,
    error_on_app_eof: Option<io::Error>,
    error_on_net_eof: Option<io::Error>,
) -> (Copier<AppR, NetW>, Copier<NetR, AppW>)
where
    AppR: AsyncRead + Unpin + Send,
    AppW: AsyncWrite + Unpin + Send,
    NetR: AsyncRead + Unpin + Send,
    NetW: AsyncWrite + Unpin + Send,
{
    let app_to_net = Copier::new(
        app_reader,
        net_writer,
        TransferMode::ApplicationToNetwork,
        error_on_app_eof,
    );

    let net_to_app = Copier::new(
        net_reader,
        app_writer,
        TransferMode::NetworkToApplication,
        error_on_net_eof,
    );

    (app_to_net, net_to_app)
}

struct RecoveryGuard<T> {
    inner: Option<T>,
    sender: Option<oneshot::Sender<T>>,
}

impl<T> Drop for RecoveryGuard<T> {
    fn drop(&mut self) {
        // If inner is still here when task dropped (aborted/failed), send it back.
        if let (Some(inner), Some(sender)) = (self.inner.take(), self.sender.take()) {
            let _ = sender.send(inner);
        }
    }
}

fn transfer_spawn_recoverable<T>(
    set: &mut JoinSet<Result<usize, TransferError<T::Error>>>,
    transfer: T,
) -> (AbortHandle, oneshot::Receiver<T>)
where
    T: Transfer + Send + 'static,
    <T as Transfer>::Error: Send,
{
    let (tx, rx) = oneshot::channel();

    let handle = set.spawn(async move {
        let mut guard = RecoveryGuard {
            inner: Some(transfer),
            sender: Some(tx),
        };
        let inner = guard.inner.as_mut().unwrap();
        inner.transfer().await
    });

    (handle, rx)
}

async fn transfer_spawn_join_inner<T, U>(
    app_to_net: T,
    net_to_app: U,
    abort_on_error: bool,
) -> (
    (T, U),
    (TransferMode, Result<usize, TransferError<T::Error>>),
    (TransferMode, Result<usize, TransferError<T::Error>>),
)
where
    T: Transfer + Send + 'static,
    <T as Transfer>::Error: Send,
    U: Transfer + Send + 'static,
    U: Transfer<Error = T::Error>,
    <U as Transfer>::Error: Send,
{
    // Spawn transfer tasks, one per direction.
    let mut set = JoinSet::new();

    let (app_net_handle, mut app_net_rx) = transfer_spawn_recoverable(&mut set, app_to_net);
    let (net_app_handle, mut net_app_rx) = transfer_spawn_recoverable(&mut set, net_to_app);

    let (app_net_id, net_app_id) = (app_net_handle.id(), net_app_handle.id());

    // Collect results as they finish.
    let mut first = None;
    let mut second = None;

    while let Some(join_res) = set.join_next_with_id().await {
        let (id, task_res) = match join_res {
            Ok((id, task_res)) => (id, task_res),
            Err(join_err) => (join_err.id(), Err(TransferError::Unfinished(join_err))),
        };

        if task_res.is_err() && abort_on_error {
            set.abort_all();
        }

        let mode = if id == net_app_id {
            TransferMode::NetworkToApplication
        } else if id == app_net_id {
            TransferMode::ApplicationToNetwork
        } else {
            // Will likely cause panic on return.
            log::error!("Unknown task {id}, expected {net_app_id} or {app_net_id}");
            continue;
        };

        if first.is_none() {
            first = Some((mode, task_res))
        } else if second.is_none() {
            second = Some((mode, task_res))
        } else {
            log::error!("Too many tasks, expected only two");
        }
    }

    // Recover objects (guaranteed by RecoveryGuard drop).
    let app_to_net = app_net_rx.try_recv().unwrap();
    let net_to_app = net_app_rx.try_recv().unwrap();

    // Return results.
    let io_objects = (app_to_net, net_to_app);
    (io_objects, first.unwrap(), second.unwrap())
}

#[cfg(test)]
mod tests {
    use std::io;

    use tokio_test::io::{Builder, Mock};

    use super::*;

    fn mock_both_success() -> (Mock, Mock, Mock, Mock) {
        (
            Builder::new().read(b"a").build(),
            Builder::new().write(b"n").build(),
            Builder::new().read(b"n").build(),
            Builder::new().write(b"a").build(),
        )
    }

    fn mock_one_error() -> (Mock, Mock, Mock, Mock) {
        (
            Builder::new().read_error(io::Error::other("err")).build(),
            Builder::new().write(b"n").build(),
            Builder::new().read(b"n").build(),
            Builder::new().build(),
        )
    }

    fn mock_both_error() -> (Mock, Mock, Mock, Mock) {
        (
            Builder::new().read_error(io::Error::other("err")).build(),
            Builder::new().build(),
            Builder::new().read_error(io::Error::other("err")).build(),
            Builder::new().build(),
        )
    }

    fn mock_eofs() -> (Mock, Mock, Mock, Mock) {
        (
            Builder::new().build(),
            Builder::new().build(),
            Builder::new().build(),
            Builder::new().build(),
        )
    }

    // copy_join

    #[tokio::test]
    async fn test_copy_join_success() {
        let (ar, aw, nr, nw) = mock_both_success();
        let (r1, r2) = copy_join(ar, aw, nr, nw, None, None).await;
        assert!(r1.is_ok() && r2.is_ok());
    }

    #[tokio::test]
    async fn test_copy_join_one_error() {
        let (ar, aw, nr, nw) = mock_one_error();
        let (r1, r2) = copy_join(ar, aw, nr, nw, None, None).await;
        assert!(r1.is_ok() && r2.is_err());
    }

    #[tokio::test]
    async fn test_copy_join_both_errors() {
        let (ar, aw, nr, nw) = mock_both_error();
        let (r1, r2) = copy_join(ar, aw, nr, nw, None, None).await;
        assert!(r1.is_err() && r2.is_err());
    }

    #[tokio::test]
    async fn test_copy_join_eof_error() {
        let (ar, aw, nr, nw) = mock_eofs();
        let net_eof_err = Some(io::ErrorKind::UnexpectedEof.into());
        let (r1, r2) = copy_join(ar, aw, nr, nw, None, net_eof_err).await;
        assert!(r1.is_err() && r2.is_ok());
    }

    // copy_try_join

    #[tokio::test]
    async fn test_copy_try_join_success() {
        let (ar, aw, nr, nw) = mock_both_success();
        let res = copy_try_join(ar, aw, nr, nw, None, None).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_copy_try_join_one_error() {
        let (ar, aw, nr, nw) = mock_one_error();
        let res = copy_try_join(ar, aw, nr, nw, None, None).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_copy_try_join_both_errors() {
        let (ar, aw, nr, nw) = mock_both_error();
        let res = copy_try_join(ar, aw, nr, nw, None, None).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_copy_try_join_eof_error() {
        let (ar, aw, nr, nw) = mock_eofs();
        let net_eof_err = Some(io::ErrorKind::UnexpectedEof.into());
        let res = copy_try_join(ar, aw, nr, nw, None, net_eof_err).await;
        assert!(res.is_err());
    }

    // copy_spawn_join

    #[tokio::test]
    async fn test_copy_spawn_join_success() {
        let (ar, aw, nr, nw) = mock_both_success();
        let (_, r1, r2) = copy_spawn_join(ar, aw, nr, nw, None, None).await;
        assert!(r1.is_ok() && r2.is_ok());
    }

    #[tokio::test]
    async fn test_copy_spawn_join_one_error() {
        let (ar, aw, nr, nw) = mock_one_error();
        let (_, r1, r2) = copy_spawn_join(ar, aw, nr, nw, None, None).await;
        assert!(r1.is_ok() && r2.is_err());
    }

    #[tokio::test]
    async fn test_copy_spawn_join_both_errors() {
        let (ar, aw, nr, nw) = mock_both_error();
        let (_, r1, r2) = copy_spawn_join(ar, aw, nr, nw, None, None).await;
        assert!(r1.is_err() && r2.is_err());
    }

    #[tokio::test]
    async fn test_copy_spawn_join_eof_error() {
        let (ar, aw, nr, nw) = mock_eofs();
        let net_eof_err = Some(io::ErrorKind::UnexpectedEof.into());
        let (_, r1, r2) = copy_spawn_join(ar, aw, nr, nw, None, net_eof_err).await;
        assert!(r1.is_err() && r2.is_ok());
    }

    // copy_spawn_try_join

    #[tokio::test]
    async fn test_copy_spawn_try_join_success() {
        let (ar, aw, nr, nw) = mock_both_success();
        let (_, res) = copy_spawn_try_join(ar, aw, nr, nw, None, None).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_copy_spawn_try_join_one_error() {
        let (ar, aw, nr, nw) = mock_one_error();
        let (_, res) = copy_spawn_try_join(ar, aw, nr, nw, None, None).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_copy_spawn_try_join_both_errors() {
        let (ar, aw, nr, nw) = mock_both_error();
        let (_, res) = copy_spawn_try_join(ar, aw, nr, nw, None, None).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_copy_spawn_try_join_eof_error() {
        let (ar, aw, nr, nw) = mock_eofs();
        let net_eof_err = Some(io::ErrorKind::UnexpectedEof.into());
        let (_, res) = copy_spawn_try_join(ar, aw, nr, nw, None, net_eof_err).await;
        assert!(res.is_err());
    }

    // transfer_join

    #[tokio::test]
    async fn test_transfer_join_success() {
        let (ar, aw, nr, nw) = mock_both_success();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let (r1, r2) = transfer_join(app_to_net, net_to_app).await;
        assert!(r1.is_ok() && r2.is_ok());
    }

    #[tokio::test]
    async fn test_transfer_join_one_error() {
        let (ar, aw, nr, nw) = mock_one_error();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let (r1, r2) = transfer_join(app_to_net, net_to_app).await;
        assert!(r1.is_ok() && r2.is_err());
    }

    #[tokio::test]
    async fn test_transfer_join_both_errors() {
        let (ar, aw, nr, nw) = mock_both_error();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let (r1, r2) = transfer_join(app_to_net, net_to_app).await;
        assert!(r1.is_err() && r2.is_err());
    }

    #[tokio::test]
    async fn test_transfer_join_eof_error() {
        let (ar, aw, nr, nw) = mock_eofs();
        let net_eof_err = Some(io::ErrorKind::UnexpectedEof.into());
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, net_eof_err);
        let (r1, r2) = transfer_join(app_to_net, net_to_app).await;
        assert!(r1.is_err() && r2.is_ok());
    }

    // transfer_try_join

    #[tokio::test]
    async fn test_transfer_try_join_success() {
        let (ar, aw, nr, nw) = mock_both_success();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let res = transfer_try_join(app_to_net, net_to_app).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_transfer_try_join_one_error() {
        let (ar, aw, nr, nw) = mock_one_error();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let res = transfer_try_join(app_to_net, net_to_app).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_transfer_try_join_both_errors() {
        let (ar, aw, nr, nw) = mock_both_error();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let res = transfer_try_join(app_to_net, net_to_app).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_transfer_try_join_eof_error() {
        let (ar, aw, nr, nw) = mock_eofs();
        let net_eof_err = Some(io::ErrorKind::UnexpectedEof.into());
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, net_eof_err);
        let res = transfer_try_join(app_to_net, net_to_app).await;
        assert!(res.is_err());
    }

    // transfer_spawn_join

    #[tokio::test]
    async fn test_transfer_spawn_join_success() {
        let (ar, aw, nr, nw) = mock_both_success();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let (_, r1, r2) = transfer_spawn_join(app_to_net, net_to_app).await;
        assert!(r1.is_ok() && r2.is_ok());
    }

    #[tokio::test]
    async fn test_transfer_spawn_join_one_error() {
        let (ar, aw, nr, nw) = mock_one_error();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let (_, r1, r2) = transfer_spawn_join(app_to_net, net_to_app).await;
        assert!(r1.is_ok() && r2.is_err());
    }

    #[tokio::test]
    async fn test_transfer_spawn_join_both_errors() {
        let (ar, aw, nr, nw) = mock_both_error();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let (_, r1, r2) = transfer_spawn_join(app_to_net, net_to_app).await;
        assert!(r1.is_err() && r2.is_err());
    }

    #[tokio::test]
    async fn test_transfer_spawn_join_eof_error() {
        let (ar, aw, nr, nw) = mock_eofs();
        let net_eof_err = Some(io::ErrorKind::UnexpectedEof.into());
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, net_eof_err);
        let (_, r1, r2) = transfer_spawn_join(app_to_net, net_to_app).await;
        assert!(r1.is_err() && r2.is_ok());
    }

    // transfer_spawn_try_join

    #[tokio::test]
    async fn test_transfer_spawn_try_join_success() {
        let (ar, aw, nr, nw) = mock_both_success();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let (_, res) = transfer_spawn_try_join(app_to_net, net_to_app).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_transfer_spawn_try_join_one_error() {
        let (ar, aw, nr, nw) = mock_one_error();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let (_, res) = transfer_spawn_try_join(app_to_net, net_to_app).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_transfer_spawn_try_join_both_errors() {
        let (ar, aw, nr, nw) = mock_both_error();
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, None);
        let (_, res) = transfer_spawn_try_join(app_to_net, net_to_app).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_transfer_spawn_try_join_eof_error() {
        let (ar, aw, nr, nw) = mock_eofs();
        let net_eof_err = Some(io::ErrorKind::UnexpectedEof.into());
        let (app_to_net, net_to_app) = copiers_from_io(ar, aw, nr, nw, None, net_eof_err);
        let (_, res) = transfer_spawn_try_join(app_to_net, net_to_app).await;
        assert!(res.is_err());
    }
}
