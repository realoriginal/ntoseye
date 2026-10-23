//! Handing the transport to the background pump while the target runs, and
//! taking it back when the target stops or the foreground needs the socket.

use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, mpsc};
use std::thread::spawn;
use std::time::{Duration, Instant};

use crate::backend::kd::framing::BREAKIN_BYTE;
use crate::base::error::{Error, Result};

use super::transport::KdTransport;
use super::{
    ContinueDrain, KdBackend, Link, PUMP_POLL, PumpHandle, PumpLink, StateChange, run_pump,
};

const SERIAL_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct SerialRecovery {
    path: PathBuf,
    pub(super) deadline: Instant,
    next_attempt: Instant,
}

impl KdBackend {
    /// Hand the framing to a freshly spawned background pump. The target has
    /// just been resumed (see [`record_running`]), so the link is inline.
    pub(super) fn start_pump(
        &mut self,
        reconnect_assist_delay: Option<Duration>,
        drain: Option<ContinueDrain>,
    ) -> Result<()> {
        let framing = match std::mem::replace(&mut self.link, Link::Lost) {
            Link::RunningInline(framing) => framing,
            other => {
                self.link = other;
                return Err(Error::Kd(
                    "cannot start KD pump: target is not resuming".into(),
                ));
            }
        };
        let (stop_tx, stop_rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let pump_shutdown = Arc::clone(&shutdown);
        let reported_stop = Arc::new(AtomicBool::new(false));
        let pump_reported_stop = Arc::clone(&reported_stop);
        let pump_debug_log = self.debug_log.clone();
        let arch = self.arch;
        let bugcheck = std::mem::take(&mut self.pump_bugcheck);
        let breakin_requested = drain
            .as_ref()
            .map(ContinueDrain::interrupt_flag)
            .unwrap_or_default();
        let join = spawn(move || {
            run_pump(
                framing,
                arch,
                PumpLink {
                    stop_tx,
                    shutdown: pump_shutdown,
                    reported_stop: pump_reported_stop,
                },
                reconnect_assist_delay,
                pump_debug_log,
                drain,
                bugcheck,
            )
        });
        kd_trace!("kd: pump: spawned background servicing thread");
        self.link.run_pumped(
            PumpHandle {
                join,
                stop_rx,
                shutdown,
                reported_stop,
                breakin_requested,
            },
            &mut self.registers,
        );
        Ok(())
    }

    /// Join the pump thread and take back ownership of the framing
    pub(super) fn reclaim_framing(&mut self) {
        if let Some(pump) = self.link.take_pump() {
            match pump.join.join() {
                // Whoever asked for the framing back also consumes the stop,
                // if there was one, and records it; until then the target is
                // still running.
                Ok(result) => {
                    self.link = Link::RunningInline(result.framing);
                    self.pump_bugcheck = result.bugcheck;
                }
                Err(_) => {
                    // The pump panicked; the framing (and socket) is lost. The
                    // next foreground op surfaces this as a transport error
                    kd_trace!("kd: pump: thread panicked, framing lost");
                }
            }
        }
    }

    /// Start recovery only after a disconnected, named serial stream. The old
    /// framing stays intact: reopening is not a new KD session or a replay.
    pub(super) fn begin_serial_recovery(&mut self, error: &Error) -> Result<bool> {
        if !matches!(error, Error::Io(error) if matches!(error.kind(),
            ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
        )) {
            return Ok(false);
        }
        let Some(path) = self.framing()?.transport_mut().serial_path()? else {
            return Ok(false);
        };
        if self.serial_recovery.is_none() {
            let now = Instant::now();
            self.serial_recovery = Some(SerialRecovery {
                path,
                deadline: now + SERIAL_RECOVERY_TIMEOUT,
                next_attempt: now,
            });
            self.record_running();
            self.efer_cache.clear();
            kd_trace!("kd: serial disconnected; retrying the existing session for up to 30s");
        }
        Ok(true)
    }

    /// Retry within one caller's poll budget, leaving longer waits and their
    /// cancellation to the existing run driver.
    pub(super) fn recover_serial(&mut self, budget: Duration) -> Result<()> {
        let poll_deadline = Instant::now() + budget;
        while let Some(recovery) = &mut self.serial_recovery {
            let now = Instant::now();
            if now >= recovery.deadline {
                let message = format!(
                    "serial connection recovery timed out after 30s waiting for {}; the session is retained",
                    recovery.path.display()
                );
                self.serial_recovery = None;
                return Err(Error::Kd(message));
            }
            if now < recovery.next_attempt {
                let wait_until = recovery
                    .next_attempt
                    .min(poll_deadline)
                    .min(recovery.deadline);
                std::thread::sleep(wait_until.saturating_duration_since(now));
                if Instant::now() >= poll_deadline {
                    return Ok(());
                }
                continue;
            }
            recovery.next_attempt = now + PUMP_POLL;
            match KdTransport::reopen_serial(&recovery.path) {
                Ok(transport) => {
                    let breakin_clone = transport.try_clone()?;
                    *self.framing()?.transport_mut() = transport;
                    self.breakin_clone = breakin_clone;
                    self.serial_recovery = None;
                    self.serial_reconnected = true;
                    kd_trace!("kd: serial connection restored; continuing the existing wait");
                    // A running guest needs no break-in. A stopped one retransmits
                    // its state change; neither case warrants RESET or continue.
                    self.start_pump(None, None)?;
                    return Ok(());
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::NotFound
                            | ErrorKind::ConnectionRefused
                            | ErrorKind::WouldBlock
                            | ErrorKind::TimedOut
                            | ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= poll_deadline {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Wait for the pump to report a stop. `wait` bounds a non-blocking poll;
    /// `None` blocks until the pump produces a stop. On a stop (or pump error)
    /// the framing is reclaimed and the pump handle dropped
    pub(super) fn take_pump_stop(&mut self, wait: Option<Duration>) -> Result<Option<StateChange>> {
        let Link::RunningPumped(pump) = &self.link else {
            return Ok(None);
        };
        let received = match wait {
            None => pump
                .stop_rx
                .recv()
                .map_err(|_| RecvTimeoutError::Disconnected),
            Some(timeout) => pump.stop_rx.recv_timeout(timeout),
        };
        match received {
            Ok(result) => {
                self.reclaim_framing();
                result.map(Some)
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                self.reclaim_framing();
                Err(Error::Kd("KD pump exited without reporting a stop".into()))
            }
        }
    }

    fn try_recv_pump_stop(
        stop_rx: &mpsc::Receiver<Result<StateChange>>,
    ) -> Result<Option<StateChange>> {
        match stop_rx.try_recv() {
            Ok(Ok(stop)) => Ok(Some(stop)),
            Ok(Err(error)) => Err(error),
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => Ok(None),
        }
    }

    /// Stop the pump and return a stop it reported during shutdown, if any.
    pub(super) fn shutdown_pump_with_stop(&mut self) -> Result<Option<StateChange>> {
        let Some(pump) = self.link.take_pump() else {
            return Ok(None);
        };
        let PumpHandle {
            join,
            stop_rx,
            shutdown,
            reported_stop: _,
            breakin_requested: _,
        } = pump;
        shutdown.store(true, Ordering::SeqCst);
        // A reported error still leaves framing in the join value. Reclaim it
        // before propagating that error, just as we do for a successful stop.
        let stop = Self::try_recv_pump_stop(&stop_rx);
        match join.join() {
            Ok(result) => {
                self.link = Link::RunningInline(result.framing);
                self.pump_bugcheck = result.bugcheck;
            }
            Err(_) => {
                kd_trace!("kd: pump: thread panicked during shutdown, framing lost");
                if matches!(stop, Ok(None)) {
                    return Err(Error::Kd("KD pump thread panicked during shutdown".into()));
                }
            }
        }
        let stop = stop?;
        if stop.is_some() {
            return Ok(stop);
        }
        Self::try_recv_pump_stop(&stop_rx)
    }

    /// Send an unframed break-in byte over the cloned socket fd. Safe to call
    /// while the pump owns the framing for reading
    pub(super) fn send_raw_breakin(&mut self) -> Result<()> {
        self.breakin_clone.write_all(&[BREAKIN_BYTE])?;
        self.breakin_clone.flush()?;
        Ok(())
    }
}
