//! Serial reconnection must repair the transport, not restart the KD session.

use super::*;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread::{self, spawn};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::backend::kd::event_loop::{PumpBugcheck, PumpResult};
use crate::backend::kd::framing::{
    BREAKIN_BYTE, PACKET_TYPE_KD_DEBUG_IO, PACKET_TYPE_KD_STATE_CHANGE64, SYNC_PACKET_ID,
};
use crate::session::tests::{MockBackend, session_with_mock};
use crate::session::{Cancel, CancelBehavior, Motion, RunOutcome, Session};

const FIXTURE_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_TIMEOUT: Duration = Duration::from_millis(40);

struct SerialFixture {
    directory: PathBuf,
    path: PathBuf,
    listener: Option<UnixListener>,
}

impl SerialFixture {
    fn connected() -> (Self, KdBackend, UnixStream) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "ntoseye-kd-recovery-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut fixture = Self {
            path: directory.join("serial.sock"),
            directory,
            listener: None,
        };
        fixture.listen();
        let host = UnixStream::connect(&fixture.path).unwrap();
        let kernel = fixture.accept();
        let mut backend = kd_backend_with_framing(host);
        // Even a failed assertion must not perform protocol I/O from Drop.
        backend.exit_prepared = true;
        (fixture, backend, kernel)
    }

    fn listen(&mut self) {
        assert!(self.listener.is_none());
        let listener = UnixListener::bind(&self.path).unwrap();
        listener.set_nonblocking(true).unwrap();
        self.listener = Some(listener);
    }

    fn disconnect_listener(&mut self, remove_path: bool) {
        drop(self.listener.take());
        if remove_path {
            std::fs::remove_file(&self.path).unwrap();
        }
    }

    fn accept(&self) -> UnixStream {
        let deadline = Instant::now() + FIXTURE_TIMEOUT;
        loop {
            match self.listener.as_ref().unwrap().accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
                    stream.set_write_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "serial reconnect never arrived");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("serial accept failed: {error}"),
            }
        }
    }

    fn accept_while_polling(&self, backend: &mut dyn DebugBackend) -> UnixStream {
        let deadline = Instant::now() + FIXTURE_TIMEOUT;
        loop {
            match self.listener.as_ref().unwrap().accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
                    stream.set_write_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    assert!(!remaining.is_zero(), "serial reconnect never arrived");
                    // Retry cadence belongs to the backend, so keep driving it
                    // instead of waiting for an accept after a single short poll.
                    assert!(
                        backend
                            .try_wait_for_stop(POLL_TIMEOUT.min(remaining))
                            .unwrap()
                            .is_none()
                    );
                    assert!(backend.is_running());
                }
                Err(error) => panic!("serial accept failed: {error}"),
            }
        }
    }

    fn assert_no_connection(&self) {
        assert!(
            matches!(
                self.listener.as_ref().unwrap().accept(),
                Err(error) if error.kind() == ErrorKind::WouldBlock
            ),
            "exit must not reopen the serial socket"
        );
    }
}

impl Drop for SerialFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn assert_quiet(kernel: &mut UnixStream) {
    kernel
        .set_read_timeout(Some(Duration::from_millis(25)))
        .unwrap();
    let result = kernel.read(&mut [0u8; 1]);
    assert!(
        matches!(result, Err(ref error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)),
        "reconnection must not send RESET, BREAKIN, continue, or any other unsolicited byte: {result:?}"
    );
    kernel.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
}

fn send_exception(kernel: &mut UnixStream, packet_id: u32, pc: u64) {
    kernel
        .write_all(&data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            packet_id,
            &exception_state_change_payload(pc),
        ))
        .unwrap();
}

fn assert_ack(kernel: &mut UnixStream, packet_id: u32) {
    let packet = read_wire_packet(kernel);
    let header = wire_header(&packet);
    assert!(!header.is_data());
    assert_eq!(header.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
    assert_eq!(header.packet_id, packet_id);
}

#[test]
fn serial_recovery_waits_for_the_listener_without_interrupting_the_run() {
    const PC: u64 = 0xffff_f800_0011_2233;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    backend.bp_handles.insert(PC, 7);
    backend.managed_bp_addresses.insert(PC);
    backend.start_pump(None, None).unwrap();
    fixture.disconnect_listener(true);
    drop(kernel);

    let started = Instant::now();
    let result = backend.try_wait_for_stop(Duration::from_millis(30));
    assert!(matches!(result, Ok(None)), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(backend.is_running());

    fixture.listen();
    let mut kernel = fixture.accept_while_polling(&mut backend);
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID, PC);
    let stop = backend.try_wait_for_stop(FIXTURE_TIMEOUT).unwrap().unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert!(!stop.assisted_breakin);
    assert!(!stop.target_reloaded);
    assert!(!backend.is_running());
    assert_eq!(backend.bp_handles.get(&PC), Some(&7));
    assert!(backend.managed_bp_addresses.contains(&PC));
}

#[test]
fn blocking_wait_reconnects_and_surfaces_a_fresh_exception_at_a_known_breakin_pc() {
    const PC: u64 = 0xffff_f800_0011_2233;
    const BP: u64 = 0xffff_f800_0090_0000;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    backend.breakin_addresses.insert(PC);
    backend.late_breakin = true;
    backend.bp_handles.insert(BP, 7);
    backend.managed_bp_addresses.insert(BP);
    backend.start_pump(None, None).unwrap();
    fixture.disconnect_listener(true);
    drop(kernel);

    let (tx, rx) = mpsc::channel();
    let waiter = spawn(move || {
        let result = backend.wait_for_stop();
        tx.send((backend, result)).unwrap();
    });
    // The blocking facade must keep polling while the named socket is absent.
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(150)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    fixture.listen();
    let mut kernel = fixture.accept();
    assert_quiet(&mut kernel);
    // Lose the replacement too: the same blocking wait must recover again
    // without a second host command or a protocol reset.
    fixture.disconnect_listener(true);
    drop(kernel);
    assert!(matches!(
        rx.recv_timeout(POLL_TIMEOUT),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    fixture.listen();
    let mut kernel = fixture.accept();
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID, PC);

    let (backend, result) = rx
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("blocking wait did not report the recovered stop");
    waiter.join().unwrap();
    let stop = result.unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert!(
        !stop.assisted_breakin,
        "a transport repair is not a break-in"
    );
    assert!(!stop.target_reloaded);
    assert!(!backend.is_running());
    assert_eq!(backend.bp_handles.get(&BP), Some(&7));
    assert!(backend.managed_bp_addresses.contains(&BP));
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
    assert_quiet(&mut kernel);
}

#[test]
fn regression_session_run_status_returns_promptly_for_a_queued_serial_eof() {
    const PC: u64 = 0x1080;
    const ACCESS_VIOLATION: u32 = 0xc000_0005;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    backend.start_pump(None, None).unwrap();
    fixture.disconnect_listener(true);
    drop(kernel);
    let deadline = Instant::now() + FIXTURE_TIMEOUT;
    while !backend.has_pending_stop() {
        assert!(Instant::now() < deadline, "pump did not queue serial EOF");
        thread::sleep(Duration::from_millis(2));
    }

    let (status_tx, status_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = spawn(move || {
        // Session owns non-Send host hooks, so construct it in its worker.
        let mut session = session_with_mock(MockBackend::default());
        session.register_map = backend.register_map().clone();
        session.backend = Box::new(backend);
        let status = session.run_status();
        status_tx
            .send((
                status.running,
                session.backend.is_running(),
                session.stop_pending(),
            ))
            .unwrap();

        fixture.listen();
        let mut kernel = fixture.accept_while_polling(session.backend.as_mut());
        assert_quiet(&mut kernel);
        // An access violation is an ordinary stop without requiring an int3
        // in the separate Session fixture's zero-filled code image.
        let mut payload = exception_state_change_payload(PC);
        bytes::write_u32(&mut payload, 32, ACCESS_VIOLATION);
        kernel
            .write_all(&data_packet(
                PACKET_TYPE_KD_STATE_CHANGE64,
                INITIAL_PACKET_ID,
                &payload,
            ))
            .unwrap();
        let deadline = Instant::now() + FIXTURE_TIMEOUT;
        while !session.backend.has_pending_stop() {
            assert!(
                Instant::now() < deadline,
                "pump did not queue the recovered stop"
            );
            thread::sleep(Duration::from_millis(2));
        }
        assert_ack(&mut kernel, INITIAL_PACKET_ID);

        // Settling can issue follow-on queries while selecting the stopped
        // context. Answer the actual APIs, not a speculative reply sequence.
        let target = spawn(move || {
            let deadline = Instant::now() + FIXTURE_TIMEOUT;
            let mut remote_id = INITIAL_PACKET_ID ^ 1;
            let mut context = vec![0u8; amd64::CONTEXT_SIZE];
            amd64::build_register_map()
                .write_u64("rip", &mut context, PC)
                .unwrap();
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(
                    !remaining.is_zero(),
                    "stop-settling target exceeded its deadline"
                );
                kernel.set_read_timeout(Some(remaining)).unwrap();
                kernel.set_write_timeout(Some(remaining)).unwrap();
                let packet = match try_read_wire_packet(&mut kernel) {
                    Ok(packet) => packet,
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => return,
                    Err(error) => panic!("reading stop-settling request: {error}"),
                };
                let header = wire_header(&packet);
                if !header.is_data() {
                    continue;
                }
                assert_eq!(header.packet_type, PACKET_TYPE_KD_STATE_MANIPULATE);
                let request = &packet[HEADER_SIZE..packet.len() - 1];
                let api_number = bytes::read_u32(request, 0);
                let processor = bytes::read_u16(request, 6);
                kernel
                    .write_all(&control_packet(
                        PACKET_TYPE_KD_ACKNOWLEDGE,
                        header.packet_id,
                    ))
                    .unwrap();
                let reply = match api_number {
                    api::DBGKD_GET_CONTEXT => {
                        api::test_wire::build_reply(api_number, processor, &[], &context)
                    }
                    api::DBGKD_READ_CONTROL_SPACE => {
                        read_special_registers_reply_payload(processor)
                    }
                    api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER => {
                        let mut union = [0u8; 12];
                        union[..4].copy_from_slice(&request[16..20]);
                        api::test_wire::build_reply(api_number, processor, &union, &[])
                    }
                    _ => panic!("unexpected stop-settling API {api_number:#x}"),
                };
                kernel
                    .write_all(&data_packet(
                        PACKET_TYPE_KD_STATE_MANIPULATE,
                        remote_id,
                        &reply,
                    ))
                    .unwrap();
                remote_id ^= 1;
            }
        });
        session.settle_pending_stop().unwrap();
        assert!(!session.backend.is_running());
        assert!(!session.backend.has_pending_stop());
        assert!(
            session.stop_pending(),
            "the recovered ordinary stop must be parked"
        );
        let event = &session.last_event.as_ref().unwrap().stop;
        assert_eq!(event.program_counter, Some(PC));
        assert_eq!(event.exception_code, Some(ACCESS_VIOLATION));
        assert!(!event.target_reloaded);
        assert!(!event.assisted_breakin);
        assert!(!event.is_bugcheck);
        // Closing the host stream releases the responder's bounded read.
        drop(session);
        target.join().unwrap();
        done_tx.send(()).unwrap();
    });

    // On the broken path this fails promptly instead of joining the worker
    // blocked in the 30s recovery budget. Its backend suppresses Drop I/O.
    let (status_running, backend_running, stop_pending) = status_rx
        .recv_timeout(Duration::from_millis(500))
        .expect("run_status blocked on queued serial EOF instead of returning within 500ms");
    assert!(status_running);
    assert!(backend_running);
    assert!(!stop_pending, "serial EOF is not an ordinary target stop");
    done_rx.recv_timeout(FIXTURE_TIMEOUT).unwrap();
    worker.join().unwrap();
}

#[test]
fn session_wait_deadlines_return_running_and_retain_real_serial_recovery() {
    const PC: u64 = 0xffff_f800_00aa_1000;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    backend.start_pump(None, None).unwrap();
    fixture.disconnect_listener(true);
    drop(kernel);
    let mut session = session_with_mock(MockBackend::default());
    session.backend = Box::new(backend);

    for _ in 0..2 {
        let started = Instant::now();
        let outcome = session
            .run(Motion::Wait, &Cancel::within(Duration::from_millis(40)))
            .unwrap();
        assert!(matches!(outcome, RunOutcome::Running), "{outcome:?}");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the Session deadline must not wait for the serial recovery budget"
        );
        assert!(session.backend.is_running());
    }

    // Both waits handed back a live session, not a failed or halted target.
    // Complete that retained recovery without sending a resume or break-in.
    fixture.listen();
    let mut kernel = fixture.accept_while_polling(session.backend.as_mut());
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID, PC);
    let stop = session
        .backend
        .try_wait_for_stop(FIXTURE_TIMEOUT)
        .unwrap()
        .unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert!(!stop.assisted_breakin);
    assert!(!stop.target_reloaded);
    assert!(!session.backend.is_running());
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
    assert_quiet(&mut kernel);
}

#[test]
fn session_wait_observes_a_cross_thread_return_running_flag_after_one_recovery_poll() {
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    backend.start_pump(None, None).unwrap();
    fixture.disconnect_listener(true);
    drop(kernel);
    let mut session = session_with_mock(MockBackend::default());
    session.backend = Box::new(backend);
    let flag = Arc::new(AtomicBool::new(false));
    let ticks = AtomicU64::new(0);
    let (after_poll_tx, after_poll_rx) = mpsc::sync_channel(0);
    let (raised_tx, raised_rx) = mpsc::sync_channel(0);
    let canceller = {
        let flag = Arc::clone(&flag);
        spawn(move || {
            after_poll_rx.recv_timeout(FIXTURE_TIMEOUT).unwrap();
            flag.store(true, Ordering::SeqCst);
            raised_tx.send(()).unwrap();
        })
    };
    let tick = |_: &mut Session| {
        if ticks.fetch_add(1, Ordering::SeqCst) == 1 {
            // Tick two follows the first actual backend poll. Rendezvous
            // with the other thread so cancellation has no scheduling race.
            after_poll_tx.send(()).unwrap();
            raised_rx.recv_timeout(FIXTURE_TIMEOUT).unwrap();
        }
    };
    let cancel = Cancel {
        flag: Some(flag.as_ref()),
        deadline: Some(Instant::now() + FIXTURE_TIMEOUT),
        behavior: CancelBehavior::ReturnRunning,
        tick: Some(&tick),
    };

    let started = Instant::now();
    let outcome = session.run(Motion::Wait, &cancel).unwrap();
    assert!(matches!(outcome, RunOutcome::Running), "{outcome:?}");
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(flag.load(Ordering::SeqCst));
    assert_eq!(ticks.load(Ordering::SeqCst), 2);
    assert!(session.backend.is_running());
    canceller.join().unwrap();

    // ReturnRunning neither halts nor poisons the next host wait.
    let started = Instant::now();
    let outcome = session
        .run(Motion::Wait, &Cancel::within(Duration::from_millis(40)))
        .unwrap();
    assert!(matches!(outcome, RunOutcome::Running), "{outcome:?}");
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(session.backend.is_running());
    fixture.listen();
    let mut kernel = fixture.accept_while_polling(session.backend.as_mut());
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID, 0xffff_f800_00aa_2000);
    assert!(
        session
            .backend
            .try_wait_for_stop(FIXTURE_TIMEOUT)
            .unwrap()
            .is_some()
    );
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
}

#[test]
fn shared_backend_handle_polls_and_recovers_the_existing_serial_session() {
    const PC: u64 = 0xffff_f800_00aa_3000;
    const BP: u64 = 0xffff_f800_00bb_0000;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    backend.bp_handles.insert(BP, 23);
    backend.managed_bp_addresses.insert(BP);
    backend.start_pump(None, None).unwrap();
    let (mut handle, memory) = backend.into_remote_memory();
    fixture.disconnect_listener(true);
    drop(kernel);

    for _ in 0..2 {
        let started = Instant::now();
        assert!(handle.try_wait_for_stop(POLL_TIMEOUT).unwrap().is_none());
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(handle.is_running());
        assert!(memory.inner.lock().unwrap().link.is_running());
    }
    fixture.listen();
    let mut kernel = fixture.accept_while_polling(&mut handle);
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID, PC);
    let stop = handle.try_wait_for_stop(FIXTURE_TIMEOUT).unwrap().unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert!(!stop.assisted_breakin);
    assert!(!stop.target_reloaded);
    assert!(!handle.is_running());
    {
        let shared = memory.inner.lock().unwrap();
        assert!(!shared.link.is_running());
        assert_eq!(shared.bp_handles.get(&BP), Some(&23));
        assert!(shared.managed_bp_addresses.contains(&BP));
    }
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
    assert_quiet(&mut kernel);
}

#[test]
fn explicit_interrupt_reconnects_and_sends_breakin_on_the_new_stream() {
    const PC: u64 = 0xffff_f800_0022_3344;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    fixture.disconnect_listener(true);
    drop(kernel);
    fixture.listen();

    let target = spawn(move || {
        let mut kernel = fixture.accept();
        let mut byte = [0u8; 1];
        kernel.read_exact(&mut byte).unwrap();
        assert_eq!(
            byte,
            [BREAKIN_BYTE],
            "break-in must reach the replacement fd"
        );
        send_exception(&mut kernel, INITIAL_PACKET_ID, PC);
        assert_ack(&mut kernel, INITIAL_PACKET_ID);
        assert_quiet(&mut kernel);
    });
    let started = Instant::now();
    let stop = backend.interrupt().unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(stop.program_counter, Some(PC));
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert!(!backend.is_running());
    target.join().unwrap();
}

#[test]
fn interrupt_preserves_a_real_exception_that_races_the_reconnected_breakin() {
    const PC: u64 = 0xffff_f800_0033_4455;
    const ACCESS_VIOLATION: u32 = 0xc000_0005;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    fixture.disconnect_listener(true);
    drop(kernel);
    fixture.listen();

    let target = spawn(move || {
        let mut kernel = fixture.accept();
        let mut payload = exception_state_change_payload(PC);
        bytes::write_u32(&mut payload, 32, ACCESS_VIOLATION);
        // Queue a genuine stop before acknowledging any break-in on the new fd.
        kernel
            .write_all(&data_packet(
                PACKET_TYPE_KD_STATE_CHANGE64,
                INITIAL_PACKET_ID,
                &payload,
            ))
            .unwrap();
        let mut byte = [0u8; 1];
        kernel.read_exact(&mut byte).unwrap();
        if byte == [BREAKIN_BYTE] {
            assert_ack(&mut kernel, INITIAL_PACKET_ID);
        } else {
            let mut ack = vec![0u8; HEADER_SIZE];
            ack[0] = byte[0];
            kernel.read_exact(&mut ack[1..]).unwrap();
            assert_eq!(wire_header(&ack).packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
            assert_eq!(wire_header(&ack).packet_id, INITIAL_PACKET_ID);
        }
    });

    let stop = backend.interrupt().unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert_eq!(stop.exception_code, Some(ACCESS_VIOLATION));
    assert!(!stop.assisted_breakin);
    assert!(!stop.target_reloaded);
    assert!(!backend.is_running());
    target.join().unwrap();
}

#[test]
fn exit_does_not_reopen_a_disconnected_serial_socket() {
    for leave_running in [false, true] {
        let (mut fixture, mut backend, kernel) = SerialFixture::connected();
        fixture.disconnect_listener(true);
        drop(kernel);
        assert!(backend.try_wait_for_stop(POLL_TIMEOUT).unwrap().is_none());
        assert!(backend.is_running());
        fixture.listen();

        let started = Instant::now();
        // Cleanup is best effort; its error policy is separate from reopening.
        let _result = backend.prepare_for_exit(leave_running);
        assert!(started.elapsed() < Duration::from_secs(2));
        fixture.assert_no_connection();
        drop(backend);
        fixture.assert_no_connection();
    }
}

#[test]
fn an_expired_recovery_budget_allows_a_later_explicit_wait_to_retry() {
    const PC: u64 = 0xffff_f800_0077_8899;
    const BP: u64 = 0xffff_f800_0090_0000;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    backend.bp_handles.insert(BP, 17);
    backend.managed_bp_addresses.insert(BP);
    fixture.disconnect_listener(true);
    drop(kernel);
    assert!(backend.try_wait_for_stop(POLL_TIMEOUT).unwrap().is_none());
    backend.serial_recovery.as_mut().unwrap().deadline = Instant::now();

    let started = Instant::now();
    let error = backend.try_wait_for_stop(POLL_TIMEOUT).unwrap_err();
    assert!(
        matches!(&error, Error::Kd(message) if message.contains("timed out")),
        "recovery expiration must surface its timeout: {error:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(backend.is_running());
    assert_eq!(backend.bp_handles.get(&BP), Some(&17));
    assert!(backend.managed_bp_addresses.contains(&BP));

    fixture.listen();
    let (tx, rx) = mpsc::channel();
    let waiter = spawn(move || {
        let result = backend.wait_for_stop();
        tx.send((backend, result)).unwrap();
    });
    let mut kernel = fixture.accept();
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID, PC);
    let (backend, result) = rx.recv_timeout(FIXTURE_TIMEOUT).unwrap();
    waiter.join().unwrap();
    let stop = result.unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert!(!stop.assisted_breakin);
    assert!(!stop.target_reloaded);
    assert!(!backend.is_running());
    assert_eq!(backend.bp_handles.get(&BP), Some(&17));
    assert!(backend.managed_bp_addresses.contains(&BP));
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
    assert_quiet(&mut kernel);
}

#[test]
fn zero_duration_polls_remain_bounded_while_the_serial_socket_is_missing() {
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    fixture.disconnect_listener(true);
    drop(kernel);
    assert!(backend.try_wait_for_stop(POLL_TIMEOUT).unwrap().is_none());

    let started = Instant::now();
    for _ in 0..32 {
        assert!(backend.try_wait_for_stop(Duration::ZERO).unwrap().is_none());
        assert!(backend.is_running());
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "zero polls must not each sleep for a reconnect retry interval"
    );

    fixture.listen();
    let mut kernel = fixture.accept_while_polling(&mut backend);
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID, 0xffff_f800_0077_9900);
    assert!(
        backend
            .try_wait_for_stop(FIXTURE_TIMEOUT)
            .unwrap()
            .is_some()
    );
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
}

#[test]
fn interrupt_sends_only_one_breakin_when_the_reopened_connection_stays_silent() {
    const PC: u64 = 0xffff_f800_0077_aa00;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    fixture.disconnect_listener(true);
    drop(kernel);
    assert!(backend.try_wait_for_stop(POLL_TIMEOUT).unwrap().is_none());
    fixture.listen();
    let mut kernel = fixture.accept_while_polling(&mut backend);
    assert_quiet(&mut kernel);

    let target = spawn(move || {
        let mut byte = [0u8; 1];
        kernel.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [BREAKIN_BYTE]);
        kernel
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let started = Instant::now();
        let result = kernel.read(&mut byte);
        assert!(
            matches!(result, Err(ref error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)),
            "interrupt must not resend BREAKIN or any other byte while waiting: {result:?}"
        );
        assert!(started.elapsed() >= Duration::from_millis(250));
        kernel.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
        send_exception(&mut kernel, INITIAL_PACKET_ID, PC);
        assert_ack(&mut kernel, INITIAL_PACKET_ID);
        assert_quiet(&mut kernel);
    });

    let started = Instant::now();
    let stop = backend.interrupt().unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(stop.program_counter, Some(PC));
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert!(!stop.assisted_breakin);
    assert!(!backend.is_running());
    target.join().unwrap();
}

#[test]
fn a_pump_stop_reported_during_failed_writer_shutdown_wins_over_the_write_error() {
    const PC: u64 = 0xffff_f800_0077_bb00;
    const ACCESS_VIOLATION: u32 = 0xc000_0005;
    let (host, mut kernel) = UnixStream::pair().unwrap();
    let (writer, dead_peer) = UnixStream::pair().unwrap();
    drop(dead_peer);
    let (stop_tx, stop_rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let reported_stop = Arc::new(AtomicBool::new(false));
    let join = {
        let shutdown = Arc::clone(&shutdown);
        let reported_stop = Arc::clone(&reported_stop);
        spawn(move || {
            let deadline = Instant::now() + FIXTURE_TIMEOUT;
            while !shutdown.load(Ordering::SeqCst) {
                assert!(
                    Instant::now() < deadline,
                    "failed writer never shut down the pump"
                );
                thread::sleep(Duration::from_millis(2));
            }
            // The initial zero poll cannot see this stop. Only the shutdown
            // drain can preserve it after the cloned writer fails.
            let mut payload = exception_state_change_payload(PC);
            bytes::write_u32(&mut payload, 32, ACCESS_VIOLATION);
            stop_tx
                .send(Ok(parse_state_change(&payload).unwrap()))
                .unwrap();
            reported_stop.store(true, Ordering::SeqCst);
            PumpResult {
                framing: KdFraming::new(host.into()),
                bugcheck: PumpBugcheck::default(),
            }
        })
    };
    let pump = PumpHandle {
        join,
        stop_rx,
        shutdown,
        reported_stop,
        breakin_requested: Arc::new(AtomicBool::new(false)),
    };
    let mut backend = kd_backend_with_pump(pump, writer);
    backend.exit_prepared = true;
    let error = backend
        .breakin_clone
        .write_all(&[BREAKIN_BYTE])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);

    let stop = backend.interrupt().unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert_eq!(stop.exception_code, Some(ACCESS_VIOLATION));
    assert!(!stop.assisted_breakin);
    assert!(!stop.target_reloaded);
    assert!(!backend.is_running());
    assert_quiet(&mut kernel);
}

#[test]
fn regression_interrupt_does_not_learn_a_prequeued_unmanaged_breakpoint_as_breakin() {
    const KNOWN_BREAKIN_PC: u64 = 0xffff_f800_0088_4000;
    const PC: u64 = 0xffff_f800_0088_5000;
    let (host, mut kernel) = UnixStream::pair().unwrap();
    let breakin_clone = host.try_clone().unwrap();
    let stop = parse_state_change(&exception_state_change_payload(PC)).unwrap();
    let (stop_tx, stop_rx) = mpsc::channel();
    stop_tx.send(Ok(stop.clone())).unwrap();
    let pump = PumpHandle {
        join: spawn(move || PumpResult {
            framing: KdFraming::new(host.into()),
            bugcheck: PumpBugcheck::default(),
        }),
        stop_rx,
        shutdown: Arc::new(AtomicBool::new(false)),
        reported_stop: Arc::new(AtomicBool::new(true)),
        breakin_requested: Arc::new(AtomicBool::new(false)),
    };
    let mut backend = kd_backend_with_pump(pump, breakin_clone);
    backend.exit_prepared = true;
    backend.late_breakin = true;
    backend.breakin_addresses.insert(KNOWN_BREAKIN_PC);
    assert!(!backend.breakin_addresses.contains(&PC));
    assert!(!backend.managed_bp_addresses.contains(&PC));

    let event = backend.interrupt().unwrap();
    assert_eq!(event.program_counter, Some(PC));
    assert_eq!(event.exception_code, Some(STATUS_BREAKPOINT));
    assert!(!event.assisted_breakin);
    assert!(!backend.is_running());
    assert!(!backend.late_breakin);
    assert_quiet(&mut kernel);
    assert!(backend.breakin_addresses.contains(&KNOWN_BREAKIN_PC));
    let next = backend.mark_known_breakin_stop(stop);
    assert_eq!(
        (
            backend.breakin_addresses.contains(&PC),
            next.assisted_breakin
        ),
        (false, false),
        "explicit interrupt must not record a genuine queued breakpoint as assistance before clearing its event flag"
    );
}

#[test]
fn regression_interrupt_consuming_a_prequeued_exception_does_not_invent_a_late_breakin() {
    const FAULT_PC: u64 = 0xffff_f800_0088_1000;
    const BREAK_PC: u64 = 0xffff_f800_0088_2000;
    const ACCESS_VIOLATION: u32 = 0xc000_0005;
    let (host, mut kernel) = UnixStream::pair().unwrap();
    kernel.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
    kernel.set_write_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.exit_prepared = true;
    backend.start_pump(None, None).unwrap();
    let mut payload = exception_state_change_payload(FAULT_PC);
    bytes::write_u32(&mut payload, 32, ACCESS_VIOLATION);
    kernel
        .write_all(&data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            &payload,
        ))
        .unwrap();
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
    let deadline = Instant::now() + FIXTURE_TIMEOUT;
    while !backend.has_pending_stop() {
        assert!(
            Instant::now() < deadline,
            "pump did not queue the exception"
        );
        thread::sleep(Duration::from_millis(2));
    }

    let stop = backend.interrupt().unwrap();
    assert_eq!(stop.exception_code, Some(ACCESS_VIOLATION));
    assert_eq!(stop.program_counter, Some(FAULT_PC));
    assert!(!stop.assisted_breakin);
    assert!(!backend.is_running());
    assert_quiet(&mut kernel);
    let late_after_interrupt = backend.late_breakin;

    // Resume only the local fixture state: no continue request is needed to
    // demonstrate that the next guest int3 must retain its genuine cause.
    backend.record_running();
    send_exception(&mut kernel, INITIAL_PACKET_ID ^ 1, BREAK_PC);
    let next = backend.try_wait_for_stop(FIXTURE_TIMEOUT).unwrap().unwrap();
    assert_eq!(next.exception_code, Some(STATUS_BREAKPOINT));
    assert_eq!(next.program_counter, Some(BREAK_PC));
    assert_ack(&mut kernel, INITIAL_PACKET_ID ^ 1);
    assert_eq!(
        (late_after_interrupt, next.assisted_breakin),
        (false, false),
        "consuming a queued stop without sending BREAKIN cannot create a late break-in"
    );
}

#[test]
fn regression_fatal_print_acked_before_eof_keeps_bugcheck_details_after_reconnect() {
    const PC: u64 = 0xffff_f800_0088_3000;
    let (mut fixture, mut backend, mut kernel) = SerialFixture::connected();
    backend.start_pump(None, None).unwrap();
    let fatal = debug_io_print_payload(
        b"\r\n*** Fatal System Error: 0x000000d1\r\n                       (0x1,0x2,0x0,0x4)\r\n",
    );
    kernel
        .write_all(&data_packet(
            PACKET_TYPE_KD_DEBUG_IO,
            INITIAL_PACKET_ID,
            &fatal,
        ))
        .unwrap();
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
    let driver = debug_io_print_payload(b"Driver at fault: myfault.sys.\r\n");
    kernel
        .write_all(&data_packet(
            PACKET_TYPE_KD_DEBUG_IO,
            INITIAL_PACKET_ID ^ 1,
            &driver,
        ))
        .unwrap();
    assert_ack(&mut kernel, INITIAL_PACKET_ID ^ 1);
    // Both prints have been ACKed, so the target will not retransmit them
    // when the replacement socket starts carrying the same KD session.
    fixture.disconnect_listener(true);
    drop(kernel);
    assert!(backend.try_wait_for_stop(POLL_TIMEOUT).unwrap().is_none());
    assert!(backend.is_running());
    fixture.listen();
    let mut kernel = fixture.accept_while_polling(&mut backend);
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID, PC);

    let stop = backend.try_wait_for_stop(FIXTURE_TIMEOUT).unwrap().unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert!(!stop.target_reloaded);
    assert!(!stop.assisted_breakin);
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
    assert!(
        stop.is_bugcheck,
        "the ACKed fatal print must survive serial recovery"
    );
    let info = stop
        .bugcheck
        .expect("captured bugcheck must survive serial recovery");
    assert_eq!(info.code, 0xd1);
    assert_eq!(info.parameters, [1, 2, 0, 4]);
    assert_eq!(info.driver.as_deref(), Some("myfault.sys"));
}

#[test]
fn unnamed_stream_eof_is_a_typed_io_error_inline() {
    let (host, kernel) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.exit_prepared = true;
    drop(kernel);

    let error = backend.try_wait_for_stop(POLL_TIMEOUT).unwrap_err();
    assert!(
        matches!(&error, Error::Io(error) if error.kind() == ErrorKind::UnexpectedEof),
        "an unnamed, non-reconnectable stream must retain its I/O error: {error:?}"
    );
}

#[test]
fn unnamed_stream_eof_is_a_typed_io_error_from_the_pump() {
    let (host, kernel) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.exit_prepared = true;
    backend.start_pump(None, None).unwrap();
    drop(kernel);

    let error = backend.try_wait_for_stop(FIXTURE_TIMEOUT).unwrap_err();
    assert!(
        matches!(&error, Error::Io(error) if error.kind() == ErrorKind::UnexpectedEof),
        "the pump must not stringify the transport error: {error:?}"
    );
}

#[test]
fn refused_serial_socket_is_retried_on_later_bounded_polls() {
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    // A leftover socket inode with no listener produces ConnectionRefused.
    fixture.disconnect_listener(false);
    drop(kernel);
    for _ in 0..2 {
        let started = Instant::now();
        assert!(backend.try_wait_for_stop(POLL_TIMEOUT).unwrap().is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(backend.is_running());
    }

    std::fs::remove_file(&fixture.path).unwrap();
    fixture.listen();
    let mut kernel = fixture.accept_while_polling(&mut backend);
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID, 0xffff_f800_0044_5566);
    assert!(
        backend
            .try_wait_for_stop(FIXTURE_TIMEOUT)
            .unwrap()
            .is_some()
    );
}

#[test]
fn reconnect_preserves_both_packet_id_streams_and_breakpoint_tracking() {
    const STALE_PC: u64 = 0xffff_f800_0055_0000;
    const PC: u64 = 0xffff_f800_0055_1122;
    const BP: u64 = 0xffff_f800_0090_0000;
    let (mut fixture, mut backend, mut kernel) = SerialFixture::connected();
    backend.bp_handles.insert(BP, 11);
    backend.managed_bp_addresses.insert(BP);

    kernel
        .write_all(&control_packet(
            PACKET_TYPE_KD_ACKNOWLEDGE,
            INITIAL_PACKET_ID,
        ))
        .unwrap();
    backend
        .framing()
        .unwrap()
        .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"before reconnect")
        .unwrap();
    assert_eq!(
        wire_header(&read_wire_packet(&mut kernel)).packet_id,
        INITIAL_PACKET_ID
    );
    kernel
        .write_all(&data_packet(
            PACKET_TYPE_KD_DEBUG_IO,
            INITIAL_PACKET_ID,
            b"prime",
        ))
        .unwrap();
    assert_eq!(
        backend.framing().unwrap().recv_data().unwrap().payload,
        b"prime"
    );
    assert_ack(&mut kernel, INITIAL_PACKET_ID);

    fixture.disconnect_listener(true);
    drop(kernel);
    assert!(backend.try_wait_for_stop(POLL_TIMEOUT).unwrap().is_none());
    fixture.listen();
    let mut kernel = fixture.accept_while_polling(&mut backend);
    assert_quiet(&mut kernel);
    // A new framing would accept the stale packet and discard the fresh one.
    send_exception(&mut kernel, INITIAL_PACKET_ID, STALE_PC);
    send_exception(&mut kernel, INITIAL_PACKET_ID ^ 1, PC);
    let stop = backend.try_wait_for_stop(FIXTURE_TIMEOUT).unwrap().unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert!(!stop.target_reloaded);
    assert_eq!(backend.bp_handles.get(&BP), Some(&11));
    assert!(backend.managed_bp_addresses.contains(&BP));
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
    assert_ack(&mut kernel, INITIAL_PACKET_ID ^ 1);

    kernel
        .write_all(&control_packet(
            PACKET_TYPE_KD_ACKNOWLEDGE,
            INITIAL_PACKET_ID ^ 1,
        ))
        .unwrap();
    backend
        .framing()
        .unwrap()
        .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"after reconnect")
        .unwrap();
    let request = read_wire_packet(&mut kernel);
    assert_eq!(wire_header(&request).packet_id, INITIAL_PACKET_ID ^ 1);
    assert_quiet(&mut kernel);
}

#[test]
fn a_real_sync_after_reconnect_still_reports_target_reload() {
    const PC: u64 = 0xffff_f800_0066_7788;
    const BP: u64 = 0xffff_f800_0090_0000;
    let (mut fixture, mut backend, kernel) = SerialFixture::connected();
    backend.bp_handles.insert(BP, 13);
    backend.managed_bp_addresses.insert(BP);
    fixture.disconnect_listener(true);
    drop(kernel);
    assert!(backend.try_wait_for_stop(POLL_TIMEOUT).unwrap().is_none());
    fixture.listen();
    let mut kernel = fixture.accept_while_polling(&mut backend);
    assert_quiet(&mut kernel);
    send_exception(&mut kernel, INITIAL_PACKET_ID | SYNC_PACKET_ID, PC);

    let stop = backend.try_wait_for_stop(FIXTURE_TIMEOUT).unwrap().unwrap();
    assert_eq!(stop.program_counter, Some(PC));
    assert!(
        stop.target_reloaded,
        "a genuine KD SYNC is not just a socket repair"
    );
    assert!(backend.bp_handles.is_empty());
    assert!(backend.managed_bp_addresses.is_empty());
    assert_ack(&mut kernel, INITIAL_PACKET_ID);
}
