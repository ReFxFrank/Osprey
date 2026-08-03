//! M-01 over a real session: subscribe, backfill, stream, unsubscribe.
//!
//! Drives the shipping code paths end to end — a real `Noise_IK` session
//! against a real `run` loop — because the parts most likely to break are the
//! seams: the correlation between a subscribe and its history answer, and the
//! fact that ticks arrive *uncorrelated* while the loop is otherwise idle.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
// Only the streaming assertions need a clock, and they only compile where
// there is a collector to stream from.
#[cfg(windows)]
use std::time::Instant;

use common::{
    connect_to_hint, free_port, open_session, pair_one_controller, recv_envelope, send_body,
    SharedSink,
};
use osprey_core::audit::AuditLog;
use osprey_core::identity::DeviceIdentity;
use osprey_proto::{Body, Capability, MessageType, MetricsSubscribeBody};
use osprey_svc::commands::run;
use osprey_svc::host::Host;
use osprey_svc::paths::DataLayout;
use uuid::Uuid;

/// Long enough for several 1 Hz samples, short enough that a hang is obvious.
#[cfg(windows)]
const STREAM_WINDOW: Duration = Duration::from_secs(8);

#[test]
fn subscribe_backfills_then_streams_and_unsubscribing_stops_it() {
    let agent_dir = tempfile::tempdir().expect("agent dir");
    let controller_dir = tempfile::tempdir().expect("controller dir");
    let layout = DataLayout::under(agent_dir.path());
    let port = free_port();

    let controller_identity = DeviceIdentity::generate();
    let controller_audit = AuditLog::open(controller_dir.path()).expect("audit");
    let enrolled = pair_one_controller(&layout, port, &controller_identity, &controller_audit);

    let running = Arc::new(AtomicBool::new(true));
    let run_thread = {
        let layout = layout.clone();
        let running = Arc::clone(&running);
        std::thread::spawn(move || {
            let host = Host::open(layout, "gate-host").expect("reopen host");
            let mut sink = SharedSink::default();
            run::execute(
                &host,
                &run::RunOptions {
                    port,
                    ..Default::default()
                },
                running,
                &mut sink,
            )
        })
    };

    let mut stream = connect_to_hint(&enrolled.payload.lan_hints);
    let mut session = open_session(
        &mut stream,
        &controller_identity,
        &enrolled.agent_pin,
        Uuid::new_v4(),
    );

    // ---- the agent advertises what it can actually serve -------------------
    // `open_session` already checked the correlation; this checks the content,
    // because a client gates its whole metrics UI on this list.
    {
        let mut probe_stream = connect_to_hint(&enrolled.payload.lan_hints);
        let mut probe = osprey_core::channel::connect(
            &mut probe_stream,
            &controller_identity,
            &enrolled.agent_pin,
        )
        .expect("second session");
        let hello_id = Uuid::new_v4();
        send_body(
            &mut probe,
            &mut probe_stream,
            hello_id,
            &Body::Hello(osprey_proto::HelloBody {
                protocol_version: osprey_proto::PROTOCOL_VERSION,
                min_protocol_version: osprey_proto::MIN_PROTOCOL_VERSION,
                capabilities: vec![Capability::Metrics],
                device_id: Uuid::new_v4(),
                software_version: "gate-test".into(),
            }),
        );
        let envelope = recv_envelope(&mut probe, &mut probe_stream);
        let Ok(Body::HelloOk(hello_ok)) = envelope.decode_body() else {
            panic!("expected hello.ok, got {}", envelope.t);
        };
        assert!(
            hello_ok.capabilities.contains(&Capability::Metrics),
            "the agent must advertise the metrics capability it implements"
        );
        assert!(
            hello_ok.display_name.is_some(),
            "hello.ok must carry a machine name for the device list (A24)"
        );
    }

    // ---- 1. subscribe is answered by a correlated history ------------------
    let sub_id = Uuid::new_v4();
    send_body(
        &mut session,
        &mut stream,
        sub_id,
        &Body::MetricsSubscribe(MetricsSubscribeBody {
            backfill_seconds: 3_600,
            stream: true,
        }),
    );

    let answer = recv_envelope(&mut session, &mut stream);
    assert_eq!(
        answer.id, sub_id,
        "the history answering a subscribe must carry the subscribe's id"
    );
    assert_eq!(answer.t, MessageType::MetricsHistory);
    let Ok(Body::MetricsHistory(history)) = answer.decode_body() else {
        panic!("expected a metrics.history body");
    };
    assert_eq!(history.sub, sub_id);
    // Every parallel array must agree, or the client plots misaligned series.
    let points = history.cpu_percent.len();
    assert_eq!(history.mem_used_bytes.len(), points);
    assert_eq!(history.net_rx_bytes_per_sec.len(), points);
    assert_eq!(history.net_tx_bytes_per_sec.len(), points);
    assert!(
        history.interval_ms > 0,
        "an interval of zero would stack every sample on one instant"
    );

    // ---- 2. ticks arrive unprompted, carrying the subscription id ----------
    // Only Windows has a collector; elsewhere the engine correctly produces
    // nothing, and asserting otherwise would be asserting fabricated data.
    #[cfg(windows)]
    {
        stream
            .set_read_timeout(Some(STREAM_WINDOW))
            .expect("read timeout");
        let deadline = Instant::now() + STREAM_WINDOW;
        let mut ticks = 0;
        while Instant::now() < deadline && ticks < 2 {
            let envelope = recv_envelope(&mut session, &mut stream);
            assert_eq!(
                envelope.t,
                MessageType::MetricsTick,
                "only ticks should arrive unprompted on an idle session"
            );
            let Ok(Body::MetricsTick(tick)) = envelope.decode_body() else {
                panic!("expected a metrics.tick body");
            };
            assert_eq!(tick.sub, sub_id, "a tick must name its subscription");
            assert_ne!(
                envelope.id, sub_id,
                "a pushed tick is uncorrelated and must not reuse the request id"
            );
            assert!(
                (0.0..=100.0).contains(&tick.cpu_percent),
                "cpu {} is outside 0-100",
                tick.cpu_percent
            );
            assert!(tick.mem_total_bytes > 0, "installed memory must be real");
            assert!(tick.mem_used_bytes <= tick.mem_total_bytes);
            assert_eq!(tick.disk_labels.len(), tick.disk_used_bytes.len());
            assert_eq!(tick.disk_labels.len(), tick.disk_total_bytes.len());
            ticks += 1;
        }
        assert!(ticks >= 2, "expected a 1 Hz stream, saw {ticks} ticks");
    }

    // ---- 3. unsubscribing is answered, and the stream stops ----------------
    let stop_id = Uuid::new_v4();
    send_body(
        &mut session,
        &mut stream,
        stop_id,
        &Body::MetricsSubscribe(MetricsSubscribeBody {
            backfill_seconds: 0,
            stream: false,
        }),
    );

    // Ticks already in flight may arrive before the answer, so drain until the
    // correlated response appears rather than assuming the next message is it.
    let mut settled = false;
    for _ in 0..64 {
        let envelope = recv_envelope(&mut session, &mut stream);
        if envelope.id == stop_id {
            assert_eq!(envelope.t, MessageType::MetricsHistory);
            settled = true;
            break;
        }
        assert_eq!(
            envelope.t,
            MessageType::MetricsTick,
            "unexpected message while draining the stopped stream"
        );
    }
    assert!(settled, "the unsubscribe was never answered");

    // With the stream closed the session must go quiet. A tick arriving here
    // would mean an unsubscribe left a feed running.
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    assert!(
        session.recv(&mut stream).is_err(),
        "no message should arrive after unsubscribing; the read must time out"
    );

    running.store(false, Ordering::Relaxed);
    drop(stream);
    run_thread.join().expect("run thread").expect("run result");
}
