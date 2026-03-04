//! Heap profiling endpoints backed by jemalloc's built-in profiler.
//!
//! Returns pprof-format heap profiles at `/debug/pprof/allocs` and interactive
//! SVG flamegraphs at `/debug/pprof/allocs/flamegraph`. Only functional on Linux;
//! other platforms return 501 Not Implemented.

#[cfg(target_os = "linux")]
mod inner {
    use axum::{http::StatusCode, response::IntoResponse};

    pub async fn handle_get_heap() -> impl IntoResponse {
        let Some(prof_ctl) = jemalloc_pprof::PROF_CTL.as_ref() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Heap profiling not enabled",
            )
                .into_response();
        };
        let mut guard = prof_ctl.lock().await;
        match guard.dump_pprof() {
            Ok(pprof) => (
                StatusCode::OK,
                [("content-type", "application/octet-stream")],
                pprof,
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to dump heap profile: {err}"),
            )
                .into_response(),
        }
    }

    pub async fn handle_get_heap_flamegraph() -> impl IntoResponse {
        let Some(prof_ctl) = jemalloc_pprof::PROF_CTL.as_ref() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Heap profiling not enabled",
            )
                .into_response();
        };
        let mut guard = prof_ctl.lock().await;
        match guard.dump_flamegraph() {
            Ok(svg) => (StatusCode::OK, [("content-type", "image/svg+xml")], svg).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to dump flamegraph: {err}"),
            )
                .into_response(),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod inner {
    use axum::{http::StatusCode, response::IntoResponse};

    pub async fn handle_get_heap() -> impl IntoResponse {
        (
            StatusCode::NOT_IMPLEMENTED,
            "Heap profiling is only available on Linux",
        )
    }

    pub async fn handle_get_heap_flamegraph() -> impl IntoResponse {
        (
            StatusCode::NOT_IMPLEMENTED,
            "Heap profiling is only available on Linux",
        )
    }
}

pub use inner::{handle_get_heap, handle_get_heap_flamegraph};
