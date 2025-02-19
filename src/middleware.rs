use std::fmt::Write;

use axum::body::Bytes;
use axum::{body::Body, extract::Request, response::Response};
use futures::future::BoxFuture;
use http::StatusCode;
use http_body_util::BodyExt;
use std::fmt::Display;
use std::task::Context;
use std::task::Poll;
use tower::Layer;
use tower::Service;
use tracing::Instrument;

/// Create bytes buffer from body
async fn buffer<B>(body: B) -> Result<Bytes, String>
where
    B: axum::body::HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return Err(format!("failed to read body: {err}"));
        }
    };

    Ok(bytes)
}

fn format_headers(req: &axum::extract::Request) -> String {
    req.headers()
        .iter()
        .fold(String::new(), |mut agg, (name, value)| {
            if let Err(e) = write!(
                &mut agg,
                "\n\t{}:{}",
                name,
                value.to_str().unwrap_or("failed to parse")
            ) {
                tracing::error!("Failed to format headers: {e}");
            }
            agg
        })
}

#[derive(Clone)]
pub struct RequestTracingService<S> {
    inner: S,
}

impl<S> Service<Request> for RequestTracingService<S>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Display + std::fmt::Debug + Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>; // use `BoxFuture`

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let span = tracing::info_span!("req_tracing");

        let method = req.method().clone();
        let uri = req.uri().clone();
        span.in_scope(|| {
            tracing::info!(
                "Request:\n\t{}: {}{}{}",
                method.as_str(),
                uri.path(),
                if let Some(q) = uri.query() {
                    format!("?{}", q)
                } else {
                    "".to_string()
                },
                format_headers(&req)
            );
        });

        let fut = self.inner.call(req).instrument(span.clone());

        Box::pin(
            async move {
                let result = fut.await;
                match result {
                    Ok(res) if res.status().eq(&StatusCode::FORBIDDEN) => {
                        let (parts, body) = res.into_parts();
                        let bytes = match buffer(body).await {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                tracing::error!("Error: {e}");
                                Bytes::new()
                            }
                        };
                        match std::str::from_utf8(&bytes) {
                            Ok(msg) if !msg.is_empty() => {
                                tracing::info!(
                                    "Forbidden request: {}: {}, body: {}",
                                    method.as_str(),
                                    uri.path(),
                                    msg
                                );
                            }
                            _ => {
                                tracing::info!(
                                    "Forbidden request: {}: {}",
                                    method.as_str(),
                                    uri.path()
                                );
                            }
                        }
                        Ok(Response::from_parts(parts, Body::from(bytes)))
                    }
                    Err(e) => {
                        tracing::error!("Error: {e}");
                        Err(e)
                    }
                    anyother => anyother,
                }
            }
            .instrument(span),
        )
    }
}

#[derive(Clone)]
pub struct RequestTracingLayer;

impl<S> Layer<S> for RequestTracingLayer {
    type Service = RequestTracingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestTracingService { inner }
    }
}
