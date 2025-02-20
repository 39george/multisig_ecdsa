use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::extract::ConnectInfo;
use axum::middleware::AddExtension;
use axum::routing;
use axum::serve::Serve;
use axum::Router;
use http::StatusCode;
use secp256k1::All;
use secp256k1::Secp256k1;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tower_http::services::ServeFile;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::api;
use crate::config::Settings;
use crate::middleware::RequestTracingLayer;
use crate::storage::in_memory::InMemoryStorage;
use crate::storage::Storage;

use self::api_doc::ApiDoc;

pub mod api_doc;

type Server = Serve<
    TcpListener,
    IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
    AddExtension<Router, ConnectInfo<SocketAddr>>,
>;

pub struct Application {
    port: u16,
    server: Server,
}

/// Thread-safe type
#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub storage: Arc<dyn Storage + Send + Sync>,
    pub secp: Secp256k1<All>,
}

impl Application {
    /// Build a new server.
    ///
    /// This functions builds a new `Application` with given configuration.
    pub async fn build(
        configuration: Settings,
    ) -> Result<Application, anyhow::Error> {
        let address =
            format!("{}:{}", configuration.app_ip, configuration.app_port);
        tracing::info!("running on {} address", address);

        let listener = TcpListener::bind(address).await?;
        let port = listener.local_addr()?.port();

        let app_state = AppState {
            settings: Arc::new(configuration),
            storage: Arc::new(InMemoryStorage::default()),
            secp: secp256k1::Secp256k1::new(),
        };

        let server = Self::build_server(listener, app_state);

        Ok(Self { server, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// This function only returns when the application is stopped.
    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        self.server
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        Ok(())
    }

    /// Configure `Server`.
    fn build_server(listener: TcpListener, app_state: AppState) -> Server {
        #[rustfmt::skip]
        let mut router = Router::new()
            .nest("/api/v1", api::router())
            .with_state(app_state)
            .fallback_service(ServeDir::new("dist").fallback(ServeFile::new("dist/index.html")))
            .layer(RequestTracingLayer)
            .route("/api/healthcheck", routing::get(healthcheck)); // Do not trace healthchecks

        match std::env::var("ENVIRONMENT").unwrap_or_default().as_str() {
            "production" => (),
            _ => {
                let cors = tower_http::cors::CorsLayer::new()
                    // allow `GET` and `POST` when accessing the resource
                    .allow_methods([http::Method::GET, http::Method::POST])
                    // allow requests from any origin
                    .allow_origin(tower_http::cors::Any);
                router = router
                    .merge(
                        SwaggerUi::new("/swagger-ui")
                            .url("/api-docs/openapi.json", ApiDoc::openapi()),
                    )
                    .layer(cors);
            }
        }

        axum::serve(
            listener,
            router
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
    }
}

#[utoipa::path(
    get,
    path = "/api/healthcheck",
    responses(
        (status = 200, description = "Healthcheck"),
    ),
    tag = "open"
)]
async fn healthcheck() -> StatusCode {
    StatusCode::OK
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    let terminate = async {
        tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .expect("failed to install signal handler")
        .recv()
        .await;
    };
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("Terminate signal received");
}
