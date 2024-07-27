use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    runtime,
    trace::{BatchConfig, RandomIdGenerator, Sampler, Tracer},
    Resource,
};
use opentelemetry_semantic_conventions::{
    resource::{DEPLOYMENT_ENVIRONMENT, SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};
use tracing_core::LevelFilter;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// Create a Resource that captures information about the entity for which telemetry is recorded.
fn resource() -> Resource {
    Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
            KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
            KeyValue::new(DEPLOYMENT_ENVIRONMENT, "develop"),
        ],
        SCHEMA_URL,
    )
}

pub fn setup_otel() -> OtelGuard {
    // TODO: per layer filter
    // - RUST_LOG for otel.
    // - clap verbosity flag for logger.

    let otel_layer = std::env::var("OTEL_COLLECTOR_URL").map_or_else(
        |_| {
          println!("No collector url found.");
          None
        },
        |url| Some(OpenTelemetryLayer::new(init_tracer(&url))),
    );

    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::builder().from_env_lossy()
    } else {
        "warn,auth_ex=debug"
            .parse()
            .expect("valid EnvFilter value can be parsed")
    };

    tracing_subscriber::registry()
        .with(filter) // Read global subscriber filter from `RUST_LOG`
        .with(tracing_subscriber::fmt::layer()) // Setup logging layer
        .with(otel_layer)
        .init();

    OtelGuard
}

// Construct Tracer for OpenTelemetryLayer
fn init_tracer(url: &str) -> Tracer {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default()
                // Customize sampling strategy
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                    1.0,
                ))))
                // If export trace to AWS X-Ray, you can use XrayIdGenerator
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(resource()),
        )
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(url),
        )
        .with_batch_config(BatchConfig::default())
        .install_batch(runtime::Tokio)
        .expect("opentelemetry tracer to configure correctly")
}

pub struct OtelGuard;

impl Drop for OtelGuard {
    fn drop(&mut self) {
        opentelemetry::global::shutdown_tracer_provider();
    }
}