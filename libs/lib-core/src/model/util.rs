use crate::{ctx::Ctx, model::model_manager::ModelManager};

pub async fn init_dev_db() -> Result<(), Box<dyn std::error::Error>> {
    // -- Init model layer.
    let mm = ModelManager::new().await?;

    let ctx = Ctx::root_ctx();

    tracing::info!("{:<12} - init_dev_db - set demo1 pwd", "FOR-DEV-ONLY");

    Ok(())
}
