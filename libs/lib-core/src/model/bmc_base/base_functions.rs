use bson::{doc, oid::ObjectId, Document};
use futures::StreamExt;
use mongodb::Collection;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    ctx::Ctx,
    model::{Error, Result},
};

#[async_trait::async_trait]
pub trait Bmc {
    const COLLECTION_NAME: &'static str;
}

pub async fn create<MC, E>(ctx: &Ctx, collection: &Collection<E>, entity: E) -> Result<ObjectId>
where
    MC: Bmc,
    E: Serialize + Send + Sync,
{
    if !ctx.is_root() {
        return Err(Error::NonRootCantCreateEntity {
            collection_name: MC::COLLECTION_NAME,
        });
    }

    let result = collection.insert_one(entity).await.map_err(Error::Mongo)?;

    let id = result
        .inserted_id
        .as_object_id()
        .ok_or(Error::InsertedIdNotObjectId {
            inserted_id: result.inserted_id,
        })?;

    Ok(id)
}

pub async fn find_one<MC, E>(
    _ctx: &Ctx,
    collection: &Collection<E>,
    filter_doc: impl Into<Document>,
) -> Result<E>
where
    MC: Bmc,
    E: Serialize + DeserializeOwned + Send + Sync,
{
    let result = collection
        .find_one(filter_doc.into())
        .await
        .map_err(Error::Mongo)?;

    result.ok_or(Error::EntityNotFound {
        collection_name: MC::COLLECTION_NAME,
    })
}

pub async fn find_many<MC, E>(
    _ctx: &Ctx,
    collection: &Collection<E>,
    filter_doc: impl Into<Document>,
) -> Result<Vec<E>>
where
    MC: Bmc,
    E: Serialize + DeserializeOwned + Send + Sync,
{
    let user_results: Vec<_> = collection
        .find(filter_doc.into())
        .await
        .map_err(Error::Mongo)?
        .collect()
        .await;

    user_results
        .into_iter()
        .map(|r| r.map_err(Error::Mongo))
        .collect::<Result<Vec<_>>>()
}

pub async fn find_all<MC, E>(_ctx: &Ctx, collection: &Collection<E>) -> Result<Vec<E>>
where
    MC: Bmc,
    E: Serialize + DeserializeOwned + Send + Sync,
{
    find_many::<MC, E>(_ctx, collection, doc! {}).await
}

pub async fn delete_one<MC, E>(
    _ctx: &Ctx,
    collection: &Collection<E>,
    filter_doc: impl Into<Document>,
) -> Result<()>
where
    MC: Bmc,
    E: Serialize + DeserializeOwned + Send + Sync,
{
    let result = collection
        .delete_one(filter_doc.into())
        .await
        .map_err(Error::Mongo)?;

    if result.deleted_count == 0 {
        return Err(Error::EntityNotFound {
            collection_name: MC::COLLECTION_NAME,
        });
    }

    Ok(())
}

pub async fn delete_many<MC, E>(
    _ctx: &Ctx,
    collection: &Collection<E>,
    filter_doc: impl Into<Document>,
) -> Result<u64>
where
    MC: Bmc,
    E: Serialize + DeserializeOwned + Send + Sync,
{
    Ok(collection
        .delete_many(filter_doc.into())
        .await
        .map_err(Error::Mongo)?
        .deleted_count)
}
