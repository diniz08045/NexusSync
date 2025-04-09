import logging
from flask import current_app
from app import es

logger = logging.getLogger(__name__)

def add_to_index(index, model):
    """Add an object to the Elasticsearch index."""
    if es is None:
        logger.warning("Elasticsearch is not available")
        return
    
    payload = {}
    for field in model.__searchable__ if hasattr(model, '__searchable__') else ['id', 'username', 'email', 'first_name', 'last_name']:
        value = getattr(model, field, None)
        if value is not None:
            payload[field] = value
    
    try:
        es.index(index=index, id=model.id, body=payload)
        logger.debug(f"Added to Elasticsearch index: {index}, id: {model.id}")
    except Exception as e:
        logger.error(f"Error adding to Elasticsearch index: {e}")

def remove_from_index(index, model):
    """Remove an object from the Elasticsearch index."""
    if es is None:
        logger.warning("Elasticsearch is not available")
        return
    
    try:
        es.delete(index=index, id=model.id)
        logger.debug(f"Removed from Elasticsearch index: {index}, id: {model.id}")
    except Exception as e:
        logger.error(f"Error removing from Elasticsearch index: {e}")

def query_index(index, query, page=1, per_page=10):
    """Search for objects in the Elasticsearch index."""
    if es is None:
        logger.warning("Elasticsearch is not available")
        return []
    
    try:
        search = es.search(
            index=index,
            body={
                'query': {
                    'multi_match': {
                        'query': query,
                        'fields': ['*']
                    }
                },
                'from': (page - 1) * per_page,
                'size': per_page
            }
        )
        
        ids = [int(hit['_id']) for hit in search['hits']['hits']]
        return ids
    except Exception as e:
        logger.error(f"Error querying Elasticsearch index: {e}")
        return []

def bulk_index(index, models):
    """Index multiple objects in Elasticsearch."""
    if es is None:
        logger.warning("Elasticsearch is not available")
        return
    
    try:
        actions = []
        for model in models:
            payload = {}
            for field in model.__searchable__ if hasattr(model, '__searchable__') else ['id', 'username', 'email', 'first_name', 'last_name']:
                value = getattr(model, field, None)
                if value is not None:
                    payload[field] = value
            
            actions.append({
                '_index': index,
                '_id': model.id,
                '_source': payload
            })
        
        if actions:
            from elasticsearch.helpers import bulk
            bulk(es, actions)
            logger.debug(f"Bulk indexed {len(actions)} documents in {index}")
    except Exception as e:
        logger.error(f"Error bulk indexing to Elasticsearch: {e}")

def create_index(index, mapping=None):
    """Create an Elasticsearch index with optional mapping."""
    if es is None:
        logger.warning("Elasticsearch is not available")
        return
    
    try:
        if not es.indices.exists(index=index):
            es.indices.create(index=index, body=mapping if mapping else {})
            logger.info(f"Created Elasticsearch index: {index}")
    except Exception as e:
        logger.error(f"Error creating Elasticsearch index: {e}")

def delete_index(index):
    """Delete an Elasticsearch index."""
    if es is None:
        logger.warning("Elasticsearch is not available")
        return
    
    try:
        if es.indices.exists(index=index):
            es.indices.delete(index=index)
            logger.info(f"Deleted Elasticsearch index: {index}")
    except Exception as e:
        logger.error(f"Error deleting Elasticsearch index: {e}")

def reindex_all(index, model_class):
    """Reindex all objects of a model class."""
    if es is None:
        logger.warning("Elasticsearch is not available")
        return
    
    try:
        # First, delete the index if it exists
        delete_index(index)
        
        # Create a new index
        create_index(index)
        
        # Bulk index all objects
        models = model_class.query.all()
        bulk_index(index, models)
        
        logger.info(f"Reindexed {len(models)} documents in {index}")
    except Exception as e:
        logger.error(f"Error reindexing Elasticsearch index: {e}")
