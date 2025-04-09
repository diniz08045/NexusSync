import logging

logger = logging.getLogger(__name__)

# Stub functions to replace ElasticSearch functionality
def add_to_index(index, model):
    """Stub function - ElasticSearch functionality removed"""
    logger.debug(f"ElasticSearch functionality removed - add_to_index called with index: {index}")
    return

def remove_from_index(index, model):
    """Stub function - ElasticSearch functionality removed"""
    logger.debug(f"ElasticSearch functionality removed - remove_from_index called with index: {index}")
    return

def query_index(index, query, page=1, per_page=10):
    """Stub function - ElasticSearch functionality removed"""
    logger.debug(f"ElasticSearch functionality removed - query_index called with index: {index}, query: {query}")
    return [], 0

def bulk_index(index, models):
    """Stub function - ElasticSearch functionality removed"""
    logger.debug(f"ElasticSearch functionality removed - bulk_index called with index: {index}")
    return

def create_index(index, mapping=None):
    """Stub function - ElasticSearch functionality removed"""
    logger.debug(f"ElasticSearch functionality removed - create_index called with index: {index}")
    return

def delete_index(index):
    """Stub function - ElasticSearch functionality removed"""
    logger.debug(f"ElasticSearch functionality removed - delete_index called with index: {index}")
    return

def reindex_all(index, model_class):
    """Stub function - ElasticSearch functionality removed"""
    logger.debug(f"ElasticSearch functionality removed - reindex_all called with index: {index}")
    return
