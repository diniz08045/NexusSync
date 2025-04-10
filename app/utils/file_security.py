"""
File security module for handling secure file uploads and operations.

This module provides functions for securely handling file uploads, validating file types,
checking file contents, and protecting against file-based attacks.
"""

import os
import magic
import hashlib
import uuid
from typing import Optional, List, Dict, Set, Tuple, Union
import logging

from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask import current_app

# Setup the file security logger
file_security_logger = logging.getLogger("app.file_security")
file_security_logger.setLevel(logging.INFO)

# Define allowed file types and extensions
ALLOWED_EXTENSIONS: Set[str] = {
    # Images
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg',
    # Documents
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv',
    # Archives
    'zip', 'gz', 'tar',
}

# Mapping of file extensions to allowed MIME types
MIME_TYPE_MAPPING: Dict[str, List[str]] = {
    # Images
    'jpg': ['image/jpeg'],
    'jpeg': ['image/jpeg'],
    'png': ['image/png'],
    'gif': ['image/gif'],
    'webp': ['image/webp'],
    'svg': ['image/svg+xml'],
    # Documents
    'pdf': ['application/pdf'],
    'doc': ['application/msword'],
    'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    'xls': ['application/vnd.ms-excel'],
    'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    'ppt': ['application/vnd.ms-powerpoint'],
    'pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
    'txt': ['text/plain'],
    'csv': ['text/csv', 'application/csv'],
    # Archives
    'zip': ['application/zip'],
    'gz': ['application/gzip'],
    'tar': ['application/x-tar'],
}

# Default file size limits in bytes
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def allowed_file(filename: str) -> bool:
    """
    Check if a file has an allowed extension.
    
    Args:
        filename: The filename to check
        
    Returns:
        bool: True if the file has an allowed extension, False otherwise
    """
    if '.' not in filename:
        return False
        
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS

def validate_file_type(file: FileStorage) -> bool:
    """
    Validate a file's type by checking both extension and content MIME type.
    
    Args:
        file: The file to validate
        
    Returns:
        bool: True if the file type is valid, False otherwise
    """
    if not file or not file.filename:
        return False
        
    # Check the extension
    filename = file.filename
    if not allowed_file(filename):
        file_security_logger.warning(f"File with disallowed extension: {filename}")
        return False
        
    # Get file extension
    extension = filename.rsplit('.', 1)[1].lower()
    
    # Save the file to a temporary location to check its MIME type
    temp_path = os.path.join('/tmp', secure_filename(filename))
    file.save(temp_path)
    
    try:
        # Get the actual MIME type of the file content
        mime = magic.Magic(mime=True)
        content_type = mime.from_file(temp_path)
        
        # Check if content type matches the allowed MIME types for this extension
        if extension in MIME_TYPE_MAPPING and content_type in MIME_TYPE_MAPPING[extension]:
            return True
        else:
            file_security_logger.warning(
                f"File MIME type mismatch: {filename}, "
                f"declared extension: {extension}, "
                f"detected MIME: {content_type}"
            )
            return False
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
def process_uploaded_file(
    file: FileStorage, 
    upload_dir: str, 
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
) -> Optional[Dict[str, str]]:
    """
    Process and securely save an uploaded file.
    
    Args:
        file: The uploaded file
        upload_dir: The directory to save the file in
        max_file_size: Maximum allowed file size in bytes
        
    Returns:
        Optional[Dict[str, str]]: Details about the saved file or None if invalid
    """
    if not file or not file.filename:
        return None
        
    # Check file size
    if file.content_length > max_file_size:
        file_security_logger.warning(
            f"File size exceeds limit: {file.filename}, "
            f"size: {file.content_length}, "
            f"limit: {max_file_size}"
        )
        return None
        
    # Validate file type
    if not validate_file_type(file):
        return None
        
    # Create a secure filename
    original_filename = secure_filename(file.filename)
    file_ext = os.path.splitext(original_filename)[1]
    
    # Generate a unique filename using UUID
    unique_filename = f"{uuid.uuid4().hex}{file_ext}"
    
    # Ensure the upload directory exists
    os.makedirs(upload_dir, exist_ok=True)
    
    # Prepare the full path
    file_path = os.path.join(upload_dir, unique_filename)
    
    # Save the file
    file.save(file_path)
    
    # Calculate file hash for integrity checking
    file_hash = calculate_file_hash(file_path)
    
    file_security_logger.info(
        f"File saved securely: {original_filename} -> {unique_filename}, "
        f"hash: {file_hash}"
    )
    
    return {
        'original_filename': original_filename,
        'stored_filename': unique_filename,
        'file_path': file_path,
        'file_size': os.path.getsize(file_path),
        'file_type': os.path.splitext(original_filename)[1][1:],  # Extension without dot
        'file_hash': file_hash
    }

def calculate_file_hash(file_path: str) -> str:
    """
    Calculate SHA-256 hash of a file for integrity checking.
    
    Args:
        file_path: Path to the file
        
    Returns:
        str: The hex digest of the file hash
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read the file in chunks to handle large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            
    return sha256_hash.hexdigest()

def scan_file_for_malware(file_path: str) -> bool:
    """
    Scan a file for malware.
    
    This is a placeholder function. In a production environment, you would
    integrate with an actual antivirus scanner or API service.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        bool: True if the file is safe, False if malware is detected
    """
    # In a real implementation, you would call an antivirus scanner here
    # For example, using ClamAV:
    #
    # import clamd
    # cd = clamd.ClamdUnixSocket()
    # scan_result = cd.scan(file_path)
    # return scan_result[file_path][0] == 'OK'
    
    # For now, just log that this is a placeholder
    file_security_logger.warning(
        f"Malware scanning is not implemented. "
        f"File {file_path} was not scanned."
    )
    
    # Return True assuming the file is safe
    # In production, NEVER skip actual malware scanning
    return True

def validate_upload_directory(base_dir: str, requested_dir: str) -> str:
    """
    Validate and sanitize an upload directory to prevent directory traversal.
    
    Args:
        base_dir: The base upload directory
        requested_dir: The requested subdirectory
        
    Returns:
        str: The full validated path, or base_dir if validation fails
    """
    # Normalize paths
    base_dir = os.path.normpath(os.path.abspath(base_dir))
    
    # Sanitize the requested directory
    sanitized_dir = secure_filename(requested_dir) if requested_dir else ""
    
    # Create the full path
    full_path = os.path.normpath(os.path.join(base_dir, sanitized_dir))
    
    # Check if the path is valid (within the base directory)
    if not full_path.startswith(base_dir):
        file_security_logger.warning(
            f"Directory traversal attempt: {requested_dir}"
        )
        return base_dir
        
    # Ensure the directory exists
    os.makedirs(full_path, exist_ok=True)
    
    return full_path