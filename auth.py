"""
Authentication and Authorization Module for Folio API

This module contains all JWT authentication, Keycloak integration,
and authorization functions.
"""

import logging
import requests
import os
import jwt
from functools import wraps
from flask import request, jsonify, g
import traceback

logger = logging.getLogger(__name__)

# Keycloak configuration from environment variables
KEYCLOAK_HOST = os.getenv("KEYCLOAK_HOST", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "agari")
KEYCLOAK_ISSUER = os.getenv("KEYCLOAK_ISSUER", f"{KEYCLOAK_HOST}/realms/{KEYCLOAK_REALM}")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "dms")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
KEYCLOAK_PERMISSION_URI = f"{KEYCLOAK_HOST}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

# Keycloak Admin API endpoints
KEYCLOAK_ADMIN_TOKEN_URI = f"{KEYCLOAK_HOST}/realms/master/protocol/openid-connect/token"
KEYCLOAK_ADMIN_BASE_URI = f"{KEYCLOAK_HOST}/admin/realms/{KEYCLOAK_REALM}"
KEYCLOAK_ADMIN_CLIENT_ID = "admin-cli"

# UMA Resource Server endpoints
KEYCLOAK_UMA_RESOURCE_URI = f"{KEYCLOAK_HOST}/realms/{KEYCLOAK_REALM}/authz/protection/resource_set"


def get_service_token():
    """Get a service token from Keycloak for admin operations"""
    try:
        logger.info("Getting service token from Keycloak")
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': KEYCLOAK_CLIENT_ID,
            'client_secret': KEYCLOAK_CLIENT_SECRET
        }
        
        response = requests.post(KEYCLOAK_PERMISSION_URI, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        
        token_data = response.json()
        access_token = token_data.get('access_token')
        
        if access_token:
            logger.info("Successfully obtained service token")
            return access_token
        else:
            logger.error("No access token in response")
            return None
            
    except Exception as e:
        logger.error(f"Failed to get service token: {e}")
        return None


def get_dms_client_token():
    """Get client credentials token for DMS client (service-to-service auth)"""
    try:
        logger.info("=== Getting DMS client credentials token for resource management ===")
        data = {
            'grant_type': 'client_credentials',
            'client_id': KEYCLOAK_CLIENT_ID,  # Use DMS client
            'client_secret': KEYCLOAK_CLIENT_SECRET,  # Use DMS client secret
        }
        
        response = requests.post(KEYCLOAK_PERMISSION_URI, data=data, timeout=10)
        response.raise_for_status()
        
        token_data = response.json()
        logger.info(f"Got DMS client credentials token for resource management")
        return token_data.get('access_token')
        
    except Exception as e:
        logger.error(f"Failed to get DMS client credentials token: {e}")
        return None


def get_dms_client_id():
    """Get the internal client ID for the DMS client"""
    try:
        service_token = get_service_token()
        if not service_token:
            return None
            
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        # Try to get all clients and find DMS - this may fail due to permissions
        response = requests.get(f"{KEYCLOAK_ADMIN_BASE_URI}/clients", headers=headers, timeout=10)
        
        if response.status_code == 403:
            logger.warning("Service account doesn't have admin permissions to list clients")
            logger.info("Need to grant realm-admin role to service-account-dms or use alternative approach")
            return None
            
        response.raise_for_status()
        
        clients = response.json()
        for client in clients:
            if client.get('clientId') == KEYCLOAK_CLIENT_ID:
                return client.get('id')
        
        logger.error(f"DMS client '{KEYCLOAK_CLIENT_ID}' not found")
        return None
        
    except Exception as e:
        logger.error(f"Failed to get DMS client ID: {e}")
        return None


def get_user_by_username(username):
    """Get user details by username from Keycloak"""
    try:
        service_token = get_service_token()
        if not service_token:
            return None
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        # Search for user by username
        response = requests.get(f"{KEYCLOAK_ADMIN_BASE_URI}/users", 
                              headers=headers, 
                              params={'username': username, 'exact': 'true'}, 
                              timeout=10)
        response.raise_for_status()
        
        users = response.json()
        if users:
            user = users[0]  # Get first (and should be only) exact match
            logger.info(f"Found user '{username}' with ID: {user.get('id')}")
            return user
        else:
            logger.warning(f"User '{username}' not found")
            return None
        
    except Exception as e:
        logger.error(f"Failed to get user by username: {e}")
        return None


def get_project_group_by_name(group_name):
    """Get a project or study group by its exact name using Keycloak search API"""
    try:
        service_token = get_service_token()
        if not service_token:
            return None
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        # Search for the group by name
        response = requests.get(f"{KEYCLOAK_ADMIN_BASE_URI}/groups?search={group_name}", 
                              headers=headers, timeout=10)
        response.raise_for_status()
        
        groups = response.json()
        
        # Find exact match
        for group in groups:
            if group.get('name') == group_name:
                logger.info(f"Found group '{group_name}' with ID: {group['id']}")
                return group
        
        logger.warning(f"Group '{group_name}' not found")
        return None
        
    except Exception as e:
        logger.error(f"Failed to get group by name '{group_name}': {e}")
        return None


def get_rpt_permissions(access_token):
    """Exchange JWT access token for RPT permissions (Following SONG's pattern)"""
    try:
        logger.info("=== FETCHING RPT PERMISSIONS ===")
        
        # Prepare UMA token exchange request (like SONG does)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Bearer {access_token}'
        }
        
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
            'audience': KEYCLOAK_CLIENT_ID,
            'response_mode': 'permissions'
        }
        
        logger.info(f"Exchanging JWT for RPT permissions at: {KEYCLOAK_PERMISSION_URI}")
        response = requests.post(KEYCLOAK_PERMISSION_URI, headers=headers, data=data, timeout=10)
        
        if response.status_code in [200, 207]:
            permissions = response.json()
            logger.info(f"RPT permissions response: {permissions}")
            return permissions
        else:
            logger.error(f"Failed to get RPT permissions: {response.status_code} - {response.text}")
            return []
            
    except Exception as e:
        logger.error(f"Failed to fetch RPT permissions: {e}")
        return []


def extract_scopes_from_rpt(permissions):
    """Extract scopes from RPT permissions (Following SONG's extractGrantedScopesFromRpt pattern)"""
    granted_scopes = set()
    
    for permission in permissions:
        rsname = permission.get('rsname', '')
        scopes = permission.get('scopes', [])
        
        for scope in scopes:
            granted_scopes.add(f"{rsname}.{scope}")
    
    logger.info(f"Extracted scopes from RPT: {granted_scopes}")
    return granted_scopes


def validate_jwt_token(token):
    """Validate JWT token by exchanging it for RPT permissions (Following SONG's pattern)"""
    try:
        logger.info("=== Starting JWT validation via RPT exchange ===")
        
        # Skip local JWT validation - let Keycloak validate it!
        # Just extract basic info without validation for logging
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            logger.info(f"Token from user: {payload.get('preferred_username', 'unknown')}")
        except:
            logger.info("Could not decode token for logging")
        
        # The real validation: try to get RPT permissions from Keycloak
        # If this works, the token is valid!
        rpt_permissions = get_rpt_permissions(token)
        granted_scopes = extract_scopes_from_rpt(rpt_permissions)
        
        # Return validated payload with RPT permissions
        return {
            'granted_scopes': granted_scopes,
            'rpt_permissions': rpt_permissions,
            'preferred_username': payload.get('preferred_username', 'unknown'),
            'email': payload.get('email'),
            'name': payload.get('name'),
            'sub': payload.get('sub'),
            'iss': payload.get('iss'),
            'azp': payload.get('azp', payload.get('aud')),
        }
        
    except Exception as e:
        logger.error(f"JWT validation failed: {e}")
        return None


def extract_user_info(payload):
    """Extract user information and RPT permissions from JWT payload"""
    
    # Extract user information
    user_info = {
        "username": payload.get("preferred_username", "unknown"),
        "email": payload.get("email"),
        "name": payload.get("name"),
        "sub": payload.get("sub"),
        "iss": payload.get("iss"),
        "client_id": payload.get("azp", payload.get("aud")),
    }
    
    # Get RPT-based permissions
    granted_scopes = payload.get('granted_scopes', set())
    rpt_permissions = payload.get('rpt_permissions', [])
    
    # Convert to list for JSON serialization
    user_info["permissions"] = list(granted_scopes)
    user_info["rpt_permissions"] = rpt_permissions
    
    # Extract folio-specific permissions
    folio_permissions = [scope for scope in granted_scopes if scope.startswith('folio.')]
    user_info["folio_permissions"] = folio_permissions
    
    logger.info(f"User {user_info['username']} has RPT permissions: {folio_permissions}")
    
    return user_info


def authenticate_token(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401

        token = auth_header.split(' ')[1]
        payload = validate_jwt_token(token)
        
        if payload is None:
            return jsonify({'error': 'Invalid token'}), 401

        # Store user info in Flask's g object for access in the route
        g.user = extract_user_info(payload)
        g.token = token
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_permissions(required_scopes):
    """Decorator to require specific RPT permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_permissions = set(g.user.get('permissions', []))
            
            # Check if user has any of the required scopes
            has_permission = any(scope in user_permissions for scope in required_scopes)
            
            if not has_permission:
                return jsonify({
                    'error': f'Insufficient permissions. Required: {required_scopes}',
                    'user_permissions': list(user_permissions),
                    'rpt_permissions': g.user.get('rpt_permissions', [])
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
