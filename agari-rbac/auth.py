"""
Authentication Module for AGARI RBAC API

Simplified authentication focused on JWT token validation and role extraction.
This version focuses on extracting user information and roles from JWT tokens
rather than complex UMA permission checking.
"""

import logging
import jwt
import os
from functools import wraps
from flask import request, jsonify, g

logger = logging.getLogger(__name__)

# Keycloak configuration from environment variables
KEYCLOAK_HOST = os.getenv("KEYCLOAK_HOST", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "agari")
KEYCLOAK_ISSUER = os.getenv("KEYCLOAK_ISSUER", f"{KEYCLOAK_HOST}/realms/{KEYCLOAK_REALM}")


def extract_user_info_from_jwt(token):
    """
    Extract user information and roles from JWT token.
    
    This function decodes the JWT token without verification for now,
    focusing on extracting the role information we need for RBAC.
    
    Args:
        token (str): JWT token string
        
    Returns:
        dict: User information including roles, or None if invalid
    """
    try:
        # Decode JWT without verification for now - in production you'd verify the signature
        # This allows us to focus on the RBAC logic first
        payload = jwt.decode(token, options={"verify_signature": False})
        
        logger.info(f"Decoded JWT payload keys: {list(payload.keys())}")
        
        # Extract user basic info
        user_info = {
            "username": payload.get("preferred_username", "unknown"),
            "email": payload.get("email"),
            "name": payload.get("name"),
            "first_name": payload.get("given_name"),
            "last_name": payload.get("family_name"),
            "sub": payload.get("sub"),
            "iss": payload.get("iss"),
            "client_id": payload.get("azp", payload.get("aud")),
        }
        
        # Extract organisation information from custom attributes
        user_info["organisation_id"] = payload.get("organisation_id")
        
        # Extract roles from the token
        # Keycloak puts realm roles in realm_access.roles
        realm_roles = []
        if "realm_access" in payload and "roles" in payload["realm_access"]:
            realm_roles = payload["realm_access"]["roles"]
        
        # Filter to only include AGARI-specific roles
        agari_roles = [role for role in realm_roles if role.startswith(('agari-', 'system-admin'))]
        user_info["roles"] = agari_roles
        
        # Log what we extracted
        logger.info(f"User: {user_info['username']}")
        logger.info(f"Organisation: {user_info.get('organisation_id', 'unknown')}")
        logger.info(f"All realm roles: {realm_roles}")
        logger.info(f"AGARI roles: {agari_roles}")
        
        return user_info
        
    except jwt.DecodeError as e:
        logger.error(f"JWT decode error: {e}")
        return None
    except Exception as e:
        logger.error(f"Error extracting user info from JWT: {e}")
        return None


def authenticate_token(f):
    """
    Decorator to require valid JWT token and extract user information.
    
    This decorator:
    1. Checks for Authorization header
    2. Extracts JWT token
    3. Decodes user information and roles
    4. Stores user info in Flask's g object
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'error': 'Missing or invalid Authorization header',
                'message': 'Please provide a valid JWT token in the Authorization header'
            }), 401

        # Extract token
        token = auth_header.split(' ')[1]
        
        # Extract user information from token
        user_info = extract_user_info_from_jwt(token)
        
        if user_info is None:
            return jsonify({
                'error': 'Invalid token',
                'message': 'Could not decode or validate JWT token'
            }), 401

        # Store user info in Flask's g object for access in the route
        g.user = user_info
        g.token = token
        
        logger.info(f"Authenticated user: {user_info['username']} with roles: {user_info['roles']}")
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_permission(permission):
    """
    Decorator to require a specific permission.
    
    This decorator checks if the authenticated user has the specified permission
    based on their roles and the permissions matrix.
    
    Args:
        permission (str): The permission name to check
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Import here to avoid circular imports
            from permissions import has_permission
            
            user_roles = g.user.get('roles', [])
            
            if not has_permission(user_roles, permission):
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': f'Permission "{permission}" required',
                    'user_roles': user_roles,
                    'required_permission': permission
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def require_any_permission(*permissions):
    """
    Decorator to require any one of multiple permissions.
    
    Args:
        *permissions: Variable number of permission names
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from permissions import has_permission
            
            user_roles = g.user.get('roles', [])
            
            # Check if user has any of the required permissions
            has_any_permission = any(has_permission(user_roles, perm) for perm in permissions)
            
            if not has_any_permission:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': f'One of these permissions required: {list(permissions)}',
                    'user_roles': user_roles,
                    'required_permissions': list(permissions)
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def require_role(role):
    """
    Decorator to require a specific role.
    
    Args:
        role (str): The role name to check
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_roles = g.user.get('roles', [])
            
            if role not in user_roles:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': f'Role "{role}" required',
                    'user_roles': user_roles,
                    'required_role': role
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
