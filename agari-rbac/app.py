"""
AGARI RBAC API - Role-Based Access Control System

A Flask application focused on implementing the AGARI permissions matrix
based on Keycloak JWT tokens and user roles.
"""

from flask import Flask, jsonify, request, g
from flask_restx import Api, Resource, fields
import logging
import jwt
import os
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)

# Initialize Flask-RESTX for Swagger documentation
api = Api(
    app,
    version='1.0',
    title='AGARI RBAC API',
    description='''
    **AGARI Role-Based Access Control API**
    
    ## Overview
    This API implements the AGARI permissions matrix based on user roles extracted from Keycloak JWT tokens.
    
    ## Roles
    - **system-admin**: Global system administrator with all permissions
    - **agari-org-owner**: Organisation owner with full organisation control
    - **agari-org-admin**: Organisation administrator with member management
    - **agari-project-admin**: Project administrator with project-specific control
    - **agari-contributor**: Can contribute data to assigned projects
    - **agari-viewer**: Read-only access to assigned projects
    
    ## Permissions Matrix
    The system uses a permission matrix to determine what actions each role can perform.
    ''',
    doc='/docs/',
    authorizations={
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'JWT Bearer token from Keycloak. Format: Bearer <token>'
        }
    },
    security='Bearer'
)

# Import the permissions matrix and auth functions
from permissions import PERMISSIONS_MATRIX, get_user_permissions
from auth import authenticate_token

# Create namespaces
auth_ns = api.namespace('auth', description='Authentication and user info operations')
permissions_ns = api.namespace('permissions', description='Permission checking operations')


@auth_ns.route('/user')
class UserInfo(Resource):
    @api.doc('get_user_info')
    @authenticate_token
    def get(self):
        """Get current user information from JWT token"""
        return {
            'user': g.user,
            'permissions': get_user_permissions(g.user.get('roles', []))
        }


@auth_ns.route('/whoami')
class WhoAmI(Resource):
    @api.doc('whoami')
    @authenticate_token
    def get(self):
        """Simple endpoint to check authentication status"""
        return {
            'username': g.user.get('username', 'unknown'),
            'email': g.user.get('email'),
            'organisation_id': g.user.get('organisation_id'),
            'roles': g.user.get('roles', []),
            'authenticated': True
        }


@permissions_ns.route('/check/<permission>')
class PermissionCheck(Resource):
    @api.doc('check_permission')
    @authenticate_token
    def get(self, permission):
        """Check if current user has a specific permission"""
        user_permissions = get_user_permissions(g.user.get('roles', []))
        has_permission = permission in user_permissions
        
        return {
            'permission': permission,
            'granted': has_permission,
            'user_roles': g.user.get('roles', []),
            'user_permissions': list(user_permissions)
        }


@permissions_ns.route('/matrix')
class PermissionsMatrix(Resource):
    @api.doc('get_permissions_matrix')
    def get(self):
        """Get the complete permissions matrix"""
        return {
            'permissions_matrix': PERMISSIONS_MATRIX,
            'description': 'Maps permissions to roles that can perform them'
        }


@permissions_ns.route('/my-permissions')
class MyPermissions(Resource):
    @api.doc('get_my_permissions')
    @authenticate_token
    def get(self):
        """Get all permissions for the current user"""
        user_permissions = get_user_permissions(g.user.get('roles', []))
        
        return {
            'user_roles': g.user.get('roles', []),
            'permissions': list(user_permissions),
            'permission_count': len(user_permissions)
        }


# Health check endpoint
@api.route('/health')
class HealthCheck(Resource):
    @api.doc('health_check')
    def get(self):
        """Health check endpoint"""
        return {
            "status": "healthy",
            "message": "AGARI RBAC API is running",
            "version": "1.0"
        }


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return {"error": "Endpoint not found"}, 404


@app.errorhandler(500)
def internal_error(error):
    return {"error": "Internal server error"}, 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
