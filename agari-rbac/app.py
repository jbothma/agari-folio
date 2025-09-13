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

# Import database and models
from database import check_db_connection, init_database
from models import Pathogen, Project, Study

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)

# Initialize database when the app starts
with app.app_context():
    try:
        logger.info("Initializing database...")
        init_database()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

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
        db_status = "connected" if check_db_connection() else "disconnected"
        
        return {
            "status": "healthy" if db_status == "connected" else "degraded",
            "message": "AGARI Folio API is running",
            "version": "1.0",
            "database": db_status
        }


# Data Management Namespaces
pathogens_ns = api.namespace('pathogens', description='Pathogen management operations')

# Pathogen management endpoints
@pathogens_ns.route('')
class PathogenList(Resource):
    @api.doc('list_pathogens')
    def get(self):
        """Get all pathogens"""
        try:
            pathogens = Pathogen.get_all()
            return {
                "status": "success",
                "data": pathogens,
                "count": len(pathogens)
            }
        except Exception as e:
            logger.error(f"Failed to fetch pathogens: {e}")
            return {
                "status": "error",
                "message": f"Failed to fetch pathogens: {str(e)}"
            }, 500
    
    @api.doc('create_pathogen')
    @api.expect(api.model('PathogenCreate', {
        'name': fields.String(required=True, description='Pathogen name'),
        'scientific_name': fields.String(description='Scientific name'),
        'description': fields.String(description='Description')
    }))
    @authenticate_token
    def post(self):
        """Create a new pathogen (requires create_pathogen permission)"""
        user_roles = g.user.get('roles', [])
        if 'create_pathogen' not in get_user_permissions(user_roles):
            return {
                "status": "error",
                "message": "Insufficient permissions to create pathogen"
            }, 403
        
        try:
            data = request.json
            pathogen = Pathogen.create(
                name=data['name'],
                scientific_name=data.get('scientific_name'),
                description=data.get('description')
            )
            return {
                "status": "success",
                "data": pathogen
            }, 201
        except Exception as e:
            logger.error(f"Failed to create pathogen: {e}")
            return {
                "status": "error",
                "message": f"Failed to create pathogen: {str(e)}"
            }, 500

@pathogens_ns.route('/<string:pathogen_id>')
class PathogenDetail(Resource):
    @api.doc('get_pathogen')
    def get(self, pathogen_id):
        """Get a specific pathogen by ID"""
        try:
            pathogen = Pathogen.get_by_id(pathogen_id)
            if not pathogen:
                return {
                    "status": "error",
                    "message": "Pathogen not found"
                }, 404
            
            return {
                "status": "success",
                "data": pathogen
            }
        except Exception as e:
            logger.error(f"Failed to fetch pathogen: {e}")
            return {
                "status": "error",
                "message": f"Failed to fetch pathogen: {str(e)}"
            }, 500
    
    @api.doc('update_pathogen')
    @api.expect(api.model('PathogenUpdate', {
        'name': fields.String(description='Pathogen name'),
        'scientific_name': fields.String(description='Scientific name'),
        'description': fields.String(description='Description')
    }))
    @authenticate_token
    def put(self, pathogen_id):
        """Update a pathogen (requires edit_pathogen permission)"""
        user_roles = g.user.get('roles', [])
        if 'edit_pathogen' not in get_user_permissions(user_roles):
            return {
                "status": "error",
                "message": "Insufficient permissions to edit pathogen"
            }, 403
        
        try:
            # Check if pathogen exists
            existing_pathogen = Pathogen.get_by_id(pathogen_id)
            if not existing_pathogen:
                return {
                    "status": "error",
                    "message": "Pathogen not found"
                }, 404
            
            # Update pathogen
            data = request.json or {}
            updated_pathogen = Pathogen.update(pathogen_id, **data)
            
            return {
                "status": "success",
                "data": updated_pathogen,
                "message": "Pathogen updated successfully"
            }
        except Exception as e:
            logger.error(f"Failed to update pathogen: {e}")
            return {
                "status": "error",
                "message": f"Failed to update pathogen: {str(e)}"
            }, 500
    
    @api.doc('delete_pathogen')
    @authenticate_token
    def delete(self, pathogen_id):
        """Delete a pathogen (requires delete_pathogen permission)"""
        user_roles = g.user.get('roles', [])
        if 'delete_pathogen' not in get_user_permissions(user_roles):
            return {
                "status": "error",
                "message": "Insufficient permissions to delete pathogen"
            }, 403
        
        try:
            # Check if pathogen exists
            existing_pathogen = Pathogen.get_by_id(pathogen_id)
            if not existing_pathogen:
                return {
                    "status": "error",
                    "message": "Pathogen not found"
                }, 404
            
            # Check if pathogen is referenced by any projects
            if Pathogen.is_referenced_by_projects(pathogen_id):
                return {
                    "status": "error",
                    "message": "Cannot delete pathogen: it is referenced by one or more projects"
                }, 409  # Conflict
            
            # Soft delete the pathogen
            deleted = Pathogen.delete(pathogen_id)
            if deleted:
                return {
                    "status": "success",
                    "message": "Pathogen deleted successfully"
                }
            else:
                return {
                    "status": "error",
                    "message": "Failed to delete pathogen"
                }, 500
        except Exception as e:
            logger.error(f"Failed to delete pathogen: {e}")
            return {
                "status": "error",
                "message": f"Failed to delete pathogen: {str(e)}"
            }, 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return {"error": "Endpoint not found"}, 404


@app.errorhandler(500)
def internal_error(error):
    return {"error": "Internal server error"}, 500


if __name__ == '__main__':
    # Initialize database on startup
    try:
        logger.info("Initializing database...")
        init_database()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        # Continue running even if database init fails to allow debugging
    
    app.run(host='0.0.0.0', port=5001, debug=True)
