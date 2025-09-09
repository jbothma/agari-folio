"""
Folio API - Main Application Module

This is the main Flask application that sets up the API, Swagger documentation,
and registers all endpoints from modular components.
"""

from flask import Flask
from flask_restx import Api, Resource, fields
import logging

from pathogens import setup_pathogen_endpoints
from projects import setup_project_endpoints
from studies import setup_study_endpoints
from utils import get_db_connection

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)

# Initialize Flask-RESTX for Swagger documentation
api = Api(
    app,
    version='1.0',
    title='Folio API',
    description='''
    **Folio API - Complete CRUD API for AGARI Genomics Data Management**
    
    ## Overview
    Folio provides a comprehensive REST API for managing genomics research data with JWT authentication, 
    role-based access control, and Keycloak integration.
    
    ## Features
    - **JWT Authentication**: Secure token-based authentication via Keycloak
    - **Role-based Access Control**: Granular permissions with `folio.READ` and `folio.WRITE` scopes
    - **Complete CRUD Operations**: Full Create, Read, Update, Delete operations for all entities
    - **Soft Deletes**: All delete operations preserve data integrity with timestamp-based soft deletion
    - **Cascade Protection**: Prevents deletion of entities with dependencies (e.g., pathogen with projects)
    - **Keycloak Integration**: Automatic project and study group creation and user management
    
    ## Entity Hierarchy
    ```
    Pathogens (managed by super users)
    └── Projects (with read/write/admin groups)
        └── Studies (with read/write/admin groups)
    ```
    
    ## Permission Model
    - **Public Access**: Anyone with valid token can view pathogens
    - **Super User (`folio.WRITE`)**: Can create/edit/delete pathogens, projects, and studies
    - **Project Members**: Automatic group-based permissions (read/write/admin) for project access
    - **Study Members**: Automatic group-based permissions (read/write/admin) for study access
    - **Data Protection**: Cascade deletion prevention maintains referential integrity
    
    ## Getting Started
    1. Obtain JWT token from Keycloak
    2. Include token in Authorization header: `Bearer <your-jwt-token>`
    3. Explore entity endpoints: `/pathogens`, `/projects`, `/studies`
    ''',
    doc='/docs/',  # Swagger UI will be available at /docs/
    authorizations={
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'JWT Bearer token. Format: Bearer <token>'
        }
    },
    security='Bearer'
)

# Create API namespaces
health_ns = api.namespace('health', description='Health check operations')
projects_ns = api.namespace('projects', description='Project CRUD operations and group management - Full lifecycle management including Keycloak integration')
pathogens_ns = api.namespace('pathogens', description='Pathogen CRUD operations - Super user management of pathogen entities with cascade protection')
studies_ns = api.namespace('studies', description='Study CRUD operations and group management - Complete lifecycle management including Keycloak integration and user management')


# Health check endpoint
@health_ns.route('')
class HealthCheck(Resource):
    @health_ns.doc('health_check')
    def get(self):
        """Health check endpoint - returns API status"""
        try:
            # Test database connection
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            cur.close()
            conn.close()
            
            return {
                "status": "healthy",
                "message": "Folio API is running",
                "database": "connected",
                "version": "1.0"
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": "Database connection failed",
                "error": str(e),
                "version": "1.0"
            }, 500


# Setup endpoints from modules
setup_pathogen_endpoints(api, pathogens_ns)
setup_project_endpoints(api, projects_ns)
setup_study_endpoints(api, studies_ns)


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return {"error": "Endpoint not found"}, 404


@app.errorhandler(500)
def internal_error(error):
    return {"error": "Internal server error"}, 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
