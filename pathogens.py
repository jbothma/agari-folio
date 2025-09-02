"""
Pathogen Management Module for Folio API

This module contains all pathogen-related endpoints and Keycloak
resource/group management functions.
"""

import logging
import requests
import traceback
import psycopg2
from psycopg2.extras import RealDictCursor
import uuid
from datetime import datetime
from flask_restx import Resource, fields
from flask import jsonify, g
from auth import (
    get_service_token, authenticate_token, require_permissions,
    KEYCLOAK_ADMIN_BASE_URI, KEYCLOAK_UMA_RESOURCE_URI, get_project_group_by_name,
    get_user_by_username
)
from utils import serialize_record, get_db_connection

logger = logging.getLogger(__name__)


def create_pathogen_resource(pathogen_name):
    """Create a Keycloak resource for a pathogen using UMA Resource Registration API"""
    try:
        logger.info(f"=== CREATING UMA RESOURCE FOR PATHOGEN: {pathogen_name} ===")
        
        service_token = get_service_token()
        if not service_token:
            logger.error("Failed to get service token")
            return False
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        # Create the resource using UMA Resource Registration API
        resource_data = {
            'name': pathogen_name,
            'displayName': f"Pathogen: {pathogen_name}",
            'type': 'urn:folio:resources:pathogen',
            'scopes': ['ADMIN'],  # Only ADMIN scope - anyone can read, only admin can edit
            'attributes': {
                'pathogen_name': [pathogen_name],
                'created_by': ['folio-service']
            }
        }
        
        # Use UMA Resource Registration endpoint
        response = requests.post(KEYCLOAK_UMA_RESOURCE_URI, headers=headers, json=resource_data, timeout=10)
        
        if response.status_code == 201:
            resource = response.json()
            logger.info(f"Successfully created UMA resource '{pathogen_name}' with ID: {resource.get('_id')}")
            logger.info(f"Resource scopes: {resource.get('scopes', [])}")
            return resource
        elif response.status_code == 409:
            logger.warning(f"UMA Resource '{pathogen_name}' already exists")
            return None
        else:
            logger.error(f"Failed to create UMA resource: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create pathogen resource: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def create_pathogen_group_with_permission(pathogen_name, permission):
    """Create a Keycloak group for a pathogen with specific permission (read, write, or admin)"""
    try:
        group_name = f"pathogen-{pathogen_name}-{permission}"
        logger.info(f"=== CREATING {permission.upper()} GROUP FOR PATHOGEN: {pathogen_name} ===")
        
        service_token = get_service_token()
        if not service_token:
            logger.error("Failed to get service token")
            return False
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        # Create the group data
        group_data = {
            'name': group_name,
            'path': f"/{group_name}",
            'attributes': {
                'pathogen_name': [pathogen_name],
                'permission': [permission],
                'created_by': ['folio-service'],
                'group_type': ['pathogen'],
                'description': [f"Pathogen {permission} group for {pathogen_name}"]
            }
        }
        
        # Create the group using Keycloak Admin API
        response = requests.post(f"{KEYCLOAK_ADMIN_BASE_URI}/groups", 
                               headers=headers, json=group_data, timeout=10)
        
        if response.status_code == 201:
            # Get the created group ID from Location header
            location = response.headers.get('Location')
            group_id = location.split('/')[-1] if location else None
            logger.info(f"Successfully created {permission} group '{group_name}' with ID: {group_id}")
            return True
        elif response.status_code == 409:
            logger.warning(f"{permission.capitalize()} group for pathogen '{pathogen_name}' already exists")
            return True
        else:
            logger.error(f"Failed to create {permission} group: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create {permission} group for pathogen {pathogen_name}: {e}")
        return False


def add_user_to_pathogen_group_with_permission(pathogen_name, username, permission):
    """Add a user to a pathogen group with specific permission (read, write, or admin)"""
    try:
        group_name = f"pathogen-{pathogen_name}-{permission}"
        logger.info(f"=== ADDING USER '{username}' TO {permission.upper()} GROUP '{group_name}' ===")
        
        # Get the specific permission group
        group = get_project_group_by_name(group_name)
        if not group:
            logger.error(f"Pathogen {permission} group '{group_name}' not found")
            return False
        
        # Get the user
        user = get_user_by_username(username)
        if not user:
            logger.error(f"User '{username}' not found")
            return False
        
        service_token = get_service_token()
        if not service_token:
            return False
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        group_id = group['id']
        user_id = user['id']
        
        # Add user to group
        response = requests.put(f"{KEYCLOAK_ADMIN_BASE_URI}/users/{user_id}/groups/{group_id}", 
                              headers=headers, timeout=10)
        
        if response.status_code == 204:
            logger.info(f"Successfully added user '{username}' to {permission} group '{group_name}'")
            return True
        else:
            logger.error(f"Failed to add user to {permission} group: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to add user '{username}' to {permission} group: {e}")
        return False


def setup_pathogen_endpoints(api, pathogens_ns):
    """Setup pathogen API endpoints"""
    
    # Define pathogen models for Swagger
    pathogen_model = api.model('Pathogen', {
        'id': fields.String(description='Pathogen UUID (auto-generated)', readonly=True),
        'name': fields.String(required=True, description='Pathogen name (unique identifier)'),
        'scientific_name': fields.String(description='Scientific name of the pathogen'),
        'description': fields.String(description='Detailed description of the pathogen'),
        'created_at': fields.DateTime(description='Creation timestamp (auto-generated)', readonly=True),
        'updated_at': fields.DateTime(description='Last update timestamp (auto-generated)', readonly=True)
    })

    pathogen_input_model = api.model('PathogenInput', {
        'name': fields.String(required=True, description='Pathogen name (must be unique)'),
        'scientific_name': fields.String(description='Scientific name of the pathogen'),
        'description': fields.String(description='Detailed description of the pathogen')
    })

    @pathogens_ns.route('')
    class PathogenList(Resource):
        @pathogens_ns.doc('list_pathogens', security='Bearer')
        @pathogens_ns.marshal_list_with(pathogen_model)
        @pathogens_ns.response(401, 'Invalid or missing token')
        @authenticate_token
        def get(self):
            """Get all pathogens (public access with valid token)"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Get all active pathogens (not deleted)
                cur.execute("""
                    SELECT id, name, scientific_name, description, created_at, updated_at
                    FROM pathogens 
                    WHERE deleted_at IS NULL
                    ORDER BY created_at DESC
                """)
                
                pathogens = cur.fetchall()
                
                # Convert to JSON-serializable format
                pathogen_list = [serialize_record(pathogen) for pathogen in pathogens]
                
                cur.close()
                conn.close()
                
                logger.info(f"Retrieved {len(pathogen_list)} pathogens for user: {g.user['username']}")
                return pathogen_list
                
            except Exception as e:
                logger.error(f"Error retrieving pathogens: {e}")
                return {"error": "Failed to retrieve pathogens"}, 500

        @pathogens_ns.doc('create_pathogen', security='Bearer')
        @pathogens_ns.expect(pathogen_input_model)
        @pathogens_ns.marshal_with(pathogen_model, code=201)
        @pathogens_ns.response(400, 'Invalid input data')
        @pathogens_ns.response(401, 'Invalid or missing token')
        @pathogens_ns.response(403, 'Insufficient permissions')
        @pathogens_ns.response(409, 'Pathogen name already exists')
        @require_permissions(["folio.WRITE"])
        def post(self):
            """Create a new pathogen (requires folio.WRITE permission)"""
            try:
                data = pathogens_ns.payload
                
                # Validate required fields
                if not data or not data.get('name'):
                    return {"error": "Pathogen name is required"}, 400
                
                # Generate UUID for pathogen
                pathogen_id = str(uuid.uuid4())
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if pathogen name already exists
                cur.execute("SELECT id FROM pathogens WHERE name = %s AND deleted_at IS NULL", 
                           (data['name'],))
                existing = cur.fetchone()
                
                if existing:
                    cur.close()
                    conn.close()
                    return {"error": f"Pathogen with name '{data['name']}' already exists"}, 409
                
                # Insert new pathogen
                cur.execute("""
                    INSERT INTO pathogens (id, name, scientific_name, description, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, NOW(), NOW())
                    RETURNING id, name, scientific_name, description, created_at, updated_at
                """, (
                    pathogen_id,
                    data['name'],
                    data.get('scientific_name'),
                    data.get('description')
                ))
                
                new_pathogen = cur.fetchone()
                conn.commit()
                cur.close()
                conn.close()
                
                # Create Keycloak resource for pathogen (optional - log if fails)
                try:
                    create_pathogen_resource(data['name'])
                    logger.info(f"Created Keycloak resource for pathogen: {data['name']}")
                except Exception as e:
                    logger.warning(f"Failed to create Keycloak resource for pathogen {data['name']}: {e}")
                
                logger.info(f"Created pathogen '{data['name']}' by user: {g.user['username']}")
                return serialize_record(new_pathogen), 201
                
            except Exception as e:
                logger.error(f"Error creating pathogen: {e}")
                return {"error": "Failed to create pathogen"}, 500

    @pathogens_ns.route('/<string:pathogen_id>')
    @pathogens_ns.param('pathogen_id', 'The pathogen UUID')
    class PathogenDetail(Resource):
        @pathogens_ns.doc('get_pathogen', security='Bearer')
        @pathogens_ns.marshal_with(pathogen_model)
        @pathogens_ns.response(401, 'Invalid or missing token')
        @pathogens_ns.response(404, 'Pathogen not found')
        @authenticate_token
        def get(self, pathogen_id):
            """Get pathogen details by ID"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                cur.execute("""
                    SELECT id, name, scientific_name, description, created_at, updated_at
                    FROM pathogens 
                    WHERE id = %s AND deleted_at IS NULL
                """, (pathogen_id,))
                
                pathogen = cur.fetchone()
                cur.close()
                conn.close()
                
                if not pathogen:
                    return {"error": "Pathogen not found"}, 404
                
                return serialize_record(pathogen)
                
            except Exception as e:
                logger.error(f"Error retrieving pathogen {pathogen_id}: {e}")
                return {"error": "Failed to retrieve pathogen"}, 500

        @pathogens_ns.doc('update_pathogen', security='Bearer')
        @pathogens_ns.expect(pathogen_input_model)
        @pathogens_ns.marshal_with(pathogen_model)
        @pathogens_ns.response(400, 'Invalid input data')
        @pathogens_ns.response(401, 'Invalid or missing token')
        @pathogens_ns.response(403, 'Insufficient permissions')
        @pathogens_ns.response(404, 'Pathogen not found')
        @pathogens_ns.response(409, 'Pathogen name already exists')
        @require_permissions(["folio.WRITE"])
        def put(self, pathogen_id):
            """Update a pathogen (requires folio.WRITE permission)"""
            try:
                data = pathogens_ns.payload
                
                if not data:
                    return {"error": "No data provided"}, 400
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if pathogen exists
                cur.execute("SELECT name FROM pathogens WHERE id = %s AND deleted_at IS NULL", (pathogen_id,))
                existing = cur.fetchone()
                
                if not existing:
                    cur.close()
                    conn.close()
                    return {"error": "Pathogen not found"}, 404
                
                # If name is being changed, check for uniqueness
                if 'name' in data and data['name'] != existing['name']:
                    cur.execute("SELECT id FROM pathogens WHERE name = %s AND deleted_at IS NULL AND id != %s", 
                               (data['name'], pathogen_id))
                    duplicate = cur.fetchone()
                    
                    if duplicate:
                        cur.close()
                        conn.close()
                        return {"error": f"Pathogen with name '{data['name']}' already exists"}, 409
                
                # Build update query dynamically
                update_fields = []
                values = []
                
                for field in ['name', 'scientific_name', 'description']:
                    if field in data:
                        update_fields.append(f"{field} = %s")
                        values.append(data[field])
                
                if not update_fields:
                    cur.close()
                    conn.close()
                    return {"error": "No valid fields to update"}, 400
                
                update_fields.append("updated_at = NOW()")
                values.append(pathogen_id)
                
                cur.execute(f"""
                    UPDATE pathogens 
                    SET {', '.join(update_fields)}
                    WHERE id = %s AND deleted_at IS NULL
                    RETURNING id, name, scientific_name, description, created_at, updated_at
                """, values)
                
                updated_pathogen = cur.fetchone()
                conn.commit()
                cur.close()
                conn.close()
                
                logger.info(f"Updated pathogen {pathogen_id} by user: {g.user['username']}")
                return serialize_record(updated_pathogen)
                
            except Exception as e:
                logger.error(f"Error updating pathogen {pathogen_id}: {e}")
                return {"error": "Failed to update pathogen"}, 500

        @pathogens_ns.doc('delete_pathogen', security='Bearer')
        @pathogens_ns.response(204, 'Pathogen deleted successfully')
        @pathogens_ns.response(401, 'Invalid or missing token')
        @pathogens_ns.response(403, 'Insufficient permissions')
        @pathogens_ns.response(404, 'Pathogen not found')
        @pathogens_ns.response(409, 'Cannot delete pathogen with associated projects')
        @require_permissions(["folio.WRITE"])
        def delete(self, pathogen_id):
            """Soft delete a pathogen (requires folio.WRITE permission)"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if pathogen exists
                cur.execute("SELECT name FROM pathogens WHERE id = %s AND deleted_at IS NULL", (pathogen_id,))
                pathogen = cur.fetchone()
                
                if not pathogen:
                    cur.close()
                    conn.close()
                    return {"error": "Pathogen not found"}, 404
                
                # Check for associated projects (cascade protection)
                cur.execute("SELECT COUNT(*) as count FROM projects WHERE pathogen_id = %s AND deleted_at IS NULL", 
                           (pathogen_id,))
                project_count = cur.fetchone()['count']
                
                if project_count > 0:
                    cur.close()
                    conn.close()
                    return {
                        "error": f"Cannot delete pathogen '{pathogen['name']}'. It has {project_count} associated project(s). Delete or reassign projects first."
                    }, 409
                
                # Soft delete the pathogen
                cur.execute("""
                    UPDATE pathogens 
                    SET deleted_at = NOW(), updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NULL
                """, (pathogen_id,))
                
                conn.commit()
                cur.close()
                conn.close()
                
                logger.info(f"Soft deleted pathogen {pathogen_id} by user: {g.user['username']}")
                return '', 204
                
            except Exception as e:
                logger.error(f"Error deleting pathogen {pathogen_id}: {e}")
                return {"error": "Failed to delete pathogen"}, 500
