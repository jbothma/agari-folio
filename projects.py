"""
Project Management Module for Folio API

This module contains all project-related endpoints and Keycloak
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


def create_project_resource(project_code):
    """Create a Keycloak resource for a project using UMA Resource Registration API"""
    try:
        logger.info(f"=== CREATING UMA RESOURCE FOR PROJECT: {project_code} ===")
        
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
            'name': project_code,
            'displayName': f"Project: {project_code}",
            'type': 'urn:folio:resources:project',
            'scopes': ['READ', 'WRITE', 'ADMIN'],
            'attributes': {
                'project_code': [project_code],
                'created_by': ['folio-service']
            }
        }
        
        # Use UMA Resource Registration endpoint
        response = requests.post(KEYCLOAK_UMA_RESOURCE_URI, headers=headers, json=resource_data, timeout=10)
        
        if response.status_code == 201:
            resource = response.json()
            logger.info(f"Successfully created UMA resource '{project_code}' with ID: {resource.get('_id')}")
            logger.info(f"Resource scopes: {resource.get('scopes', [])}")
            return resource
        elif response.status_code == 409:
            logger.warning(f"UMA Resource '{project_code}' already exists")
            return None
        else:
            logger.error(f"Failed to create UMA resource: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create project resource: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def create_project_group_with_permission(project_code, permission):
    """Create a Keycloak group for a project with specific permission (read, write, or admin)"""
    try:
        group_name = f"project-{project_code}-{permission}"
        logger.info(f"=== CREATING {permission.upper()} GROUP FOR PROJECT: {project_code} ===")
        
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
                'project_code': [project_code],
                'permission': [permission],
                'created_by': ['folio-service'],
                'group_type': ['project'],
                'description': [f"Project {permission} group for {project_code}"]
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
            logger.warning(f"{permission.capitalize()} group for project '{project_code}' already exists")
            return True
        else:
            logger.error(f"Failed to create {permission} group: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create {permission} group for project {project_code}: {e}")
        return False


def add_user_to_project_group_with_permission(project_code, username, permission):
    """Add a user to a project group with specific permission (read, write, or admin)"""
    try:
        group_name = f"project-{project_code}-{permission}"
        logger.info(f"=== ADDING USER '{username}' TO {permission.upper()} GROUP '{group_name}' ===")
        
        # Get the specific permission group
        group = get_project_group_by_name(group_name)
        if not group:
            logger.error(f"Project {permission} group '{group_name}' not found")
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


def setup_project_endpoints(api, projects_ns):
    """Setup project API endpoints"""
    
    # Define project models for Swagger
    project_model = api.model('Project', {
        'id': fields.String(description='Project UUID (auto-generated)', readonly=True),
        'code': fields.String(required=True, description='Project code (unique identifier)'),
        'name': fields.String(required=True, description='Project name'),
        'description': fields.String(description='Project description'),
        'pathogen_id': fields.String(description='Associated pathogen UUID'),
        'pathogen_name': fields.String(description='Associated pathogen name (read-only)', readonly=True),
        'created_at': fields.DateTime(description='Creation timestamp (auto-generated)', readonly=True),
        'updated_at': fields.DateTime(description='Last update timestamp (auto-generated)', readonly=True)
    })

    project_input_model = api.model('ProjectInput', {
        'code': fields.String(required=True, description='Project code (must be unique)'),
        'name': fields.String(required=True, description='Project name'),
        'description': fields.String(description='Project description'),
        'pathogen_id': fields.String(description='Associated pathogen UUID')
    })

    @projects_ns.route('')
    class ProjectList(Resource):
        @projects_ns.doc('list_projects', security='Bearer')
        @projects_ns.marshal_list_with(project_model)
        @projects_ns.response(401, 'Invalid or missing token')
        @authenticate_token
        def get(self):
            """Get all projects (public access with valid token)"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Get all active projects with pathogen names
                cur.execute("""
                    SELECT p.id, p.code, p.name, p.description, p.pathogen_id, p.created_at, p.updated_at,
                           path.name as pathogen_name
                    FROM projects p
                    LEFT JOIN pathogens path ON p.pathogen_id = path.id AND path.deleted_at IS NULL
                    WHERE p.deleted_at IS NULL
                    ORDER BY p.created_at DESC
                """)
                
                projects = cur.fetchall()
                
                # Convert to JSON-serializable format
                project_list = [serialize_record(project) for project in projects]
                
                cur.close()
                conn.close()
                
                logger.info(f"Retrieved {len(project_list)} projects for user: {g.user['username']}")
                return project_list
                
            except Exception as e:
                logger.error(f"Error retrieving projects: {e}")
                return {"error": "Failed to retrieve projects"}, 500

        @projects_ns.doc('create_project', security='Bearer')
        @projects_ns.expect(project_input_model)
        @projects_ns.marshal_with(project_model, code=201)
        @projects_ns.response(400, 'Invalid input data')
        @projects_ns.response(401, 'Invalid or missing token')
        @projects_ns.response(403, 'Insufficient permissions')
        @projects_ns.response(409, 'Project code already exists')
        @require_permissions(["folio.WRITE"])
        def post(self):
            """Create a new project (requires folio.WRITE permission)"""
            try:
                data = projects_ns.payload
                
                # Validate required fields
                if not data or not data.get('code') or not data.get('name'):
                    return {"error": "Project code and name are required"}, 400
                
                # Generate UUID for project
                project_id = str(uuid.uuid4())
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if project code already exists
                cur.execute("SELECT id FROM projects WHERE code = %s AND deleted_at IS NULL", 
                           (data['code'],))
                existing = cur.fetchone()
                
                if existing:
                    cur.close()
                    conn.close()
                    return {"error": f"Project with code '{data['code']}' already exists"}, 409
                
                # Validate pathogen_id if provided
                pathogen_name = None
                if data.get('pathogen_id'):
                    cur.execute("SELECT name FROM pathogens WHERE id = %s AND deleted_at IS NULL", 
                               (data['pathogen_id'],))
                    pathogen = cur.fetchone()
                    
                    if not pathogen:
                        cur.close()
                        conn.close()
                        return {"error": "Invalid pathogen_id provided"}, 400
                    
                    pathogen_name = pathogen['name']
                
                # Insert new project
                cur.execute("""
                    INSERT INTO projects (id, code, name, description, pathogen_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                    RETURNING id, code, name, description, pathogen_id, created_at, updated_at
                """, (
                    project_id,
                    data['code'],
                    data['name'],
                    data.get('description'),
                    data.get('pathogen_id')
                ))
                
                new_project = cur.fetchone()
                conn.commit()
                cur.close()
                conn.close()
                
                # Add pathogen_name to response
                result = serialize_record(new_project)
                result['pathogen_name'] = pathogen_name
                
                # Create Keycloak resource and groups for project (optional - log if fails)
                try:
                    resource = create_project_resource(data['code'])
                    if resource:
                        logger.info(f"Created Keycloak resource for project: {data['code']}")
                        
                        # Create permission groups
                        for permission in ['read', 'write', 'admin']:
                            create_project_group_with_permission(data['code'], permission)
                except Exception as e:
                    logger.warning(f"Failed to create Keycloak resources for project {data['code']}: {e}")
                
                logger.info(f"Created project '{data['code']}' by user: {g.user['username']}")
                return result, 201
                
            except Exception as e:
                logger.error(f"Error creating project: {e}")
                return {"error": "Failed to create project"}, 500

    @projects_ns.route('/<string:project_id>')
    @projects_ns.param('project_id', 'The project UUID')
    class ProjectDetail(Resource):
        @projects_ns.doc('get_project', security='Bearer')
        @projects_ns.marshal_with(project_model)
        @projects_ns.response(401, 'Invalid or missing token')
        @projects_ns.response(404, 'Project not found')
        @authenticate_token
        def get(self, project_id):
            """Get project details by ID"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                cur.execute("""
                    SELECT p.id, p.code, p.name, p.description, p.pathogen_id, p.created_at, p.updated_at,
                           path.name as pathogen_name
                    FROM projects p
                    LEFT JOIN pathogens path ON p.pathogen_id = path.id AND path.deleted_at IS NULL
                    WHERE p.id = %s AND p.deleted_at IS NULL
                """, (project_id,))
                
                project = cur.fetchone()
                cur.close()
                conn.close()
                
                if not project:
                    return {"error": "Project not found"}, 404
                
                return serialize_record(project)
                
            except Exception as e:
                logger.error(f"Error retrieving project {project_id}: {e}")
                return {"error": "Failed to retrieve project"}, 500

        @projects_ns.doc('update_project', security='Bearer')
        @projects_ns.expect(project_input_model)
        @projects_ns.marshal_with(project_model)
        @projects_ns.response(400, 'Invalid input data')
        @projects_ns.response(401, 'Invalid or missing token')
        @projects_ns.response(403, 'Insufficient permissions')
        @projects_ns.response(404, 'Project not found')
        @projects_ns.response(409, 'Project code already exists')
        @require_permissions(["folio.WRITE"])
        def put(self, project_id):
            """Update a project (requires folio.WRITE permission)"""
            try:
                data = projects_ns.payload
                
                if not data:
                    return {"error": "No data provided"}, 400
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if project exists
                cur.execute("SELECT code FROM projects WHERE id = %s AND deleted_at IS NULL", (project_id,))
                existing = cur.fetchone()
                
                if not existing:
                    cur.close()
                    conn.close()
                    return {"error": "Project not found"}, 404
                
                # If code is being changed, check for uniqueness
                if 'code' in data and data['code'] != existing['code']:
                    cur.execute("SELECT id FROM projects WHERE code = %s AND deleted_at IS NULL AND id != %s", 
                               (data['code'], project_id))
                    duplicate = cur.fetchone()
                    
                    if duplicate:
                        cur.close()
                        conn.close()
                        return {"error": f"Project with code '{data['code']}' already exists"}, 409
                
                # Validate pathogen_id if provided
                if 'pathogen_id' in data and data['pathogen_id']:
                    cur.execute("SELECT name FROM pathogens WHERE id = %s AND deleted_at IS NULL", 
                               (data['pathogen_id'],))
                    pathogen = cur.fetchone()
                    
                    if not pathogen:
                        cur.close()
                        conn.close()
                        return {"error": "Invalid pathogen_id provided"}, 400
                
                # Build update query dynamically
                update_fields = []
                values = []
                
                for field in ['code', 'name', 'description', 'pathogen_id']:
                    if field in data:
                        update_fields.append(f"{field} = %s")
                        values.append(data[field])
                
                if not update_fields:
                    cur.close()
                    conn.close()
                    return {"error": "No valid fields to update"}, 400
                
                update_fields.append("updated_at = NOW()")
                values.append(project_id)
                
                cur.execute(f"""
                    UPDATE projects 
                    SET {', '.join(update_fields)}
                    WHERE id = %s AND deleted_at IS NULL
                    RETURNING id, code, name, description, pathogen_id, created_at, updated_at
                """, values)
                
                updated_project = cur.fetchone()
                
                # Get pathogen name if pathogen_id exists
                pathogen_name = None
                if updated_project['pathogen_id']:
                    cur.execute("SELECT name FROM pathogens WHERE id = %s", 
                               (updated_project['pathogen_id'],))
                    pathogen = cur.fetchone()
                    if pathogen:
                        pathogen_name = pathogen['name']
                
                conn.commit()
                cur.close()
                conn.close()
                
                # Add pathogen_name to response
                result = serialize_record(updated_project)
                result['pathogen_name'] = pathogen_name
                
                logger.info(f"Updated project {project_id} by user: {g.user['username']}")
                return result
                
            except Exception as e:
                logger.error(f"Error updating project {project_id}: {e}")
                return {"error": "Failed to update project"}, 500

        @projects_ns.doc('delete_project', security='Bearer')
        @projects_ns.response(204, 'Project deleted successfully')
        @projects_ns.response(401, 'Invalid or missing token')
        @projects_ns.response(403, 'Insufficient permissions')
        @projects_ns.response(404, 'Project not found')
        @projects_ns.response(409, 'Cannot delete project with associated studies')
        @require_permissions(["folio.WRITE"])
        def delete(self, project_id):
            """Soft delete a project (requires folio.WRITE permission)"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if project exists
                cur.execute("SELECT code FROM projects WHERE id = %s AND deleted_at IS NULL", (project_id,))
                project = cur.fetchone()
                
                if not project:
                    cur.close()
                    conn.close()
                    return {"error": "Project not found"}, 404
                
                # Check for associated studies (cascade protection)
                cur.execute("SELECT COUNT(*) as count FROM studies WHERE project_id = %s AND deleted_at IS NULL", 
                           (project_id,))
                study_count = cur.fetchone()['count']
                
                if study_count > 0:
                    cur.close()
                    conn.close()
                    return {
                        "error": f"Cannot delete project '{project['code']}'. It has {study_count} associated study/studies. Delete or reassign studies first."
                    }, 409
                
                # Soft delete the project
                cur.execute("""
                    UPDATE projects 
                    SET deleted_at = NOW(), updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NULL
                """, (project_id,))
                
                conn.commit()
                cur.close()
                conn.close()
                
                logger.info(f"Soft deleted project {project_id} by user: {g.user['username']}")
                return '', 204
                
            except Exception as e:
                logger.error(f"Error deleting project {project_id}: {e}")
                return {"error": "Failed to delete project"}, 500
