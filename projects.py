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


def create_project_policy(project_code, permission, group_id):
    """Create a Keycloak policy for a project group"""
    try:
        policy_name = f"project-{project_code}-{permission}-policy"
        logger.info(f"=== CREATING {permission.upper()} POLICY FOR PROJECT: {project_code} ===")
        
        service_token = get_service_token()
        if not service_token:
            logger.error("Failed to get service token")
            return False
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        # Get DMS client ID
        clients_response = requests.get(f"{KEYCLOAK_ADMIN_BASE_URI}/clients?clientId=dms", 
                                      headers=headers, timeout=10)
        if clients_response.status_code != 200:
            logger.error(f"Failed to get DMS client: {clients_response.status_code}")
            return False
        
        clients = clients_response.json()
        if not clients:
            logger.error("DMS client not found")
            return False
        
        client_uuid = clients[0]['id']
        
        # Create group-based policy
        policy_data = {
            'name': policy_name,
            'description': f'Policy for {permission} access to project {project_code}',
            'type': 'group',
            'logic': 'POSITIVE',
            'decisionStrategy': 'UNANIMOUS',
            'groups': [{'id': group_id, 'extendChildren': False}]
        }
        
        # Create the policy using Keycloak Admin API
        response = requests.post(f"{KEYCLOAK_ADMIN_BASE_URI}/clients/{client_uuid}/authz/resource-server/policy/group", 
                               headers=headers, json=policy_data, timeout=10)
        
        if response.status_code == 201:
            policy = response.json()
            logger.info(f"Successfully created {permission} policy '{policy_name}' with ID: {policy.get('id')}")
            return policy
        elif response.status_code == 409:
            logger.warning(f"{permission.capitalize()} policy for project '{project_code}' already exists")
            # Try to get existing policy
            policies_response = requests.get(f"{KEYCLOAK_ADMIN_BASE_URI}/clients/{client_uuid}/authz/resource-server/policy?name={policy_name}", 
                                           headers=headers, timeout=10)
            if policies_response.status_code == 200:
                policies = policies_response.json()
                if policies:
                    return policies[0]
            return None
        else:
            logger.error(f"Failed to create {permission} policy: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create {permission} policy for project {project_code}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def create_project_permission(project_id, permission, resource_id, policy_id, scopes):
    """Create a Keycloak permission linking policy to resource"""
    try:
        permission_name = f"project-{project_id}-{permission}-permission"
        logger.info(f"=== CREATING {permission.upper()} PERMISSION FOR PROJECT: {project_id} ===")
        
        service_token = get_service_token()
        if not service_token:
            logger.error("Failed to get service token")
            return False
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        # Get DMS client ID
        clients_response = requests.get(f"{KEYCLOAK_ADMIN_BASE_URI}/clients?clientId=dms", 
                                      headers=headers, timeout=10)
        if clients_response.status_code != 200:
            logger.error(f"Failed to get DMS client: {clients_response.status_code}")
            return False
        
        clients = clients_response.json()
        if not clients:
            logger.error("DMS client not found")
            return False
        
        client_uuid = clients[0]['id']
        
        # Create resource-based permission
        permission_data = {
            'name': permission_name,
            'description': f'Permission for {permission} access to project {project_id}',
            'type': 'resource',
            'logic': 'POSITIVE',
            'decisionStrategy': 'UNANIMOUS',
            'resources': [resource_id],
            'policies': [policy_id],
            'scopes': scopes
        }
        
        # Create the permission using Keycloak Admin API
        response = requests.post(f"{KEYCLOAK_ADMIN_BASE_URI}/clients/{client_uuid}/authz/resource-server/permission/resource", 
                               headers=headers, json=permission_data, timeout=10)
        
        if response.status_code == 201:
            permission = response.json()
            logger.info(f"Successfully created {permission} permission '{permission_name}' with ID: {permission.get('id')}")
            return permission
        elif response.status_code == 409:
            logger.warning(f"{permission.capitalize()} permission for project '{project_id}' already exists")
            return None
        else:
            logger.error(f"Failed to create {permission} permission: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create {permission} permission for project {project_id}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
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


def add_creator_to_project_admin_group(project_code, username):
    """Add the project creator to the admin group - convenience function for project creation"""
    return add_user_to_project_group_with_permission(project_code, username, 'admin')


def remove_user_from_project_group_with_permission(project_code, username, permission):
    """Remove a user from a project group with specific permission (read, write, or admin)"""
    try:
        group_name = f"project-{project_code}-{permission}"
        logger.info(f"=== REMOVING USER '{username}' FROM {permission.upper()} GROUP '{group_name}' ===")
        
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
        
        # Remove user from group
        response = requests.delete(f"{KEYCLOAK_ADMIN_BASE_URI}/users/{user_id}/groups/{group_id}", 
                                 headers=headers, timeout=10)
        
        if response.status_code == 204:
            logger.info(f"Successfully removed user '{username}' from {permission} group '{group_name}'")
            return True
        else:
            logger.error(f"Failed to remove user from {permission} group: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to remove user '{username}' from {permission} group: {e}")
        return False


def manage_project_user_permissions(project_code, username, permissions_to_add=None, permissions_to_remove=None):
    """
    Manage user permissions for a project by adding/removing from multiple groups
    
    Args:
        project_code: The project slug/code
        username: Username to manage permissions for
        permissions_to_add: List of permissions to add (e.g., ['read', 'write'])
        permissions_to_remove: List of permissions to remove (e.g., ['admin'])
    
    Returns:
        dict: Status of operations
    """
    results = {
        'added': [],
        'removed': [],
        'failed_add': [],
        'failed_remove': []
    }
    
    if permissions_to_add:
        for permission in permissions_to_add:
            if add_user_to_project_group_with_permission(project_code, username, permission):
                results['added'].append(permission)
            else:
                results['failed_add'].append(permission)
    
    if permissions_to_remove:
        for permission in permissions_to_remove:
            if remove_user_from_project_group_with_permission(project_code, username, permission):
                results['removed'].append(permission)
            else:
                results['failed_remove'].append(permission)
    
    return results


def setup_project_endpoints(api, projects_ns):
    """Setup project API endpoints"""
    
    # Define project models for Swagger
    project_model = api.model('Project', {
        'id': fields.String(description='Project UUID (auto-generated)', readonly=True),
        'slug': fields.String(required=True, description='Project slug (unique identifier)'),
        'name': fields.String(required=True, description='Project name'),
        'description': fields.String(description='Project description'),
        'pathogen_id': fields.String(description='Associated pathogen UUID'),
        'pathogen_name': fields.String(description='Associated pathogen name (read-only)', readonly=True),
        'created_at': fields.DateTime(description='Creation timestamp (auto-generated)', readonly=True),
        'updated_at': fields.DateTime(description='Last update timestamp (auto-generated)', readonly=True)
    })

    project_input_model = api.model('ProjectInput', {
        'slug': fields.String(required=True, description='Project slug (must be unique)'),
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
                    SELECT p.id, p.slug, p.name, p.description, p.pathogen_id, p.created_at, p.updated_at,
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
        @authenticate_token
        @require_permissions(["folio.WRITE"])
        def post(self):
            """Create a new project (requires folio.WRITE permission)"""
            try:
                data = projects_ns.payload
                
                # Validate required fields
                if not data or not data.get('slug') or not data.get('name'):
                    return {"error": "Project slug and name are required"}, 400
                
                # Generate UUID for project
                project_id = str(uuid.uuid4())
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if project slug already exists
                cur.execute("SELECT id FROM projects WHERE slug = %s AND deleted_at IS NULL", 
                           (data['slug'],))
                existing = cur.fetchone()
                
                if existing:
                    cur.close()
                    conn.close()
                    return {"error": f"Project with slug '{data['slug']}' already exists"}, 409
                
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
                    INSERT INTO projects (id, slug, name, description, pathogen_id, organization_id, user_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                    RETURNING id, slug, name, description, pathogen_id, created_at, updated_at
                """, (
                    project_id,
                    data['slug'],
                    data['name'],
                    data.get('description'),
                    data.get('pathogen_id'),
                    'default-org',  # TODO: Get from user context
                    g.user.get('sub', 'unknown')  # User ID from token
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
                    # Always try to create/ensure groups exist, regardless of resource status
                    resource = create_project_resource(data['slug'])
                    logger.info(f"Ensured Keycloak resource exists for project: {data['slug']}")
                    
                    # Create permission groups and policies/permissions
                    for permission in ['read', 'write', 'admin']:
                        # Create the group
                        create_project_group_with_permission(data['slug'], permission)
                        
                        # Get the group to extract its ID for policy creation
                        group = get_project_group_by_name(f"project-{data['slug']}-{permission}")
                        if group and resource:
                            group_id = group['id']
                            resource_id = resource.get('_id')
                            
                            # Create policy for this group
                            policy = create_project_policy(data['slug'], permission, group_id)
                            
                            # Create permission linking policy to resource
                            if policy:
                                policy_id = policy.get('id')
                                scopes = []
                                if permission == 'read':
                                    scopes = ['READ']
                                elif permission == 'write':
                                    scopes = ['READ', 'WRITE']
                                elif permission == 'admin':
                                    scopes = ['READ', 'WRITE', 'ADMIN']
                                
                                create_project_permission(data['slug'], permission, resource_id, policy_id, scopes)
                    
                    # Add the creating user to the admin group for this project
                    if add_creator_to_project_admin_group(data['slug'], g.user['username']):
                        logger.info(f"Added user '{g.user['username']}' to admin group for project: {data['slug']}")
                    else:
                        logger.warning(f"Failed to add user '{g.user['username']}' to admin group for project: {data['slug']}")
                    
                except Exception as e:
                    logger.warning(f"Failed to create Keycloak resources for project {data['slug']}: {e}")
                    logger.warning(f"Traceback: {traceback.format_exc()}")
                
                logger.info(f"Created project '{data['slug']}' by user: {g.user['username']}")
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
                    SELECT p.id, p.slug, p.name, p.description, p.pathogen_id, p.created_at, p.updated_at,
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
        @authenticate_token
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
                cur.execute("SELECT slug FROM projects WHERE id = %s AND deleted_at IS NULL", (project_id,))
                existing = cur.fetchone()
                
                if not existing:
                    cur.close()
                    conn.close()
                    return {"error": "Project not found"}, 404
                
                # If slug is being changed, check for uniqueness
                if 'slug' in data and data['slug'] != existing['slug']:
                    cur.execute("SELECT id FROM projects WHERE slug = %s AND deleted_at IS NULL AND id != %s", 
                               (data['slug'], project_id))
                    duplicate = cur.fetchone()
                    
                    if duplicate:
                        cur.close()
                        conn.close()
                        return {"error": f"Project with slug '{data['slug']}' already exists"}, 409
                
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
                
                for field in ['slug', 'name', 'description', 'pathogen_id']:
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
        @authenticate_token
        @require_permissions(["folio.WRITE"])
        def delete(self, project_id):
            """Soft delete a project (requires folio.WRITE permission)"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if project exists
                cur.execute("SELECT slug FROM projects WHERE id = %s AND deleted_at IS NULL", (project_id,))
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
