"""
Study Management Module for Folio API

This module contains all study-related endpoints and SONG integration.
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
    authenticate_token, require_permissions, require_study_access, get_service_token,
    KEYCLOAK_ADMIN_BASE_URI, KEYCLOAK_UMA_RESOURCE_URI
)
from utils import serialize_record, get_db_connection

logger = logging.getLogger(__name__)

# SONG service configuration
SONG_BASE_URI = "http://song.agari.svc.cluster.local:8080"


def create_study_in_song(study_id, name, description):
    """Create a study in SONG service using service token"""
    try:
        logger.info(f"=== CREATING STUDY IN SONG: {study_id} ===")
        
        # Get service token instead of using user token
        service_token = get_service_token()
        if not service_token:
            logger.error("Failed to get service token for SONG")
            return False
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        study_data = {
            'studyId': study_id,
            'name': name,
            'description': description or f"Study {study_id}",
            'organization': 'AGARI',
            'info': {
                'projectType': 'genomics',
                'region': 'South Africa',
                'createdBy': 'folio-service'
            }
        }
        
        response = requests.post(f"{SONG_BASE_URI}/studies/{study_id}/", 
                               headers=headers, json=study_data, timeout=30)
        
        if response.status_code == 201:
            song_study = response.json()
            logger.info(f"Successfully created study '{study_id}' in SONG")
            return song_study
        elif response.status_code == 409:
            logger.warning(f"Study '{study_id}' already exists in SONG")
            return None
        else:
            logger.error(f"Failed to create study in SONG: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create study in SONG: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def create_study_resource(study_id):
    """Create Keycloak permissions for a study using the existing 'song' resource"""
    try:
        logger.info(f"=== CREATING STUDY PERMISSIONS FOR: {study_id} ===")
        
        # Instead of creating a new UMA resource, return a reference to the existing 'song' resource
        # This ensures users get simple READ/WRITE scopes that SONG can properly match
        song_resource = {
            '_id': 'aa9aaeff-84ed-4c69-ade1-19179bedafd1',  # Song resource ID from realm
            'name': 'song',
            'study_id': study_id
        }
        
        logger.info(f"Using existing song resource for study '{study_id}'")
        return song_resource
            
    except Exception as e:
        logger.error(f"Failed to setup study permissions: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def update_study_resource_scopes(study_id):
    """Update an existing UMA resource to use correct scope format (READ, WRITE instead of STUDY.{study_id}.READ)"""
    try:
        logger.info(f"=== UPDATING UMA RESOURCE SCOPES FOR STUDY: {study_id} ===")
        
        service_token = get_service_token()
        if not service_token:
            logger.error("Failed to get service token")
            return False
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        # First, find the existing resource
        response = requests.get(f"{KEYCLOAK_UMA_RESOURCE_URI}?name={study_id}", headers=headers, timeout=10)
        
        if response.status_code != 200:
            logger.error(f"Failed to find UMA resource: {response.status_code} - {response.text}")
            return False
            
        resources = response.json()
        if not resources:
            logger.error(f"No UMA resource found with name '{study_id}'")
            return False
            
        resource = resources[0]  # Get the first matching resource
        resource_id = resource.get('_id')
        
        if not resource_id:
            logger.error(f"No resource ID found for resource '{study_id}'")
            return False
        
        # Update the resource with correct scopes
        updated_data = {
            'name': study_id,
            'displayName': f"Study: {study_id}",
            'type': 'urn:folio:resources:study',
            'scopes': ['READ', 'WRITE'],  # Use simple scopes, SONG will construct STUDY.{study_id}.WRITE internally
            'attributes': {
                'study_id': [study_id],
                'created_by': ['folio-service']
            }
        }
        
        # Update the resource
        response = requests.put(f"{KEYCLOAK_UMA_RESOURCE_URI}/{resource_id}", 
                               headers=headers, json=updated_data, timeout=10)
        
        if response.status_code == 200:
            logger.info(f"Successfully updated UMA resource '{study_id}' with correct scopes")
            return True
        else:
            logger.error(f"Failed to update UMA resource: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to update study resource scopes: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def create_study_group_with_permission(study_id, permission):
    """Create a Keycloak group for a study with specific permission (read, write, or admin)"""
    try:
        group_name = f"study-{study_id}-{permission}"
        logger.info(f"=== CREATING {permission.upper()} GROUP FOR STUDY: {study_id} ===")
        
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
                'study_id': [study_id],
                'permission': [permission],
                'created_by': ['folio-service'],
                'group_type': ['study'],
                'description': [f"Study {permission} group for {study_id}"]
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
            logger.warning(f"{permission.capitalize()} group for study '{study_id}' already exists")
            return True
        else:
            logger.error(f"Failed to create {permission} group: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create {permission} group for study {study_id}: {e}")
        return False


def create_study_policy(study_id, permission, group_id):
    """Create a Keycloak policy for a study group"""
    try:
        policy_name = f"study-{study_id}-{permission}-policy"
        logger.info(f"=== CREATING {permission.upper()} POLICY FOR STUDY: {study_id} ===")
        
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
            'description': f'Policy for {permission} access to study {study_id}',
            'type': 'group',
            'logic': 'POSITIVE',
            'decisionStrategy': 'AFFIRMATIVE',
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
            logger.warning(f"{permission.capitalize()} policy for study '{study_id}' already exists")
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
        logger.error(f"Failed to create {permission} policy for study {study_id}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def create_study_permission(study_id, permission, resource_id, policy_id, scopes):
    """Create a Keycloak permission linking policy to resource"""
    try:
        permission_name = f"study-{study_id}-{permission}-permission"
        logger.info(f"=== CREATING {permission.upper()} PERMISSION FOR STUDY: {study_id} ===")
        
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
        
        # Use the song resource ID instead of creating new resources
        # This ensures users get simple READ/WRITE scopes that SONG expects
        song_resource_id = "aa9aaeff-84ed-4c69-ade1-19179bedafd1"
        
        # Create scope-based permission (not resource-based) for the song resource
        permission_data = {
            'name': permission_name,
            'description': f'Permission for {permission} access to study {study_id} via song resource',
            'type': 'scope',
            'logic': 'POSITIVE',
            'decisionStrategy': 'AFFIRMATIVE',
            'resources': [song_resource_id],  # Reference existing song resource
            'policies': [policy_id],
            'scopes': scopes  # Simple READ, WRITE scopes
        }
        
        # Create the permission using Keycloak Admin API
        response = requests.post(f"{KEYCLOAK_ADMIN_BASE_URI}/clients/{client_uuid}/authz/resource-server/permission/scope", 
                               headers=headers, json=permission_data, timeout=10)
        
        if response.status_code == 201:
            permission = response.json()
            logger.info(f"Successfully created {permission} permission '{permission_name}' with ID: {permission.get('id')}")
            return permission
        elif response.status_code == 409:
            logger.warning(f"{permission.capitalize()} permission for study '{study_id}' already exists")
            return None
        else:
            logger.error(f"Failed to create {permission} permission: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to create {permission} permission for study {study_id}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def add_user_to_study_group_with_permission(study_id, username, permission):
    """Add a user to a study group with specific permission (read or write)"""
    try:
        group_name = f"study-{study_id}-{permission}"
        logger.info(f"=== ADDING USER '{username}' TO {permission.upper()} GROUP '{group_name}' ===")
        
        # Import auth functions we need
        from auth import get_project_group_by_name, get_user_by_username
        
        # Get the specific permission group (reuse the project function since it's generic)
        group = get_project_group_by_name(group_name)
        if not group:
            logger.error(f"Study {permission} group '{group_name}' not found")
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


def add_creator_to_study_write_group(study_id, username):
    """Add the study creator to the write group - convenience function for study creation"""
    return add_user_to_study_group_with_permission(study_id, username, 'write')


def remove_user_from_study_group_with_permission(study_id, username, permission):
    """Remove a user from a study group with specific permission (read or write)"""
    try:
        group_name = f"study-{study_id}-{permission}"
        logger.info(f"=== REMOVING USER '{username}' FROM {permission.upper()} GROUP '{group_name}' ===")
        
        # Import auth functions we need
        from auth import get_project_group_by_name, get_user_by_username, get_service_token
        
        # Get the specific permission group (reuse the project function since it's generic)
        group = get_project_group_by_name(group_name)
        if not group:
            logger.error(f"Study {permission} group '{group_name}' not found")
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


def get_study_group_members(study_id, permission):
    """Get all members of a study group with specific permission"""
    try:
        group_name = f"study-{study_id}-{permission}"
        logger.info(f"Getting members for study group: {group_name}")
        
        from auth import get_service_token
        
        service_token = get_service_token()
        if not service_token:
            logger.error("Failed to get service token")
            return []
        
        headers = {
            'Authorization': f'Bearer {service_token}',
            'Content-Type': 'application/json'
        }
        
        # Get the group
        groups_response = requests.get(f"{KEYCLOAK_ADMIN_BASE_URI}/groups?search={group_name}", 
                                     headers=headers, timeout=10)
        if groups_response.status_code != 200:
            logger.error(f"Failed to search for group: {groups_response.status_code}")
            return []
        
        groups = groups_response.json()
        group = None
        for g in groups:
            if g['name'] == group_name:
                group = g
                break
        
        if not group:
            logger.warning(f"Study group '{group_name}' not found")
            return []
        
        group_id = group['id']
        
        # Get group members
        members_response = requests.get(f"{KEYCLOAK_ADMIN_BASE_URI}/groups/{group_id}/members", 
                                      headers=headers, timeout=10)
        
        if members_response.status_code != 200:
            logger.error(f"Failed to get group members: {members_response.status_code}")
            return []
        
        members = members_response.json()
        
        # Extract relevant user info
        member_list = []
        for member in members:
            member_info = {
                'id': member.get('id'),
                'username': member.get('username'),
                'email': member.get('email'),
                'firstName': member.get('firstName'),
                'lastName': member.get('lastName'),
                'enabled': member.get('enabled', False),
                'created_at': member.get('createdTimestamp')
            }
            member_list.append(member_info)
        
        logger.info(f"Found {len(member_list)} members in study group '{group_name}'")
        return member_list
        
    except Exception as e:
        logger.error(f"Failed to get study group members for {study_id}-{permission}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return []


def setup_study_endpoints(api, studies_ns):
    """Setup study API endpoints"""
    
    # Define study models for Swagger
    study_model = api.model('Study', {
        'id': fields.String(description='Study UUID (auto-generated)', readonly=True),
        'study_id': fields.String(required=True, description='Study ID (unique identifier for SONG)'),
        'name': fields.String(required=True, description='Study name'),
        'description': fields.String(description='Study description'),
        'project_id': fields.String(description='Associated project UUID'),
        'project_code': fields.String(description='Associated project code (read-only)', readonly=True),
        'project_name': fields.String(description='Associated project name (read-only)', readonly=True),
        'organisation_id': fields.String(description='Associated organisation ID (read-only)', readonly=True),
        'pathogen_id': fields.String(description='Associated pathogen UUID (read-only)', readonly=True),
        'pathogen_name': fields.String(description='Associated pathogen name (read-only)', readonly=True),
        'created_at': fields.DateTime(description='Creation timestamp (auto-generated)', readonly=True),
        'updated_at': fields.DateTime(description='Last update timestamp (auto-generated)', readonly=True)
    })

    study_input_model = api.model('StudyInput', {
        'study_id': fields.String(required=True, description='Study ID (unique identifier for SONG)'),
        'name': fields.String(required=True, description='Study name'),
        'description': fields.String(description='Study description'),
        'project_id': fields.String(required=True, description='Associated project UUID')
    })

    @studies_ns.route('')
    class StudyList(Resource):
        @studies_ns.doc('list_studies', security='Bearer')
        @studies_ns.marshal_list_with(study_model)
        @studies_ns.response(401, 'Invalid or missing token')
        @authenticate_token
        def get(self):
            """Get all studies (public access with valid token)"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Get all active studies with project and pathogen information
                cur.execute("""
                    SELECT s.id, s.study_id, s.name, s.description, s.project_id, s.created_at, s.updated_at,
                           p.slug as project_code, p.name as project_name, p.pathogen_id, p.organisation_id,
                           path.name as pathogen_name
                    FROM studies s
                    LEFT JOIN projects p ON s.project_id = p.id AND p.deleted_at IS NULL
                    LEFT JOIN pathogens path ON p.pathogen_id = path.id AND path.deleted_at IS NULL
                    WHERE s.deleted_at IS NULL
                    ORDER BY s.created_at DESC
                """)
                
                studies = cur.fetchall()
                
                # Convert to JSON-serializable format
                study_list = [serialize_record(study) for study in studies]
                
                cur.close()
                conn.close()
                
                logger.info(f"Retrieved {len(study_list)} studies for user: {g.user['username']}")
                return study_list
                
            except Exception as e:
                logger.error(f"Error retrieving studies: {e}")
                return {"error": "Failed to retrieve studies"}, 500

        @studies_ns.doc('create_study', security='Bearer')
        @studies_ns.expect(study_input_model)
        @studies_ns.marshal_with(study_model, code=201)
        @studies_ns.response(400, 'Invalid input data')
        @studies_ns.response(401, 'Invalid or missing token')
        @studies_ns.response(403, 'Insufficient permissions')
        @authenticate_token
        def post(self):
            """Create a new study (requires project-specific folio.WRITE permission)"""
            try:
                data = studies_ns.payload
                
                # Validate required fields
                if not data or not data.get('name') or not data.get('project_id') or not data.get('study_id'):
                    return {"error": "Study name, study_id and project_id are required"}, 400
                
                # Generate UUID for study
                study_id = str(uuid.uuid4())
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Validate project_id and get project info
                cur.execute("""
                    SELECT p.slug, p.name, p.pathogen_id, p.organisation_id, path.name as pathogen_name
                    FROM projects p
                    LEFT JOIN pathogens path ON p.pathogen_id = path.id AND path.deleted_at IS NULL
                    WHERE p.id = %s AND p.deleted_at IS NULL
                """, (data['project_id'],))
                project = cur.fetchone()
                
                if not project:
                    cur.close()
                    conn.close()
                    return {"error": "Project not found"}, 404
                
                # Check project-specific permissions
                user_permissions = set(g.user.get('permissions', []))
                required_permissions = [
                    f"{project['slug']}.folio.WRITE",
                    f"{project['slug']}.folio.ADMIN",
                    "folio.WRITE"  # fallback to general permission
                ]
                
                has_permission = any(perm in user_permissions for perm in required_permissions)
                
                if not has_permission:
                    cur.close()
                    conn.close()
                    logger.warning(f"User {g.user.get('username')} lacks permissions for project {project['slug']}. Required: {required_permissions}, Has: {list(user_permissions)}")
                    return {
                        'error': f'Insufficient permissions for project {project["slug"]}. Required: WRITE or ADMIN access.',
                        'required_permissions': required_permissions,
                        'user_permissions': list(user_permissions)
                    }, 403
                
                # Insert new study
                cur.execute("""
                    INSERT INTO studies (id, study_id, name, description, project_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                    RETURNING id, study_id, name, description, project_id, created_at, updated_at
                """, (
                    study_id,
                    data['study_id'],
                    data['name'],
                    data.get('description'),
                    data['project_id']
                ))
                
                new_study = cur.fetchone()
                conn.commit()
                cur.close()
                conn.close()
                
                # Add project and pathogen info to response
                result = serialize_record(new_study)
                result['project_code'] = project['slug']
                result['project_name'] = project['name']
                result['pathogen_id'] = project['pathogen_id']
                result['pathogen_name'] = project['pathogen_name']
                result['organisation_id'] = project['organisation_id']
                
                # Create study in SONG and Keycloak resources (optional - log if fails)
                try:
                    # Create study in SONG using service token
                    song_result = create_study_in_song(data['study_id'], data['name'], 
                                                     data.get('description'))
                    if song_result:
                        logger.info(f"Successfully created study '{data['study_id']}' in SONG")
                    elif song_result is None:
                        logger.info(f"Study '{data['study_id']}' already exists in SONG")
                    else:
                        logger.warning(f"Failed to create study '{data['study_id']}' in SONG")
                    
                    # Create Keycloak resource for study
                    resource = create_study_resource(data['study_id'])
                    logger.info(f"Ensured Keycloak resource exists for study: {data['study_id']}")
                    
                    # Create permission groups and policies/permissions
                    for permission in ['read', 'write']:
                        # Create the group
                        create_study_group_with_permission(data['study_id'], permission)
                        
                        # Get the group to extract its ID for policy creation
                        from auth import get_project_group_by_name  # Reuse since it's generic
                        group = get_project_group_by_name(f"study-{data['study_id']}-{permission}")
                        if group and resource:
                            group_id = group['id']
                            resource_id = resource.get('_id')
                            
                            # Create policy for this group
                            policy = create_study_policy(data['study_id'], permission, group_id)
                            
                            # Create permission linking policy to resource
                            if policy:
                                policy_id = policy.get('id')
                                scopes = []
                                if permission == 'read':
                                    scopes = ['READ']
                                elif permission == 'write':
                                    scopes = ['READ', 'WRITE']
                                
                                create_study_permission(data['study_id'], permission, resource_id, policy_id, scopes)
                    
                    # Add the creating user to both read and write groups for this study
                    if add_user_to_study_group_with_permission(data['study_id'], g.user['username'], 'read'):
                        logger.info(f"Added user '{g.user['username']}' to read group for study: {data['study_id']}")
                    else:
                        logger.warning(f"Failed to add user '{g.user['username']}' to read group for study: {data['study_id']}")
                        
                    if add_user_to_study_group_with_permission(data['study_id'], g.user['username'], 'write'):
                        logger.info(f"Added user '{g.user['username']}' to write group for study: {data['study_id']}")
                    else:
                        logger.warning(f"Failed to add user '{g.user['username']}' to write group for study: {data['study_id']}")
                    
                except Exception as e:
                    logger.warning(f"Failed to create SONG/Keycloak resources for study {data['study_id']}: {e}")
                
                logger.info(f"Created study '{data['name']}' by user: {g.user['username']}")
                return result, 201
                
            except Exception as e:
                logger.error(f"Error creating study: {e}")
                return {"error": "Failed to create study"}, 500

    @studies_ns.route('/<string:study_id>')
    @studies_ns.param('study_id', 'The study UUID')
    class StudyDetail(Resource):
        @studies_ns.doc('get_study', security='Bearer')
        @studies_ns.marshal_with(study_model)
        @studies_ns.response(401, 'Invalid or missing token')
        @studies_ns.response(403, 'Access denied to private study')
        @studies_ns.response(404, 'Study not found')
        @authenticate_token
        @require_study_access()
        def get(self, study_id):
            """Get study details by ID (requires study access)"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                cur.execute("""
                    SELECT s.id, s.name, s.description, s.project_id, s.created_at, s.updated_at,
                           p.slug as project_code, p.name as project_name, p.pathogen_id,
                           path.name as pathogen_name
                    FROM studies s
                    LEFT JOIN projects p ON s.project_id = p.id AND p.deleted_at IS NULL
                    LEFT JOIN pathogens path ON p.pathogen_id = path.id AND path.deleted_at IS NULL
                    WHERE s.id = %s AND s.deleted_at IS NULL
                """, (study_id,))
                
                study = cur.fetchone()
                cur.close()
                conn.close()
                
                if not study:
                    return {"error": "Study not found"}, 404
                
                return serialize_record(study)
                
            except Exception as e:
                logger.error(f"Error retrieving study {study_id}: {e}")
                return {"error": "Failed to retrieve study"}, 500

        @studies_ns.doc('update_study', security='Bearer')
        @studies_ns.expect(study_input_model)
        @studies_ns.marshal_with(study_model)
        @studies_ns.response(400, 'Invalid input data')
        @studies_ns.response(401, 'Invalid or missing token')
        @studies_ns.response(403, 'Insufficient permissions')
        @studies_ns.response(404, 'Study not found')
        @authenticate_token
        @require_permissions(["folio.WRITE"])
        def put(self, study_id):
            """Update a study (requires folio.WRITE permission)"""
            try:
                data = studies_ns.payload
                
                if not data:
                    return {"error": "No data provided"}, 400
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if study exists
                cur.execute("SELECT name FROM studies WHERE id = %s AND deleted_at IS NULL", (study_id,))
                existing = cur.fetchone()
                
                if not existing:
                    cur.close()
                    conn.close()
                    return {"error": "Study not found"}, 404
                
                # Validate project_id if provided
                project_info = None
                if 'project_id' in data and data['project_id']:
                    cur.execute("""
                        SELECT p.slug, p.name, p.pathogen_id, path.name as pathogen_name
                        FROM projects p
                        LEFT JOIN pathogens path ON p.pathogen_id = path.id AND path.deleted_at IS NULL
                        WHERE p.id = %s AND p.deleted_at IS NULL
                    """, (data['project_id'],))
                    project_info = cur.fetchone()
                    
                    if not project_info:
                        cur.close()
                        conn.close()
                        return {"error": "Invalid project_id provided"}, 400
                
                # Build update query dynamically
                update_fields = []
                values = []
                
                for field in ['name', 'description', 'project_id']:
                    if field in data:
                        update_fields.append(f"{field} = %s")
                        values.append(data[field])
                
                if not update_fields:
                    cur.close()
                    conn.close()
                    return {"error": "No valid fields to update"}, 400
                
                update_fields.append("updated_at = NOW()")
                values.append(study_id)
                
                cur.execute(f"""
                    UPDATE studies 
                    SET {', '.join(update_fields)}
                    WHERE id = %s AND deleted_at IS NULL
                    RETURNING id, name, description, project_id, created_at, updated_at
                """, values)
                
                updated_study = cur.fetchone()
                
                # Get current project info if not provided in update
                if not project_info and updated_study['project_id']:
                    cur.execute("""
                        SELECT p.slug, p.name, p.pathogen_id, path.name as pathogen_name
                        FROM projects p
                        LEFT JOIN pathogens path ON p.pathogen_id = path.id AND path.deleted_at IS NULL
                        WHERE p.id = %s AND p.deleted_at IS NULL
                    """, (updated_study['project_id'],))
                    project_info = cur.fetchone()
                
                conn.commit()
                cur.close()
                conn.close()
                
                # Add project and pathogen info to response
                result = serialize_record(updated_study)
                if project_info:
                    result['project_code'] = project_info['slug']
                    result['project_name'] = project_info['name']
                    result['pathogen_id'] = project_info['pathogen_id']
                    result['pathogen_name'] = project_info['pathogen_name']
                
                logger.info(f"Updated study {study_id} by user: {g.user['username']}")
                return result
                
            except Exception as e:
                logger.error(f"Error updating study {study_id}: {e}")
                return {"error": "Failed to update study"}, 500

        @studies_ns.doc('delete_study', security='Bearer')
        @studies_ns.response(204, 'Study deleted successfully')
        @studies_ns.response(401, 'Invalid or missing token')
        @studies_ns.response(403, 'Insufficient permissions')
        @studies_ns.response(404, 'Study not found')
        @authenticate_token
        @require_permissions(["folio.WRITE"])
        def delete(self, study_id):
            """Soft delete a study (requires folio.WRITE permission)"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if study exists
                cur.execute("SELECT name FROM studies WHERE id = %s AND deleted_at IS NULL", (study_id,))
                study = cur.fetchone()
                
                if not study:
                    cur.close()
                    conn.close()
                    return {"error": "Study not found"}, 404
                
                # Soft delete the study
                cur.execute("""
                    UPDATE studies 
                    SET deleted_at = NOW(), updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NULL
                """, (study_id,))
                
                conn.commit()
                cur.close()
                conn.close()
                
                logger.info(f"Soft deleted study {study_id} by user: {g.user['username']}")
                return '', 204
                
            except Exception as e:
                logger.error(f"Error deleting study {study_id}: {e}")
                return {"error": "Failed to delete study"}, 500

    # Define member management models for studies
    study_member_input_model = api.model('StudyMemberInput', {
        'username': fields.String(required=True, description='Username to add/remove'),
        'permission': fields.String(required=True, description='Permission level: read or write', 
                                   enum=['read', 'write'])
    })

    @studies_ns.route('/<string:study_id>/members')
    @studies_ns.param('study_id', 'The study UUID')
    class StudyMembers(Resource):
        @studies_ns.doc('get_study_members', security='Bearer')
        @studies_ns.response(401, 'Invalid or missing token')
        @studies_ns.response(403, 'Access denied to private study')
        @studies_ns.response(404, 'Study not found')
        @authenticate_token
        @require_study_access()
        def get(self, study_id):
            """Get all members in study groups (requires study access)"""
            try:
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if study exists and get study_id (the SONG identifier)
                cur.execute("SELECT study_id, name FROM studies WHERE id = %s AND deleted_at IS NULL", (study_id,))
                study = cur.fetchone()
                
                if not study:
                    cur.close()
                    conn.close()
                    return {"error": "Study not found"}, 404
                
                cur.close()
                conn.close()
                
                # Get group members for this study using the SONG study_id
                study_identifier = study['study_id']
                group_members = {
                    'read': get_study_group_members(study_identifier, 'read'),
                    'write': get_study_group_members(study_identifier, 'write')
                }
                
                # Calculate totals
                all_members = set()
                for members in group_members.values():
                    all_members.update(member['username'] for member in members)
                
                return {
                    "study_id": study_id,
                    "study_identifier": study_identifier,
                    "study_name": study['name'],
                    "groups": group_members,
                    "stats": {
                        "total_unique_members": len(all_members),
                        "read_members": len(group_members['read']),
                        "write_members": len(group_members['write'])
                    }
                }
                
            except Exception as e:
                logger.error(f"Error retrieving study members {study_id}: {e}")
                return {"error": "Failed to retrieve study members"}, 500

        @studies_ns.doc('add_study_member', security='Bearer')
        @studies_ns.expect(study_member_input_model)
        @studies_ns.response(200, 'Member added successfully')
        @studies_ns.response(400, 'Invalid input data')
        @studies_ns.response(401, 'Invalid or missing token')
        @studies_ns.response(403, 'Insufficient permissions')
        @studies_ns.response(404, 'Study or user not found')
        @authenticate_token
        def post(self, study_id):
            """Add a user to a study group (requires project-specific folio.WRITE or folio.ADMIN permission)"""
            try:
                data = studies_ns.payload
                
                if not data or not data.get('username') or not data.get('permission'):
                    return {"error": "Username and permission are required"}, 400
                
                if data['permission'] not in ['read', 'write']:
                    return {"error": "Permission must be one of: read, write"}, 400
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if study exists and get study info + project info
                cur.execute("""
                    SELECT s.study_id, s.name, p.slug as project_slug, p.name as project_name
                    FROM studies s
                    JOIN projects p ON s.project_id = p.id AND p.deleted_at IS NULL
                    WHERE s.id = %s AND s.deleted_at IS NULL
                """, (study_id,))
                study = cur.fetchone()
                
                if not study:
                    cur.close()
                    conn.close()
                    return {"error": "Study not found"}, 404
                
                # Check project-specific permissions
                user_permissions = set(g.user.get('permissions', []))
                required_permissions = [
                    f"{study['project_slug']}.folio.WRITE",
                    f"{study['project_slug']}.folio.ADMIN",
                    "folio.WRITE"  # fallback to general permission
                ]
                
                has_permission = any(perm in user_permissions for perm in required_permissions)
                
                if not has_permission:
                    cur.close()
                    conn.close()
                    logger.warning(f"User {g.user.get('username')} lacks permissions for project {study['project_slug']}. Required: {required_permissions}, Has: {list(user_permissions)}")
                    return {
                        'error': f'Insufficient permissions for project {study["project_slug"]}. Required: WRITE or ADMIN access.',
                        'required_permissions': required_permissions,
                        'user_permissions': list(user_permissions)
                    }, 403
                
                cur.close()
                conn.close()
                
                # Add user to study group using the SONG study_id
                study_identifier = study['study_id']
                success = add_user_to_study_group_with_permission(
                    study_identifier, 
                    data['username'], 
                    data['permission']
                )
                
                if success:
                    logger.info(f"Added user '{data['username']}' to {data['permission']} group for study {study_identifier}")
                    return {
                        "message": f"Successfully added user '{data['username']}' to {data['permission']} group",
                        "study_id": study_id,
                        "study_identifier": study_identifier,
                        "username": data['username'],
                        "permission": data['permission']
                    }
                else:
                    return {"error": f"Failed to add user to {data['permission']} group"}, 400
                
            except Exception as e:
                logger.error(f"Error adding study member {study_id}: {e}")
                return {"error": "Failed to add study member"}, 500

        @studies_ns.doc('remove_study_member', security='Bearer')
        @studies_ns.expect(study_member_input_model)
        @studies_ns.response(200, 'Member removed successfully')
        @studies_ns.response(400, 'Invalid input data')
        @studies_ns.response(401, 'Invalid or missing token')
        @studies_ns.response(403, 'Insufficient permissions')
        @studies_ns.response(404, 'Study or user not found')
        @authenticate_token
        def delete(self, study_id):
            """Remove a user from a study group (requires project-specific folio.WRITE or folio.ADMIN permission)"""
            try:
                data = studies_ns.payload
                
                if not data or not data.get('username') or not data.get('permission'):
                    return {"error": "Username and permission are required"}, 400
                
                if data['permission'] not in ['read', 'write']:
                    return {"error": "Permission must be one of: read, write"}, 400
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Check if study exists and get study info + project info
                cur.execute("""
                    SELECT s.study_id, s.name, p.slug as project_slug, p.name as project_name
                    FROM studies s
                    JOIN projects p ON s.project_id = p.id AND p.deleted_at IS NULL
                    WHERE s.id = %s AND s.deleted_at IS NULL
                """, (study_id,))
                study = cur.fetchone()
                
                if not study:
                    cur.close()
                    conn.close()
                    return {"error": "Study not found"}, 404
                
                # Check project-specific permissions
                user_permissions = set(g.user.get('permissions', []))
                required_permissions = [
                    f"{study['project_slug']}.folio.WRITE",
                    f"{study['project_slug']}.folio.ADMIN",
                    "folio.WRITE"  # fallback to general permission
                ]
                
                has_permission = any(perm in user_permissions for perm in required_permissions)
                
                if not has_permission:
                    cur.close()
                    conn.close()
                    logger.warning(f"User {g.user.get('username')} lacks permissions for project {study['project_slug']}. Required: {required_permissions}, Has: {list(user_permissions)}")
                    return {
                        'error': f'Insufficient permissions for project {study["project_slug"]}. Required: WRITE or ADMIN access.',
                        'required_permissions': required_permissions,
                        'user_permissions': list(user_permissions)
                    }, 403
                
                # Check if study exists and get study_id (the SONG identifier)
                cur.execute("SELECT study_id, name FROM studies WHERE id = %s AND deleted_at IS NULL", (study_id,))
                study = cur.fetchone()
                
                if not study:
                    cur.close()
                    conn.close()
                    return {"error": "Study not found"}, 404
                
                cur.close()
                conn.close()
                
                # Remove user from study group using the SONG study_id
                study_identifier = study['study_id']
                success = remove_user_from_study_group_with_permission(
                    study_identifier, 
                    data['username'], 
                    data['permission']
                )
                
                if success:
                    logger.info(f"Removed user '{data['username']}' from {data['permission']} group for study {study_identifier}")
                    return {
                        "message": f"Successfully removed user '{data['username']}' from {data['permission']} group",
                        "study_id": study_id,
                        "study_identifier": study_identifier,
                        "username": data['username'],
                        "permission": data['permission']
                    }
                else:
                    return {"error": f"Failed to remove user from {data['permission']} group"}, 400
                
            except Exception as e:
                logger.error(f"Error removing study member {study_id}: {e}")
                return {"error": "Failed to remove study member"}, 500
