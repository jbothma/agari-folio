from flask import Flask, jsonify, request
from flask_restx import Api, Resource, fields
from auth import KeycloakAuth, require_auth, extract_user_info, check_user_permission, require_permission, require_permission_or_attribute, require_organization_access
from permissions import PERMISSIONS
from database import get_db_cursor, test_connection, get_database_info
import os
import json
from datetime import datetime, date
from decimal import Decimal

# Custom JSON encoder to handle datetime and other types
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            # Format as YYYY-MM-DD HH:MM:SS (no microseconds or timezone)
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            # Format as YYYY-MM-DD
            return obj.strftime('%Y-%m-%d')
        elif isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)

app = Flask(__name__)
app.json_encoder = CustomJSONEncoder

keycloak_auth = KeycloakAuth(
    keycloak_url=os.getenv('KEYCLOAK_URL', 'http://keycloak.local'),
    realm=os.getenv('KEYCLOAK_REALM', 'agari'),
    client_id=os.getenv('KEYCLOAK_CLIENT_ID', 'dms'),
    client_secret=os.getenv('KEYCLOAK_CLIENT_SECRET', 'VDyLEjGR3xDQvoQlrHq5AB6OwbW0Refc')
)

# Make keycloak_auth available to decorators
app.keycloak_auth = keycloak_auth

api = Api(app, 
    version='1.0', 
    title='Folio API',
    description='API documentation for the Folio application',
    doc='/docs/'
)

# Configure Flask-RESTX to use our custom JSON encoder
app.config['RESTX_JSON'] = {'cls': CustomJSONEncoder}

### Default namespace

default_ns = api.namespace('info', description='Utility endpoints')

@default_ns.route('/health')
class Health(Resource):
    @api.doc('get_health')
    def get(self):
        """Check application health status"""
        return {'status': 'healthy'}

@default_ns.route('/health/db')
class DatabaseHealth(Resource):
    @api.doc('get_db_health')
    def get(self):
        """Check database connectivity and schema"""
        db_test = test_connection()
        if db_test:
            db_info = get_database_info()
            return {
                'status': 'healthy',
                'database': db_info
            }
        else:
            return {'status': 'unhealthy', 'error': 'Database connection failed'}, 503

@default_ns.route('/whoami')
class WhoAmI(Resource):
    @api.doc('get_whoami')
    @require_auth(keycloak_auth)
    def get(self):
        """Get current user information from JWT token"""
        return extract_user_info(request.user)

@default_ns.route('/permissions')
class Permissions(Resource):
    @api.doc('get_permissions')
    @require_auth(keycloak_auth)
    def get(self):
        """Get all defined permissions"""
        return PERMISSIONS

@default_ns.route('/permissions/check/<permission_name>')
class PermissionsCheck(Resource):
    @api.doc('check_permission')
    @require_auth(keycloak_auth)
    def get(self, permission_name):
        """Check if the current user has a specific permission"""
        user_info = extract_user_info(request.user)
        has_permission = check_user_permission(user_info, permission_name, PERMISSIONS)
        
        return {
            'has_permission': has_permission,
            'user_roles': user_info.get('roles', []),
            'required_roles': PERMISSIONS.get(permission_name, [])
        }
        
###
### PATHOGENS
###

pathogen_ns = api.namespace('pathogens', description='Pathogen management endpoints')

@pathogen_ns.route('/')
class PathogenList(Resource):
    @api.doc('list_pathogens')
    def get(self):
        """List all pathogens (public access)
        
        Query Parameters:
        - deleted: true/false (default: false) - If true, include soft-deleted pathogens
        """
        try:
            # Check if deleted pathogens should be included
            include_deleted = request.args.get('deleted', 'false').lower() == 'true'
            
            with get_db_cursor() as cursor:
                if include_deleted:
                    # Include all pathogens (both active and deleted)
                    cursor.execute("""
                        SELECT id, name, scientific_name, description, created_at, updated_at, deleted_at,
                               CASE WHEN deleted_at IS NULL THEN 'active' ELSE 'deleted' END as status
                        FROM pathogens 
                        ORDER BY deleted_at IS NULL DESC, name
                    """)
                else:
                    # Only active pathogens (default behavior)
                    cursor.execute("""
                        SELECT id, name, scientific_name, description, created_at, updated_at
                        FROM pathogens 
                        WHERE deleted_at IS NULL 
                        ORDER BY name
                    """)
                
                pathogens = cursor.fetchall()

                return pathogens

        except Exception as e:
            return {'error': f'Database error: {str(e)}'}, 500

    @api.doc('create_pathogen')
    @require_auth(keycloak_auth)
    @require_permission('create_pathogen', PERMISSIONS)
    def post(self):
        """Create a new pathogen (system-admin only)"""
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            name = data.get('name')
            scientific_name = data.get('scientific_name')
            description = data.get('description')
            
            if not name:
                return {'error': 'Pathogen name is required'}, 400
            if not scientific_name:
                return {'error': 'Scientific name is required'}, 400

            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO pathogens (name, scientific_name, description)
                    VALUES (%s, %s, %s)
                    RETURNING id, name, scientific_name, description, created_at
                """, (name, scientific_name, description))
                
                new_pathogen = cursor.fetchone()
                
                return {
                    'message': 'Pathogen created successfully',
                    'pathogen': new_pathogen
                }, 201
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Pathogen with name "{name}" already exists'}, 409
            return {'error': f'Database error: {str(e)}'}, 500

@pathogen_ns.route('/<string:pathogen_id>')
class Pathogen(Resource):
    @api.doc('get_pathogen')
    def get(self, pathogen_id):
        """Get details of a specific pathogen by ID (public access)"""
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT id, name, scientific_name, description, created_at, updated_at
                    FROM pathogens 
                    WHERE id = %s AND deleted_at IS NULL
                """, (pathogen_id,))
                
                pathogen = cursor.fetchone()
                
                if not pathogen:
                    return {'error': 'Pathogen not found'}, 404
                
                return pathogen
                
        except Exception as e:
            return {'error': f'Database error: {str(e)}'}, 500

    @api.doc('delete_pathogen')
    @require_auth(keycloak_auth)
    @require_permission('delete_pathogen', PERMISSIONS)
    def delete(self, pathogen_id):
        """Delete a pathogen by ID (system-admin only)
        
        Query Parameters: 
        - hard: true/false (default: false) - If true, permanently delete from database
        """
        try:
            # Check if hard delete is requested
            hard_delete = request.args.get('hard', 'false').lower() == 'true'
            
            with get_db_cursor() as cursor:
                if hard_delete:
                    # Hard delete - permanently remove from database
                    cursor.execute("""
                        DELETE FROM pathogens 
                        WHERE id = %s
                        RETURNING id, name
                    """, (pathogen_id,))
                    
                    deleted_pathogen = cursor.fetchone()
                    
                    if not deleted_pathogen:
                        return {'error': 'Pathogen not found'}, 404
                    
                    return {
                        'message': f'Pathogen "{deleted_pathogen["name"]}" permanently deleted',
                        'delete_type': 'hard'
                    }
                else:
                    # Soft delete - set deleted_at timestamp
                    cursor.execute("""
                        UPDATE pathogens 
                        SET deleted_at = NOW(), updated_at = NOW()
                        WHERE id = %s AND deleted_at IS NULL
                        RETURNING id, name
                    """, (pathogen_id,))
                    
                    deleted_pathogen = cursor.fetchone()
                    
                    if not deleted_pathogen:
                        return {'error': 'Pathogen not found or already deleted'}, 404
                    
                    return {
                        'message': f'Pathogen "{deleted_pathogen["name"]}" deleted (can be restored)',
                        'delete_type': 'soft'
                    }
                
        except Exception as e:
            return {'error': f'Database error: {str(e)}'}, 500

    @api.doc('update_pathogen')
    @require_auth(keycloak_auth)
    @require_permission('edit_pathogen', PERMISSIONS)
    def put(self, pathogen_id):
        """Update a pathogen by ID (system-admin only)"""
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            name = data.get('name')
            scientific_name = data.get('scientific_name')
            description = data.get('description')
            
            if not name:
                return {'error': 'Pathogen name is required'}, 400
            if not scientific_name:
                return {'error': 'Scientific name is required'}, 400

            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE pathogens 
                    SET name = %s, scientific_name = %s, description = %s, updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NULL
                    RETURNING id, name, scientific_name, description, updated_at
                """, (name, scientific_name, description, pathogen_id))
                
                updated_pathogen = cursor.fetchone()
                
                if not updated_pathogen:
                    return {'error': 'Pathogen not found or already deleted'}, 404
                
                return {
                    'message': 'Pathogen updated successfully',
                    'pathogen': updated_pathogen
                }
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Pathogen with name "{name}" already exists'}, 409
            return {'error': f'Database error: {str(e)}'}, 500


@pathogen_ns.route('/<string:pathogen_id>/restore')
class PathogenRestore(Resource):
    @api.doc('restore_pathogen')
    @require_auth(keycloak_auth)
    @require_permission('create_pathogen', PERMISSIONS)
    def post(self, pathogen_id):
        """Restore a soft-deleted pathogen (system-admin only)"""
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE pathogens 
                    SET deleted_at = NULL, updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NOT NULL
                    RETURNING id, name, scientific_name, description, updated_at
                """, (pathogen_id,))
                
                restored_pathogen = cursor.fetchone()
                
                if not restored_pathogen:
                    return {'error': 'Pathogen not found or not deleted'}, 404
                
                return {
                    'message': f'Pathogen "{restored_pathogen["name"]}" restored successfully',
                    'pathogen': restored_pathogen
                }
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': 'Cannot restore: A pathogen with this name already exists'}, 409
            return {'error': f'Database error: {str(e)}'}, 500


###
### PROJECTS
###

project_ns = api.namespace('projects', description='Project management endpoints')

@project_ns.route('/')
class ProjectList(Resource):
    @api.doc('list_projects')
    def get(self):
        """List projects based on user permissions
        
        Query Parameters:
        - deleted: true/false (default: false) - If true, include soft-deleted projects
        """
        try:
            # Check if deleted projects should be included
            include_deleted = request.args.get('deleted', 'false').lower() == 'true'
            
            # Get user's organization and permissions if authenticated
            user_org_id = None
            is_system_admin = False
            can_view_org_private_projects = False
            
            auth_header = request.headers.get('Authorization')
            if auth_header:
                try:
                    from auth import KeycloakAuth
                    token = auth_header.split(' ')[1]
                    user_info_raw = keycloak_auth.verify_token(token)
                    if user_info_raw and 'error' not in user_info_raw:
                        user_info = extract_user_info(user_info_raw)
                        user_org_id = user_info.get('organisation_id')
                        user_roles = user_info.get('roles', [])
                        
                        # Check if user is system admin
                        is_system_admin = 'system-admin' in user_roles
                        can_view_org_private_projects = check_user_permission(user_info, 'view_org_private_projects', PERMISSIONS)
                        
                        # Debug output
                        print(f"Debug - User org: {user_org_id}")
                        print(f"Debug - Is system admin: {is_system_admin}")
                        print(f"Debug - Can view org private projects: {can_view_org_private_projects}")
                        print(f"Debug - User roles: {user_roles}")
                except:
                    pass  # If token is invalid, just show public projects

            with get_db_cursor() as cursor:
                if include_deleted:
                    # Include all projects (both active and deleted) with privacy filtering
                    if is_system_admin:
                        # System admin can see all projects from all organizations
                        cursor.execute("""
                            SELECT id, name, description, organisation_id, user_id, privacy, created_at, updated_at, deleted_at,
                                   CASE WHEN deleted_at IS NULL THEN 'active' ELSE 'deleted' END as status
                            FROM projects
                            ORDER BY deleted_at IS NULL DESC, name
                        """)
                    elif can_view_org_private_projects and user_org_id:
                        # User can see public projects + all private projects from their org
                        cursor.execute("""
                            SELECT id, name, description, organisation_id, user_id, privacy, created_at, updated_at, deleted_at,
                                   CASE WHEN deleted_at IS NULL THEN 'active' ELSE 'deleted' END as status
                            FROM projects
                            WHERE privacy = 'public' OR organisation_id = %s
                            ORDER BY deleted_at IS NULL DESC, name
                        """, (user_org_id,))
                    elif user_org_id:
                        # Regular authenticated user - see public + own org's private
                        cursor.execute("""
                            SELECT id, name, description, organisation_id, user_id, privacy, created_at, updated_at, deleted_at,
                                   CASE WHEN deleted_at IS NULL THEN 'active' ELSE 'deleted' END as status
                            FROM projects
                            WHERE privacy = 'public' OR organisation_id = %s
                            ORDER BY deleted_at IS NULL DESC, name
                        """, (user_org_id,))
                    else:
                        # Unauthenticated user - only public projects
                        cursor.execute("""
                            SELECT id, name, description, organisation_id, user_id, privacy, created_at, updated_at, deleted_at,
                                   CASE WHEN deleted_at IS NULL THEN 'active' ELSE 'deleted' END as status
                            FROM projects
                            WHERE privacy = 'public'
                            ORDER BY deleted_at IS NULL DESC, name
                        """)
                else:
                    # Only active projects with privacy filtering
                    if is_system_admin:
                        # System admin can see all active projects from all organizations
                        print("Debug - Using system admin query")
                        cursor.execute("""
                            SELECT id, name, description, organisation_id, user_id, privacy, created_at, updated_at
                            FROM projects
                            WHERE deleted_at IS NULL
                            ORDER BY name
                        """)
                    elif can_view_org_private_projects and user_org_id:
                        # User can see public projects + all private projects from their org
                        print(f"Debug - Using view_org_private_projects query for org: {user_org_id}")
                        cursor.execute("""
                            SELECT id, name, description, organisation_id, user_id, privacy, created_at, updated_at
                            FROM projects
                            WHERE deleted_at IS NULL AND (privacy = 'public' OR organisation_id = %s)
                            ORDER BY name
                        """, (user_org_id,))
                    elif user_org_id:
                        # Regular authenticated user - see public + own org's private
                        print(f"Debug - Using regular authenticated user query for org: {user_org_id}")
                        cursor.execute("""
                            SELECT id, name, description, organisation_id, user_id, privacy, created_at, updated_at
                            FROM projects
                            WHERE deleted_at IS NULL AND (privacy = 'public' OR organisation_id = %s)
                            ORDER BY name
                        """, (user_org_id,))
                    else:
                        # Unauthenticated user - only public projects
                        print("Debug - Using unauthenticated user query")
                        cursor.execute("""
                            SELECT id, name, description, organisation_id, user_id, privacy, created_at, updated_at
                            FROM projects
                            WHERE deleted_at IS NULL AND privacy = 'public'
                            ORDER BY name
                        """)

                projects = cursor.fetchall()
                print(f"Debug - Found {len(projects)} projects")
                for project in projects:
                    print(f"Debug - Project: {project.get('name')} (org: {project.get('organisation_id')}, privacy: {project.get('privacy')})")
                return projects

        except Exception as e:
            return {'error': f'Database error: {str(e)}'}, 500

    @api.doc('create_project')
    @require_auth(keycloak_auth)
    @require_permission('create_project', PERMISSIONS)
    def post(self):
        """Create a new project"""
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            name = data.get('name')
            description = data.get('description')
            pathogen_id = data.get('pathogen_id')
            privacy = data.get('privacy', 'public')  
            
            if not name:
                return {'error': 'Project name is required'}, 400
            if not pathogen_id:
                return {'error': 'Associated pathogen_id is required'}, 400

            # Extract user info to get the user_id
            user_info = extract_user_info(request.user)
            user_id = user_info.get('user_id')
            organisation_id = user_info.get('organisation_id')

            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO projects (name, description, pathogen_id, user_id, organisation_id, privacy)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id, name, description, organisation_id,user_id, pathogen_id, privacy, created_at
                """, (name, description, pathogen_id, user_id, organisation_id, privacy))

                new_project = cursor.fetchone()
                
                return {
                    'message': 'Project created successfully',
                    'project': new_project
                }, 201
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Project with name "{name}" already exists'}, 409
            return {'error': f'Database error: {str(e)}'}, 500

@project_ns.route('/<string:project_id>')
class Project(Resource):
    @api.doc('get_project')
    def get(self, project_id):
        """Get details of a specific project by ID with privacy controls"""
        try:
            # Get user's organization and permissions if authenticated
            user_org_id = None
            is_system_admin = False
            can_view_org_private_projects = False
            
            auth_header = request.headers.get('Authorization')
            if auth_header:
                try:
                    from auth import KeycloakAuth
                    token = auth_header.split(' ')[1]
                    user_info_raw = keycloak_auth.verify_token(token)
                    if user_info_raw and 'error' not in user_info_raw:
                        user_info = extract_user_info(user_info_raw)
                        user_org_id = user_info.get('organisation_id')
                        user_roles = user_info.get('roles', [])
                        
                        # Check if user is system admin
                        is_system_admin = 'system-admin' in user_roles
                        can_view_org_private_projects = check_user_permission(user_info, 'view_org_private_projects', PERMISSIONS)
                except:
                    pass  # If token is invalid, just show public projects

            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT id, name, description, pathogen_id, user_id, organisation_id, privacy, created_at, updated_at
                    FROM projects 
                    WHERE id = %s AND deleted_at IS NULL
                """, (project_id,))
                
                project = cursor.fetchone()
                
                if not project:
                    return {'error': 'Project not found'}, 404
                
                # Apply privacy filtering
                if project['privacy'] == 'private':
                    # Private project - check permissions
                    if is_system_admin:
                        # System admin can see all projects from all organizations
                        pass  # Allow access
                    elif can_view_org_private_projects and user_org_id == project['organisation_id']:
                        # User can see private projects from their org
                        pass  # Allow access
                    elif user_org_id == project['organisation_id']:
                        # Regular authenticated user from same org
                        pass  # Allow access
                    else:
                        # User not authorized to view this private project
                        return {'error': 'Project not found'}, 404
                
                return project
                
        except Exception as e:
            return {'error': f'Database error: {str(e)}'}, 500

    @api.doc('delete_project')
    @require_auth(keycloak_auth)
    @require_organization_access('delete_org_projects', PERMISSIONS, 'project_id')
    def delete(self, project_id):
        """Delete a project by ID with organization-based permissions
        
        Query Parameters: 
        - hard: true/false (default: false) - If true, permanently delete from database
        """
        try:
            # Get user info for hard delete check
            user_info = extract_user_info(request.user)
            user_roles = user_info.get('roles', [])
            is_system_admin = 'system-admin' in user_roles
            
            # Get the project
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT id, name, organisation_id
                    FROM projects 
                    WHERE id = %s AND deleted_at IS NULL
                """, (project_id,))
                
                project = cursor.fetchone()
                
                if not project:
                    return {'error': 'Project not found or already deleted'}, 404
                
                # Proceed with deletion
                hard_delete = request.args.get('hard', 'false').lower() == 'true'
                
                if hard_delete:
                    # Hard delete is only allowed for system admin
                    if not is_system_admin:
                        return {'error': 'Hard delete requires system admin privileges'}, 403
                    
                    # Hard delete - permanently remove from database
                    cursor.execute("""
                        DELETE FROM projects 
                        WHERE id = %s
                        RETURNING id, name
                    """, (project_id,))
                    
                    deleted_project = cursor.fetchone()
                    
                    return {
                        'message': f'Project "{deleted_project["name"]}" permanently deleted',
                        'delete_type': 'hard'
                    }
                else:
                    # Soft delete - set deleted_at timestamp
                    cursor.execute("""
                        UPDATE projects 
                        SET deleted_at = NOW(), updated_at = NOW()
                        WHERE id = %s AND deleted_at IS NULL
                        RETURNING id, name
                    """, (project_id,))
                    
                    deleted_project = cursor.fetchone()
                    
                    return {
                        'message': f'Project "{deleted_project["name"]}" deleted (can be restored)',
                        'delete_type': 'soft'
                    }
                
        except Exception as e:
            return {'error': f'Database error: {str(e)}'}, 500
        
    @api.doc('update_project')
    @require_auth(keycloak_auth)
    @require_organization_access('edit_org_projects', PERMISSIONS, 'project_id')
    def put(self, project_id):
        """Update a project by ID with organization-based permissions (only updates provided fields)"""
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            update_fields = []
            update_values = []
            
            if 'name' in data:
                update_fields.append('name = %s')
                update_values.append(data['name'])
                
            if 'description' in data:
                update_fields.append('description = %s')
                update_values.append(data['description'])
                
            if 'pathogen_id' in data:
                update_fields.append('pathogen_id = %s')
                update_values.append(data['pathogen_id'])

            if 'privacy' in data:
                update_fields.append('privacy = %s')
                update_values.append(data['privacy'])

            if not update_fields:
                return {'error': 'No valid fields provided for update'}, 400
            
            # Always update the updated_at timestamp
            update_fields.append('updated_at = NOW()')
            update_values.append(project_id)  # For the WHERE clause

            with get_db_cursor() as cursor:
                # Proceed with update (organization check already done by decorator)
                query = f"""
                    UPDATE projects 
                    SET {', '.join(update_fields)}
                    WHERE id = %s AND deleted_at IS NULL
                    RETURNING id, name, description, pathogen_id, user_id, organisation_id, privacy, updated_at
                """
                
                cursor.execute(query, update_values)
                
                updated_project = cursor.fetchone()
                
                if not updated_project:
                    return {'error': 'Project not found or already deleted'}, 404
                
                return {
                    'message': 'Project updated successfully',
                    'project': updated_project
                }
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Project name already exists'}, 409
            return {'error': f'Database error: {str(e)}'}, 500
        
@project_ns.route('/<string:project_id>/restore')
class ProjectRestore(Resource):
    @api.doc('restore_project')
    @require_auth(keycloak_auth)
    def post(self, project_id):
        """Restore a soft-deleted project (system-admin only)"""
        try:
            # Get user info and check if user is system admin
            user_info = extract_user_info(request.user)
            user_roles = user_info.get('roles', [])
            
            is_system_admin = 'system-admin' in user_roles
            
            if not is_system_admin:
                return {'error': 'Restore requires system admin privileges'}, 403
            
            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE projects 
                    SET deleted_at = NULL, updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NOT NULL
                    RETURNING id, name, description, updated_at
                """, (project_id,))
                
                restored_project = cursor.fetchone()
                
                if not restored_project:
                    return {'error': 'Project not found or not deleted'}, 404
                
                return {
                    'message': f'Project "{restored_project["name"]}" restored successfully',
                    'project': restored_project
                }
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': 'Cannot restore: A project with this name already exists'}, 409
            return {'error': f'Database error: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/users')
class ProjectUsers(Resource):
    @api.doc('list_project_users')
    @require_auth(keycloak_auth)
    @require_organization_access('list_project_users', PERMISSIONS, 'project_id', 'project-admin')
    def get(self, project_id):
        """List users associated with a project"""
        try:
            project_admins = keycloak_auth.get_users_by_attribute('project-admin', project_id)
            project_contributors = keycloak_auth.get_users_by_attribute('project-contributor', project_id)
            project_viewers = keycloak_auth.get_users_by_attribute('project-viewer', project_id)

            return {
                'project_id': project_id,
                'project_admins': project_admins,
                'project_contributors': project_contributors,
                'project_viewers': project_viewers,
                'total_users': len(project_admins) + len(project_contributors) + len(project_viewers)
            }
        except Exception as e:
            return {'error': f'Failed to retrieve project users: {str(e)}'}, 500
        
    
    @api.doc('add_project_user')
    @require_auth(keycloak_auth)
    @require_organization_access('manage_project_users', PERMISSIONS, 'project_id', 'project-admin')
    def post(self, project_id):
        """Add a user to a project with a specific attribute"""
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            user_id = data.get('user_id')
            role = data.get('role')  # 'project-admin', 'project-contributor', 'project-viewer'
            
            if not user_id or not role:
                return {'error': 'Both user_id and role are required'}, 400
            
            if role not in ['project-admin', 'project-contributor', 'project-viewer']:
                return {'error': 'Invalid role specified'}, 400
            
            # Add attribute to user in Keycloak
            if not keycloak_auth.add_attribute_value(user_id, role, project_id):
                return {'error': 'Failed to add attribute to user in Keycloak'}, 500
            
            return {
                'message': f'User {user_id} added to project {project_id} as {role}'
            }, 200
            
        except Exception as e:
            return {'error': f'Failed to add user to project: {str(e)}'}, 500

    @api.doc('remove_project_user')
    @require_auth(keycloak_auth)
    @require_organization_access('manage_project_users', PERMISSIONS, 'project_id', 'project-admin')
    def delete(self, project_id):
        """Remove a user from a project"""
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            user_id = data.get('user_id')
            role = data.get('role')  # 'project-admin', 'project-contributor', 'project-viewer'
            
            if not user_id or not role:
                return {'error': 'Both user_id and role are required'}, 400
            
            if role not in ['project-admin', 'project-contributor', 'project-viewer']:
                return {'error': 'Invalid role specified'}, 400
            
            # Remove attribute from user in Keycloak
            if not keycloak_auth.remove_attribute_value(user_id, role, project_id):
                return {'error': 'Failed to remove attribute from user in Keycloak'}, 500
            
            return {
                'message': f'User {user_id} removed from project {project_id} role {role}'
            }, 200
            
        except Exception as e:
            return {'error': f'Failed to remove user from project: {str(e)}'}, 500


###
### STUDIES
###

study_ns = api.namespace('studies', description='Study management endpoints')

@study_ns.route('/')
class StudyList(Resource):
    @api.doc('SONG and FOLIO - Get All Studies')
    @require_auth(keycloak_auth)
    @require_organization_access('manage_project_users', PERMISSIONS, 'project_id', 'project-admin')

    def get(self):
        """List studies based on user permissions
        
        Query Parameters:
        - deleted: true/false (default: false) - If true, include soft-deleted studies
        """

        return

   

@study_ns.route('/<string:study_id>')
class Study(Resource):
    @api.doc('SONG and FOLIO - Get Study')
    def get(self, study_id):
        """Get details of a specific study by ID"""
        return
    
    @api.doc('SONG and FOLIO - Create Study')
    def post(self):
        """Create a new study"""
        return

    @api.doc('SONG and FOLIO - Delete Study')
    def delete(self, study_id):
        """Delete a study by ID"""
        return
    
    @api.doc('SONG and FOLIO - Update Study')
    def put(self, study_id):
        """Update a study by ID"""
        return

    

        


if __name__ == '__main__':
    app.run(debug=True, port=5000)