"""
Study Management Module for Folio API

This module contains all study-related endpoints.
"""

import logging
import psycopg2
from psycopg2.extras import RealDictCursor
import uuid
from datetime import datetime
from flask_restx import Resource, fields
from flask import jsonify, g
from auth import authenticate_token, require_permissions
from utils import serialize_record, get_db_connection

logger = logging.getLogger(__name__)


def setup_study_endpoints(api, studies_ns):
    """Setup study API endpoints"""
    
    # Define study models for Swagger
    study_model = api.model('Study', {
        'id': fields.String(description='Study UUID (auto-generated)', readonly=True),
        'name': fields.String(required=True, description='Study name'),
        'description': fields.String(description='Study description'),
        'project_id': fields.String(description='Associated project UUID'),
        'project_code': fields.String(description='Associated project code (read-only)', readonly=True),
        'project_name': fields.String(description='Associated project name (read-only)', readonly=True),
        'pathogen_id': fields.String(description='Associated pathogen UUID (read-only)', readonly=True),
        'pathogen_name': fields.String(description='Associated pathogen name (read-only)', readonly=True),
        'created_at': fields.DateTime(description='Creation timestamp (auto-generated)', readonly=True),
        'updated_at': fields.DateTime(description='Last update timestamp (auto-generated)', readonly=True)
    })

    study_input_model = api.model('StudyInput', {
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
                    SELECT s.id, s.name, s.description, s.project_id, s.created_at, s.updated_at,
                           p.slug as project_code, p.name as project_name, p.pathogen_id,
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
        @require_permissions(["folio.WRITE"])
        def post(self):
            """Create a new study (requires folio.WRITE permission)"""
            try:
                data = studies_ns.payload
                
                # Validate required fields
                if not data or not data.get('name') or not data.get('project_id'):
                    return {"error": "Study name and project_id are required"}, 400
                
                # Generate UUID for study
                study_id = str(uuid.uuid4())
                
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=RealDictCursor)
                
                # Validate project_id and get project info
                cur.execute("""
                    SELECT p.slug, p.name, p.pathogen_id, path.name as pathogen_name
                    FROM projects p
                    LEFT JOIN pathogens path ON p.pathogen_id = path.id AND path.deleted_at IS NULL
                    WHERE p.id = %s AND p.deleted_at IS NULL
                """, (data['project_id'],))
                project = cur.fetchone()
                
                if not project:
                    cur.close()
                    conn.close()
                    return {"error": "Invalid project_id provided"}, 400
                
                # Insert new study
                cur.execute("""
                    INSERT INTO studies (id, name, description, project_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, NOW(), NOW())
                    RETURNING id, name, description, project_id, created_at, updated_at
                """, (
                    study_id,
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
        @studies_ns.response(404, 'Study not found')
        @authenticate_token
        def get(self, study_id):
            """Get study details by ID"""
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
