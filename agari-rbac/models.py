"""
Data models for AGARI Folio entities
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from database import get_db_cursor
import uuid
import logging

logger = logging.getLogger(__name__)

class BaseModel:
    """Base model with common functionality"""
    
    @classmethod
    def to_dict(cls, record) -> Dict[str, Any]:
        """Convert database record to dictionary"""
        if not record:
            return None
        
        result = dict(record)
        # Convert UUID and datetime objects to strings for JSON serialization
        for key, value in result.items():
            if isinstance(value, uuid.UUID):
                result[key] = str(value)
            elif isinstance(value, datetime):
                result[key] = value.isoformat()
        return result

class Pathogen(BaseModel):
    """Pathogen model"""
    
    @classmethod
    def get_all(cls) -> List[Dict[str, Any]]:
        """Get all pathogens"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM pathogens 
                WHERE deleted_at IS NULL 
                ORDER BY name
            """)
            return [cls.to_dict(record) for record in cursor.fetchall()]
    
    @classmethod
    def get_by_id(cls, pathogen_id: str) -> Optional[Dict[str, Any]]:
        """Get pathogen by ID"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM pathogens 
                WHERE id = %s AND deleted_at IS NULL
            """, (pathogen_id,))
            record = cursor.fetchone()
            return cls.to_dict(record) if record else None
    
    @classmethod
    def create(cls, name: str, scientific_name: str = None, description: str = None) -> Dict[str, Any]:
        """Create a new pathogen"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                INSERT INTO pathogens (name, scientific_name, description)
                VALUES (%s, %s, %s)
                RETURNING *
            """, (name, scientific_name, description))
            record = cursor.fetchone()
            return cls.to_dict(record)
    
    @classmethod
    def update(cls, pathogen_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Update a pathogen"""
        if not kwargs:
            return cls.get_by_id(pathogen_id)
        
        # Build dynamic update query
        fields = []
        values = []
        for key, value in kwargs.items():
            if key in ['name', 'scientific_name', 'description']:
                fields.append(f"{key} = %s")
                values.append(value)
        
        if not fields:
            return cls.get_by_id(pathogen_id)
        
        values.append(pathogen_id)
        
        with get_db_cursor() as cursor:
            cursor.execute(f"""
                UPDATE pathogens 
                SET {', '.join(fields)}
                WHERE id = %s AND deleted_at IS NULL
                RETURNING *
            """, values)
            record = cursor.fetchone()
            return cls.to_dict(record) if record else None
    
    @classmethod
    def delete(cls, pathogen_id: str) -> bool:
        """Soft delete a pathogen"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                UPDATE pathogens 
                SET deleted_at = CURRENT_TIMESTAMP
                WHERE id = %s AND deleted_at IS NULL
                RETURNING id
            """, (pathogen_id,))
            return cursor.fetchone() is not None
    
    @classmethod
    def is_referenced_by_projects(cls, pathogen_id: str) -> bool:
        """Check if pathogen is referenced by any active projects"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM projects 
                WHERE pathogen_id = %s AND deleted_at IS NULL
            """, (pathogen_id,))
            result = cursor.fetchone()
            return result['count'] > 0 if result else False

class Project(BaseModel):
    """Project model"""
    
    @classmethod
    def get_all(cls, user_org_id: str = None) -> List[Dict[str, Any]]:
        """Get all projects (optionally filtered by organization)"""
        query = """
            SELECT * FROM project_details 
            WHERE deleted_at IS NULL
        """
        params = []
        
        if user_org_id:
            query += " AND organisation_id = %s"
            params.append(user_org_id)
        
        query += " ORDER BY created_at DESC"
        
        with get_db_cursor() as cursor:
            cursor.execute(query, params)
            return [cls.to_dict(record) for record in cursor.fetchall()]
    
    @classmethod
    def get_by_slug(cls, slug: str) -> Optional[Dict[str, Any]]:
        """Get project by slug"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM project_details 
                WHERE slug = %s AND deleted_at IS NULL
            """, (slug,))
            record = cursor.fetchone()
            return cls.to_dict(record) if record else None
    
    @classmethod
    def get_by_id(cls, project_id: str) -> Optional[Dict[str, Any]]:
        """Get project by ID"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM project_details 
                WHERE id = %s AND deleted_at IS NULL
            """, (project_id,))
            record = cursor.fetchone()
            return cls.to_dict(record) if record else None
    
    @classmethod
    def create(cls, slug: str, name: str, description: str, organisation_id: str, 
               user_id: str, pathogen_id: str = None, privacy: str = 'public') -> Dict[str, Any]:
        """Create a new project"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                INSERT INTO projects (slug, name, description, organisation_id, user_id, pathogen_id, privacy)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (slug, name, description, organisation_id, user_id, pathogen_id, privacy))
            record = cursor.fetchone()
            return cls.to_dict(record)
    
    @classmethod
    def update(cls, project_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Update a project"""
        if not kwargs:
            return cls.get_by_id(project_id)
        
        # Build dynamic update query
        fields = []
        values = []
        for key, value in kwargs.items():
            if key in ['slug', 'name', 'description', 'pathogen_id', 'privacy']:
                fields.append(f"{key} = %s")
                values.append(value)
        
        if not fields:
            return cls.get_by_id(project_id)
        
        values.append(project_id)
        
        with get_db_cursor() as cursor:
            cursor.execute(f"""
                UPDATE projects 
                SET {', '.join(fields)}
                WHERE id = %s AND deleted_at IS NULL
                RETURNING *
            """, values)
            record = cursor.fetchone()
            return cls.to_dict(record) if record else None
    
    @classmethod
    def delete(cls, project_id: str) -> bool:
        """Soft delete a project"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                UPDATE projects 
                SET deleted_at = CURRENT_TIMESTAMP
                WHERE id = %s AND deleted_at IS NULL
                RETURNING id
            """, (project_id,))
            return cursor.fetchone() is not None

class Study(BaseModel):
    """Study model"""
    
    @classmethod
    def get_by_project(cls, project_id: str) -> List[Dict[str, Any]]:
        """Get all studies for a project"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM study_details 
                WHERE project_id = %s AND deleted_at IS NULL
                ORDER BY created_at DESC
            """, (project_id,))
            return [cls.to_dict(record) for record in cursor.fetchall()]
    
    @classmethod
    def get_by_id(cls, study_id: str) -> Optional[Dict[str, Any]]:
        """Get study by ID"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM study_details 
                WHERE id = %s AND deleted_at IS NULL
            """, (study_id,))
            record = cursor.fetchone()
            return cls.to_dict(record) if record else None
    
    @classmethod
    def get_by_study_id(cls, study_id: str) -> Optional[Dict[str, Any]]:
        """Get study by study_id"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM study_details 
                WHERE study_id = %s AND deleted_at IS NULL
            """, (study_id,))
            record = cursor.fetchone()
            return cls.to_dict(record) if record else None
    
    @classmethod
    def create(cls, study_id: str, name: str, description: str, project_id: str,
               start_date: str = None, end_date: str = None) -> Dict[str, Any]:
        """Create a new study"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                INSERT INTO studies (study_id, name, description, project_id, start_date, end_date)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (study_id, name, description, project_id, start_date, end_date))
            record = cursor.fetchone()
            return cls.to_dict(record)
    
    @classmethod
    def update(cls, study_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Update a study"""
        if not kwargs:
            return cls.get_by_id(study_id)
        
        # Build dynamic update query
        fields = []
        values = []
        for key, value in kwargs.items():
            if key in ['study_id', 'name', 'description', 'start_date', 'end_date']:
                fields.append(f"{key} = %s")
                values.append(value)
        
        if not fields:
            return cls.get_by_id(study_id)
        
        values.append(study_id)
        
        with get_db_cursor() as cursor:
            cursor.execute(f"""
                UPDATE studies 
                SET {', '.join(fields)}
                WHERE id = %s AND deleted_at IS NULL
                RETURNING *
            """, values)
            record = cursor.fetchone()
            return cls.to_dict(record) if record else None
    
    @classmethod
    def delete(cls, study_id: str) -> bool:
        """Soft delete a study"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                UPDATE studies 
                SET deleted_at = CURRENT_TIMESTAMP
                WHERE id = %s AND deleted_at IS NULL
                RETURNING id
            """, (study_id,))
            return cursor.fetchone() is not None
