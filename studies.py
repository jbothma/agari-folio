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
    
    # can they create a study
    def post(self):
        # creates in song AS the superuser
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

