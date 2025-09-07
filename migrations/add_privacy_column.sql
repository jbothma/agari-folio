-- Add privacy column to projects table
-- Privacy can be 'public' or 'private', defaults to 'private' for security
ALTER TABLE projects ADD COLUMN privacy VARCHAR(10) DEFAULT 'private' CHECK (privacy IN ('public', 'private'));

-- Update existing projects to be private by default
UPDATE projects SET privacy = 'private' WHERE privacy IS NULL;

-- Make the column NOT NULL
ALTER TABLE projects ALTER COLUMN privacy SET NOT NULL;
