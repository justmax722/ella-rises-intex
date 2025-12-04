-- Profile: Delete profile when user is deleted
ALTER TABLE profile
DROP CONSTRAINT IF EXISTS profile_userid_fkey;

ALTER TABLE profile
ADD CONSTRAINT profile_userid_fkey
FOREIGN KEY (userid) REFERENCES users(userid)
ON DELETE CASCADE;

-- Donation: Anonymize donations
ALTER TABLE donation
DROP CONSTRAINT IF EXISTS donation_userid_fkey;

ALTER TABLE donation
ADD CONSTRAINT donation_userid_fkey
FOREIGN KEY (userid) REFERENCES users(userid)
ON DELETE SET NULL;

-- Registration: Delete registrations
ALTER TABLE registration
DROP CONSTRAINT IF EXISTS registration_userid_fkey;

ALTER TABLE registration
ADD CONSTRAINT registration_userid_fkey
FOREIGN KEY (userid) REFERENCES users(userid)
ON DELETE CASCADE;

-- UserMilestone: Delete milestones
ALTER TABLE usermilestone
DROP CONSTRAINT IF EXISTS usermilestone_userid_fkey;

ALTER TABLE usermilestone
ADD CONSTRAINT usermilestone_userid_fkey
FOREIGN KEY (userid) REFERENCES users(userid)
ON DELETE CASCADE;

-- Survey: Delete survey responses
ALTER TABLE survey
DROP CONSTRAINT IF EXISTS survey_userid_fkey;

ALTER TABLE survey
ADD CONSTRAINT survey_userid_fkey
FOREIGN KEY (userid) REFERENCES users(userid)
ON DELETE CASCADE;