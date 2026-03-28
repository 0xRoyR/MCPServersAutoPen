-- AutoPen MySQL Initialization Script
-- Run automatically by Docker on first start (docker-entrypoint-initdb.d)
-- TypeORM (synchronize: true) will create/update tables automatically in dev.
-- This script only sets up the database and user permissions.

-- Ensure utf8mb4 for full Unicode support
ALTER DATABASE autopen CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Grant all privileges to the autopen user on this database
GRANT ALL PRIVILEGES ON autopen.* TO 'autopen'@'%';
FLUSH PRIVILEGES;
