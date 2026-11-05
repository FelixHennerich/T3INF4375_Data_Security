CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS data;
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE auth.companies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(10) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE auth.roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE auth.users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    company_id INTEGER REFERENCES auth.companies(id),
    role_id INTEGER REFERENCES auth.roles(id),
    is_active BOOLEAN DEFAULT TRUE,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE auth.sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id INTEGER REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    company_id INTEGER REFERENCES auth.companies(id),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE data.meter_points (
    id SERIAL PRIMARY KEY,
    meter_point_id VARCHAR(50) NOT NULL,
    company_id INTEGER NOT NULL REFERENCES auth.companies(id),
    pseudonym VARCHAR(100) NOT NULL,
    encrypted_name BYTEA,
    encrypted_address BYTEA,
    encrypted_zip_code BYTEA,
    data_key BYTEA,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (company_id, meter_point_id),
    UNIQUE (pseudonym)
);

CREATE TABLE data.consumption_hourly (
    id BIGSERIAL PRIMARY KEY,
    meter_point_id INTEGER NOT NULL REFERENCES data.meter_points(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL,
    encrypted_value BYTEA NOT NULL,
    aad_meter_point_id TEXT NOT NULL,
    aad_timestamp TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (meter_point_id, timestamp)
);

CREATE TABLE data.load_profiles (
    id BIGSERIAL PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES auth.companies(id),
    cohort_id VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    aggregated_value NUMERIC(15, 4) NOT NULL,
    num_households INTEGER NOT NULL,
    is_approved BOOLEAN DEFAULT FALSE,
    approved_by INTEGER REFERENCES auth.users(id),
    approved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (company_id, cohort_id, timestamp)
);

CREATE TABLE data.fault_requests (
    id SERIAL PRIMARY KEY,
    meter_point_id INTEGER NOT NULL REFERENCES data.meter_points(id),
    requested_by INTEGER NOT NULL REFERENCES auth.users(id),
    request_reason TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    approved_by INTEGER REFERENCES auth.users(id),
    approved_at TIMESTAMP,
    fulfilled_by INTEGER REFERENCES auth.users(id),
    fulfilled_at TIMESTAMP,
    deletion_key_destroyed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);


CREATE TABLE audit.external_anchors (
    id SERIAL PRIMARY KEY,
    anchor_value TEXT NOT NULL,
    anchor_type VARCHAR(50) NOT NULL,
    location TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE audit.audit_log (
    id BIGSERIAL PRIMARY KEY,
    sequence_number BIGINT NOT NULL UNIQUE,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    user_id INTEGER REFERENCES auth.users(id),
    session_id UUID REFERENCES auth.sessions(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id TEXT NOT NULL,
    company_id INTEGER REFERENCES auth.companies(id),
    ip_address INET,
    user_agent TEXT,
    status_code INTEGER,
    details JSONB,
    previous_hash BYTEA NOT NULL,
    current_hash BYTEA NOT NULL,
    anchor_id INTEGER REFERENCES audit.external_anchors(id)
);

CREATE INDEX idx_audit_log_sequence ON audit.audit_log(sequence_number);

CREATE TABLE crypto.key_metadata (
    id SERIAL PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES auth.companies(id),
    key_type VARCHAR(50) NOT NULL,
    key_version INTEGER NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

INSERT INTO auth.companies (name, code) VALUES
    ('Stadtwerke Neckartal', 'SWN'),
    ('Stadtwerke Bergland', 'SWB')
ON CONFLICT DO NOTHING;

INSERT INTO auth.roles (name, description) VALUES
    ('customer', 'View own contract and load profile data'),
    ('billing', 'Access to billing data: name, tariff, consumption sum, invoice amount for own utility'),
    ('network_analyst', 'Access to aggregated load profiles of network segments (ZIP codes) for network planning and load forecasting'),
    ('fault_service', 'Short-term access to current measurement values of individual meters in affected network segment during faults'),
    ('control_center', 'Review and approve fault service access requests (24/7) - Separation of Duties'),
    ('audit', 'Audit log access')
ON CONFLICT DO NOTHING;

INSERT INTO auth.users (username, password_hash, salt, company_id, role_id, is_active) VALUES
    -- SWN Users (company_id = 1)
    ('alice.mueller', 'placeholder_hash_alice', 'salt_alice', 1, (SELECT id FROM auth.roles WHERE name = 'customer'), TRUE),
    ('bob.schmidt', 'placeholder_hash_bob', 'salt_bob', 1, (SELECT id FROM auth.roles WHERE name = 'billing'), TRUE),
    ('charlie.weber', 'placeholder_hash_charlie', 'salt_charlie', 1, (SELECT id FROM auth.roles WHERE name = 'network_analyst'), TRUE),
    
    -- SWB Users (company_id = 2)
    ('dave.neumann', 'placeholder_hash_dave', 'salt_dave', 2, (SELECT id FROM auth.roles WHERE name = 'fault_service'), TRUE),
    ('eve.schulz', 'placeholder_hash_eve', 'salt_eve', 2, (SELECT id FROM auth.roles WHERE name = 'control_center'), TRUE),
    ('frank.hartmann', 'placeholder_hash_frank', 'salt_frank', 2, (SELECT id FROM auth.roles WHERE name = 'customer'), TRUE)
ON CONFLICT DO NOTHING;

INSERT INTO audit.external_anchors (anchor_value, anchor_type, location, verified_at) 
VALUES (
    encode(digest('gridvault-init' || NOW()::TEXT, 'sha256'), 'hex'),
    'initialization',
    'local',
    NOW()
) ON CONFLICT DO NOTHING;


INSERT INTO audit.audit_log (
    sequence_number, action, resource_type, resource_id,
    current_hash, previous_hash
) VALUES (
    0, 'init', 'system', 'gridvault',
    encode(digest('init' || NOW()::TEXT, 'sha256'), 'hex')::BYTEA,
    '\x0000000000000000000000000000000000000000000000000000000000000000'::BYTEA
) ON CONFLICT DO NOTHING;
