# GridVault Development Plan

## Project Overview

**Project Name:** GridVault  
**Module:** Data Security (DS) - DHBW 2026/27  
**Type:** Practical Exam - Milestone 2 (75% of grade)  
**Status:** Backend setup initialized, implementation pending  
**Current Branch:** main

---

## Table of Contents

1. [Project Context](#1-project-context)
2. [Milestone 1 - Completed (Reference)](#2-milestone-1---completed-reference)
3. [Milestone 2 - Implementation Requirements](#3-milestone-2---implementation-requirements)
4. [Phase 1: Core Infrastructure (Week 1)](#4-phase-1-core-infrastructure-week-1)
5. [Phase 2: Security Foundation (Week 1-2)](#5-phase-2-security-foundation-week-1-2)
6. [Phase 3: Business Logic (Week 2-3)](#6-phase-3-business-logic-week-2-3)
7. [Phase 4: Audit & Compliance (Week 3-4)](#7-phase-4-audit--compliance-week-3-4)
8. [Phase 5: Testing & Validation (Week 4)](#8-phase-5-testing--validation-week-4)
9. [Phase 6: Documentation (Week 4-5)](#9-phase-6-documentation-week-4-5)
10. [Phase 7: Finalization & Submission](#10-phase-7-finalization--submission)
11. [Test Matrix](#11-test-matrix)
12. [Architecture Decisions](#12-architecture-decisions)
13. [Security Considerations](#13-security-considerations)
14. [Timeline & Milestones](#14-timeline--milestones)
15. [Dependencies & Resources](#15-dependencies--resources)
16. [Risk Assessment](#16-risk-assessment)

---

## 1. Project Context

### Scenario
GridVault is a data platform operated as a PaaS (Platform as a Service) on a public cloud. Two utility companies, **Stadtwerke Neckartal (SWN)** and **Stadtwerke Bergland (SWB)**, are separate tenants sharing the same installation.

### Data Classes
1. **Contract master data**: Name, address, meter ID (Zaahlpunkt-ID), ZIP code, tariff
2. **Load profile data**: Hourly consumption values (24 values per day per household)
3. **Billing data**: Consumption sum, amount

### Roles & Requirements

| Role | Needs | Must NOT |
|------|-------|----------|
| **Customer** | View own contract and load profile data | See other meter points |
| **Billing** | Name, tariff, consumption sum, invoice amount per meter point of own utility | See individual hourly values (presence profile), see other utility's data |
| **Network Analyst** | Aggregated load profiles of entire network segments (ZIP codes) for network planning and load forecasting; pseudonymized exports for data mining | Identify or reconstruct individual households (small cells, differential attack) |
| **Fault Service** | Short-term access to current measurement values of individual meters in affected network segment during faults | Access without reason, without approval, outside segment, or after expiry |
| **Control Center** | Review and approve fault service access requests (24/7) - Separation of Duties | Read measurement data themselves; approve own requests |

### Threat Model (4 Attackers)
1. **Cloud Administrator**: Has access to platform, file system, and backups. Must NOT be able to read load profiles or delete audit entries undetected (but without keys)
2. **Attacker with write access to database file**: Tries to modify, swap, or delete values
3. **Curious Network Analyst**: Tries to re-identify households via clever aggregate queries
4. **Employee of Utility B**: Tries to access Utility A's data (multi-tenancy risk)

---

## 2. Milestone 1 - Completed (Reference)

Milestone 1 covered architecture design and planning:
- **Task 1**: Architecture sketch with trust boundaries
- **Task 2**: Implementation plan (technology, structure, principles, tests)
- **Task 3**: STRIDE threat analysis
- **Task 4**: Human, process, technology, and cloud considerations
- **Data Protection Tasks 5-7**: Data classification, roles, data breach scenarios

**Status**: Conceptual work completed, now implementing in code.

---

## 3. Milestone 2 - Implementation Requirements

### Part A: Programming (60% of M2 = 45% of total grade)

#### A1: Identity, Session, and Multi-Tenancy (10 points)
- [ ] **Multi-tenancy**: 2 utility companies (SWN, SWB) with 6 test users covering all 5 roles
- [ ] **User requirements**: Each user belongs to exactly one utility company
- [ ] **Password storage**: Salted hash using Argon2, bcrypt, scrypt, or PBKDF2
- [ ] **Password comparison**: Constant-time comparison
- [ ] **Password input**: Masked
- [ ] **Session management**: After login, maintain session with user-ID, utility company, role, and expiry time
- [ ] **Authorization**: All subsequent actions authorized against session only
- [ ] **Security**: Failed logins must NOT reveal if username exists (same error message)

#### A2: Encryption and Key Management - Security at Rest (20 points + 5 bonus)
- [ ] **Data storage**: PostgreSQL with minimum 8 meter points (4 per utility) and 24 hourly values per meter point (1 full day)
- [ ] **Test data generator**: Create realistic test data
- [ ] **Key management**: One main key per utility company, stored outside source code and database (file in separate directory or environment variable)
- [ ] **Key service**: Small key service module for accessing main key
- [ ] **Encryption scope**: Encrypt name, address, and each individual hourly value (AES-256 in authenticated mode: Fernet or AES-GCM)
- [ ] **Plaintext fields**: Only meter point ID, utility company, ZIP code, and tariff remain in plaintext
- [ ] **Rationale**: Code comments explaining why these fields remain plaintext
- [ ] **Context binding**: Ciphertext bound to meter point and timestamp
  - Option A: Include context in plaintext: `{"zp":"DE00...","ts":"2026-09-01T07:00","kwh":"1.238"}`
  - Option B: Use Additional Authenticated Data (AAD) with AES-GCM
- [ ] **Integrity check**: Swapping two valid ciphertexts must be detected and reported as integrity violation (Test T5)
- [ ] **Bonus (up to 5 points)**: Two-level key concept - each meter point gets its own data key, encrypted with main key and stored in database. Deletion requests implemented by destroying data key; all values become unreadable, even in backups

#### A3: Gateway Logic and Role Matrix (20 points)
- [ ] **Central gateway**: All data access goes through ONE central function
- [ ] **Check order**: Session valid → Role can perform action → Utility company matches → Object reference (own meter / cohort / approval) → Decryption with context check → Aggregation/masking → Audit entry
- [ ] **Role-specific output**:

| Role | Access Scope | Output | Condition |
|------|--------------|--------|-----------|
| **Customer** | Exactly own meter point | All fields including hourly values in plaintext | ID match between account and meter point |
| **Billing** | Meter points of own utility | Name, meter point, tariff, consumption sum, amount; load profile as [NOT RELEASED] | Sum calculated in gateway; individual values don't leave function |
| **Network Analyst** | Cohorts (all meter points of a ZIP code) of own utility | Only hourly sum of cohort; export for analysis environment only with pseudonyms instead of meter point IDs; never names | Small cell protection: cohort has at least k=3 meter points, otherwise rejection with n and k |
| **Fault Service** | Meter points in an approved network segment (ZIP) | Meter point, ZIP, last measurement value; name as [HIDDEN] | Valid, non-expired approval from control center for exactly this segment (A4) |
| **Control Center** | Open requests of own utility | View and approve requests; no data access | Must not approve own requests |

- [ ] **Pseudonym generation**: HMAC over meter point ID with separate key per utility (not the main key)
  - Stable but not directly reversible without key
  - Simple SHA-256 without key is NOT sufficient (explain why in code)

#### A4: Fault Approval - Four-Eyes Principle, Time-Limited, Segment-Specific (10 points)
- [ ] **Initial state**: Fault service has NO data access
- [ ] **Workflow**:
  1. Fault service creates **request** for network segment (ZIP) with ticket number and free-text justification (minimum length)
  2. **Control center** sees open requests of own utility and grants **approval**
  3. Requester and approver must be different people
  4. Approval valid **only for requested segment** and **only 30 minutes**
  5. After expiry, all access denied
  6. For testing, duration can be shortened via configuration
- [ ] **Audit trail**: Request, approval, each access, and each denial documented in audit trail with ticket reference
- [ ] **Security**: Free-text justification remains in protected ticket system, NOT copied to audit log

#### A5: Audit Trail as Hash Chain with External Anchor (10 points)
- [ ] **Audit scope**: Every action generates entry in audit_trail.log:
  - Login success and failure
  - Every query
  - Every denial
  - Every integrity violation
  - Approvals
  - Deletions
- [ ] **File mode**: Append-only mode
- [ ] **Privacy**: Personal log content minimized; integrity chain doesn't replace deletion rules
- [ ] **Mandatory fields**: Sequential number, timestamp, utility company, pseudonymous user identification, role, action, minimized object identification, result, reason, hash of previous entry, own hash
- [ ] **Exclusions**: Names, plaintext load profiles, free-text justifications NOT copied to log
- [ ] **External anchor**: Hash of last entry written to second location (anchor file in separate directory)
  - Represents WORM storage that application administrator doesn't control
- [ ] **Verification tool**: Standalone verification script (no login, so verification doesn't append anything)
  - Verifies entire chain
  - Compares last hash with anchor
  - Distinguishes: modified or deleted entry in chain, truncated end

#### A6: Deletion Functions (10 points)
- [ ] **Configurable deletion cycle**: For load profiles and analysis exports with traceable start date
- [ ] **Consider exceptions**: Account for justified retention requirements
- [ ] **Backup simulation**: Simulate backup restoration and reapply deletion cycle
- [ ] **Documentation**: Document event without rewriting deleted content back to log

#### A7: Rights and Roles (10 points)
- [ ] **Role matrix implementation**: Implement existing role matrix with purpose and object reference in central gateway
- [ ] **Test cases**: Test at least:
  - Analyst without individual value access
  - Technical support without subject-matter read access
  - Permission revocation before next query

#### A8: Data-Minimal Protocols (5 points)
- [ ] **Verification**: Using a denial and a deletion cycle, verify that audit and error messages contain NO:
  - Names
  - Load profiles
  - Free-text justifications

#### A9: Runtime and Submission Format (5 points)
- [ ] **Packaging**: ZIP or Git repository with README
- [ ] **README contents**:
  - Installation
  - Startup
  - Test users and passwords
  - Reproduction of all tests from B4 with few commands
- [ ] **Security**: No keys, no passwords in plaintext in source code
- [ ] **Structure**: Sensible module structure (Login, Crypto, Key Service, Gateway, Audit separated)

### Part B: Written Documentation (40% of M2 = 30% of total grade)

#### B1: Architecture Comparison and Decisions (15 points)
- [ ] **Comparison table**: Compare exam concept with implementation for:
  - Programming language and libraries
  - Main key storage
  - Context binding
  - Multi-tenant separation
  - Fault approval
  - Audit protection
- [ ] **Reflection**: At least 2 rows with genuine reflection (e.g., "in design I overlooked..., test T5 showed...")
- [ ] **Appendix**: Copy of graded exam paper (M1)
- [ ] **Decision table**: Three implementation decisions with rejected alternatives and reasons
  - Mandatory: Path (a) or (b) of context binding
  - Additional: Deletion cycle and permission check

#### B2: Protection Requirements and Risks of Data Aggregation (20 points)
- [ ] **CIA table**: Evaluate three data classes by confidentiality, integrity, availability (low/medium/high/very high) with justification for each classification
- [ ] **Load profile vs monthly sum**: Why hourly load profile is more protection-worthy than calculated monthly sum? Which GDPR principle applies and how does billing role implement it technically?
- [ ] **Re-identification despite k-anonymity**: Using concrete numbers from system, show how network analyst could determine consumption of single household if they could combine cohorts (two queries with n >= k, subtraction). Explain why implementation prevents or doesn't prevent this
- [ ] **Countermeasures**: Name and evaluate two measures against differential attacks (e.g., fixed cohorts, generalization, query budget, noise) regarding utility for network planning

#### B3: Cloud Operation and Provider Collaboration (20 points)
- [ ] **Shared responsibility**: Assign at least 8 security tasks (physical security, OS patching, runtime environment, gateway logic, main key custody, audit trail anchor, backups, utility company employee identities) to provider, customer, or both for PaaS. What changes with IaaS or SaaS?
- [ ] **Who has the key?**: Compare cloud-native keys, BYOK, HYOK for GridVault main key. What does customer-managed variant protect against platform administrator - and what doesn't (keyword: Data in Use, plaintext in working memory)?
- [ ] **Public, private, or hybrid**: Evaluate which GridVault components could run in public cloud and which should be in private cloud or on-premises, given utility companies are critical infrastructure
- [ ] **Audit trail in cloud**: How to prevent cloud administrator from deleting audit entries? Reference WORM/Object Lock from lecture and explain role of anchor from prototype

#### B4: Test Protocol (15 points)
- [ ] **Documentation**: Document each test with console output or screenshot AND corresponding audit entry
- [ ] **Reproducibility**: Via README

**Test Matrix:**

| # | Test | Expected Result | Points |
|---|------|-----------------|--------|
| T1 | Login with wrong then correct password | Rejection without indicating user existence; success with role and utility; both in audit trail | 2 |
| T2 | Billing requests (a) meter point of own utility, (b) other utility, (c) network analyst action | (a) sum and amount, load profile masked; (b) and (c) rejected | 2 |
| T3 | Network analyst requests cohort with n<3 and n>=3; export | Small cell rejected with n and k; hourly sum; export only with pseudonyms | 2 |
| T4 | Fault service without approval → request → approval by control center → access in segment → access outside segment → access after expiry | Rejected / request open / approval granted / value visible, name masked / rejected / rejected | 3 |
| T5 | Integrity test: Swap ciphertexts of two hourly values of same meter point in database. Read as billing. | Integrity violation with meter point and timestamp; audit entry. Explain why authenticated encryption alone doesn't detect this, even though it detects single character changes | 4 |
| T6 | Audit trail: (a) delete middle entry, (b) truncate last entry, run verification tool | (a) chain break with line number; (b) detection via anchor. Explain why hash chain alone doesn't detect (b) | 2 |

**Bonus**: If A2 bonus implemented, additionally document: delete → query as billing → proof that previously created backup copy still contains ciphertexts

#### B5: Purposes, Legal Bases, and Transparency (10 points)
- [ ] **Purposes and legal bases**: Compare billing and network planning: what are consumption data needed for, which data required, which can be omitted? Present in table using implementation's data fields
- [ ] **Pseudonymized exports**: Are pseudonymized exports for analysis environment still personal data from utility companies' perspective? Justify and name a consequence for processing
- [ ] **Customer information**: Explain how customers informed about purposes, legal bases, and recipients of pseudonymized/anonymized analysis exports. Explain why anonymization doesn't justify arbitrary further use. Briefly describe processing of information request for GridVault data
- [ ] **Attachment**: Separate PDF with common privacy notice for website and electricity contract; mark questions still to be clarified; highlight two places specifically adapted to system

#### B6: Deletion, Permissions, and Data Breach (11 points)
- [ ] **Deletion concept**: Table for load profiles, contract/billing data, analysis exports, tickets, audit logs, backups. For each: purpose, start of period, justified period/clarification needed, deletion method, responsibility. Mark what's implemented in Part A and what needs adding for production
- [ ] **Re-identification prevention**: Briefly explain using A6 implementation how to prevent deleted data from being permanently available again after backup restoration
- [ ] **Rights and roles**: Compare implementation using two denied accesses and one successful fault approval with target matrix. Name decisive check and possible deviation
- [ ] **Data breach**: Compromised support account exports load profiles of 20 households. Breach detected via audit trail; no evidence of publication. Evaluate if notification to supervisory authority and affected persons required. Show using two implemented protection measures how they prevented/limited/helped investigate breach, and name remaining weakness

#### B7: EU Hosting and US Provider (9 points)
- [ ] **Collaboration model**: Based on described participants:
  - SWN and SWB: Contract partners for electricity customers; joint determination of purposes and essential functions
  - METO-HUB Ltd., Ireland: Platform and backup operation according to utility specifications
  - METO AG, USA: Parent company of METO-HUB, initially not involved, later remote support
  - Provider's support service: Administers platform technology on behalf; access only when needed and time-limited; no subject-matter read access to customer/load data

- [ ] **EU hosting and US access**: What dataprotection requirements to check before commissioning METO-HUB? Name and justify required data protection agreement and key criteria. Explain significance of possible access rights of US parent despite hosting in Ireland, and what information still needs clarifying. Show using architecture where such access to plaintext data would be possible
- [ ] **AVV and third-country transfer**: After commissioning, METO AG should receive remote access to personal data in individual support cases. Actively certified under EU-US Data Privacy Framework (DPF) for "Non-HR Data". What additional checks and measures required? Are SCC and TIA necessary and who must ensure this? Then show how assessment changes if no DPF certification exists
- [ ] **Third-country transfer**: How does assessment change if parent company has seat in Canada and support access exclusively from there? Justify prerequisites for access admissibility

### Required Attachments
- [ ] Copy of graded exam paper (M1)
- [ ] KI declaration: Which tools used and for what (code generation, explanation, text processing, error search)? Which suggestions rejected and why?

---

## 4. Phase 1: Core Infrastructure (Week 1)

### Objectives
Establish project structure, data models, and basic functionality.

### Tasks

#### 4.1 Project Structure Setup
- [ ] Create proper Python project structure
- [ ] Set up FastAPI with proper routing
- [ ] Configure PostgreSQL database (Docker container)
- [ ] Set up environment management (.env files)
- [ ] Create requirements.txt or pyproject.toml

**Directory Structure:**
```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Configuration management
│   ├── database.py          # Database setup
│   ├── models/              # Data models
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── meter_point.py
│   │   ├── consumption.py
│   │   ├── session.py
│   │   ├── request.py
│   │   └── audit.py
│   ├── services/            # Business logic
│   │   ├── __init__.py
│   │   ├── auth_service.py
│   │   ├── crypto_service.py
│   │   ├── key_service.py
│   │   ├── gateway_service.py
│   │   └── audit_service.py
│   ├── schemas/             # Pydantic models
│   │   ├── __init__.py
│   │   └── *.py
│   ├── routers/             # API endpoints
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── data.py
│   │   ├── admin.py
│   │   └── fault.py
│   └── utils/               # Utilities
│       ├── __init__.py
│       ├── logger.py
│       └── test_data.py
├── src/
│   └── backend/             # Legacy, consolidate into app/
├── tests/                   # Test suite
│   ├── __init__.py
│   ├── test_auth.py
│   ├── test_crypto.py
│   ├── test_gateway.py
│   ├── test_audit.py
│   └── test_integration.py
├── scripts/                 # Standalone scripts
│   ├── verify_audit.py     # A5 verification tool
│   ├── generate_test_data.py
│   └── backup_restore.py
├── keys/                    # Key storage (gitignored)
│   ├── swn_key.txt
│   ├── swb_key.txt
│   ├── swn_pseudo_key.txt
│   └── swb_pseudo_key.txt
├── audit/                   # Audit trail (gitignored)
│   ├── audit_trail.log
│   └── anchor.txt
├── .env.example             # Environment template
├── .env                     # Environment (gitignored)
├── README.md
├── plan.md                  # This file
└── pyproject.toml
```

#### 4.2 Data Models
- [ ] Define User model (id, username, password_hash, salt, utility_id, role)
- [ ] Define Utility model (id, name)
- [ ] Define MeterPoint model (id, user_id, utility_id, meter_point_id, zip_code, tariff, encrypted_name, encrypted_address)
- [ ] Define Consumption model (id, meter_point_id, timestamp, encrypted_value)
- [ ] Define Session model (id, user_id, utility_id, role, expiry, token)
- [ ] Define Request model (id, user_id, utility_id, zip_code, ticket_number, justification, status)
- [ ] Define Approval model (id, request_id, approver_id, expiry)
- [ ] Define AuditLog model (id, timestamp, utility_id, user_id_pseudo, role, action, object_id_min, result, reason, prev_hash, own_hash)

#### 4.3 Database Initialization
- [ ] Create PostgreSQL database schema
- [ ] Implement migrations
- [ ] Create test data generator:
  - 2 utility companies (SWN, SWB)
  - 6 test users covering all 5 roles
  - 8 meter points (4 per utility)
  - 24 hourly values per meter point
  - Sample requests and approvals

#### 4.4 Configuration Management
- [ ] Set up configuration for:
  - Key file locations
  - Session timeout (configurable)
  - Fault approval duration (configurable, default 30 min)
  - k-value for small cell protection (default 3)
  - Database path
  - Audit log path
  - Anchor file path

---

## 5. Phase 2: Security Foundation (Week 1-2)

### Objectives
Implement authentication, encryption, and key management.

### Tasks

#### 5.1 Authentication Service (A1)
- [ ] Implement password hashing using bcrypt (recommended for Python)
- [ ] Create user registration (for test data only, not production)
- [ ] Implement login endpoint
- [ ] Implement session creation with:
  - User ID
  - Utility company
  - Role
  - Expiry time (configurable, e.g., 8 hours)
- [ ] Implement session validation middleware
- [ ] Mask password input in logs/console
- [ ] Constant-time password comparison
- [ ] Generic error messages (don't reveal if user exists)

**Dependencies:**
- `bcrypt` or `argon2-cffi` for password hashing
- `python-jose` or similar for session tokens

#### 5.2 Key Service (A2)
- [ ] Implement key service module (`key_service.py`)
- [ ] Support multiple key storage methods:
  - File-based (primary for prototype)
  - Environment variable-based
- [ ] Key loading from external directory (outside code and DB)
- [ ] Key caching with secure memory handling
- [ ] Key per utility company
- [ ] Separate pseudonym keys per utility

**Key Storage Structure:**
```
keys/
├── swn/
│   ├── main.key          # AES-256 key for SWN
│   └── pseudo.key        # HMAC key for pseudonymization
└── swb/
    ├── main.key          # AES-256 key for SWB
    └── pseudo.key        # HMAC key for pseudonymization
```

#### 5.3 Crypto Service (A2)
- [ ] Implement encryption service using `cryptography` library
- [ ] Support AES-256-GCM (authenticated encryption)
- [ ] Implement context binding:
  - **Option B (Recommended)**: Use AAD (Additional Authenticated Data) with meter_point_id and timestamp
- [ ] Encrypt/decrypt individual fields:
  - Name
  - Address
  - Each hourly consumption value
- [ ] Plaintext fields: meter_point_id, utility_id, zip_code, tariff
- [ ] Integrity check: Validate context binding on decryption
- [ ] Error handling: Detect and report integrity violations

**Example Encryption:**
```python
# Using AES-GCM with AAD
def encrypt_value(value: str, key: bytes, meter_point_id: str, timestamp: str) -> bytes:
    # Generate random nonce
    # Encrypt with AAD = (meter_point_id, timestamp)
    # Return ciphertext + nonce + tag
    pass

def decrypt_value(ciphertext: bytes, key: bytes, meter_point_id: str, timestamp: str) -> str:
    # Decrypt with AAD verification
    # If AAD doesn't match, raise IntegrityError
    pass
```

#### 5.4 Bonus: Two-Level Key Concept (A2 Bonus)
- [ ] Generate data key per meter point
- [ ] Encrypt data key with main utility key
- [ ] Store encrypted data key in database
- [ ] Use data key for encrypting consumption values
- [ ] Implement deletion: destroy data key → all values unreadable
- [ ] Verify that backups containing old ciphertexts become unreadable

---

## 6. Phase 3: Business Logic (Week 2-3)

### Objectives
Implement gateway logic, role matrix, and fault approval workflow.

### Tasks

#### 6.1 Gateway Service (A3)
- [ ] Implement central gateway function with strict check order:
  1. Validate session
  2. Check role can perform action
  3. Verify utility company match
  4. Validate object reference (own meter / cohort / approval)
  5. Decrypt with context check
  6. Apply aggregation/masking
  7. Write audit entry
- [ ] Create role-based output formatting
- [ ] Implement masking for restricted fields

**Gateway Check Order Code:**
```python
def gateway_request(session: Session, action: str, **kwargs) -> Response:
    # 1. Session validation
    if not validate_session(session):
        audit_log("denied", "invalid_session")
        raise UnauthorizedError("Invalid session")
    
    # 2. Role check
    if not role_can_perform(session.role, action):
        audit_log("denied", "role_denied", session)
        raise ForbiddenError("Role not authorized")
    
    # 3. Utility match
    if not utility_matches(session, kwargs):
        audit_log("denied", "utility_mismatch", session)
        raise ForbiddenError("Utility mismatch")
    
    # 4. Object reference
    if not validate_object_reference(session, action, kwargs):
        audit_log("denied", "object_denied", session)
        raise ForbiddenError("Object access denied")
    
    # 5. Decrypt with context
    try:
        data = decrypt_with_context(session, kwargs)
    except IntegrityError as e:
        audit_log("integrity_violation", str(e), session)
        raise IntegrityError(f"Integrity violation: {e}")
    
    # 6. Aggregate/mask
    output = apply_role_transform(session.role, data)
    
    # 7. Audit
    audit_log("success", action, session, output_metadata)
    
    return output
```

#### 6.2 Role Implementation

**Customer Role:**
- [ ] Query own meter point only
- [ ] Return all fields including decrypted hourly values
- [ ] Verify ID match between account and meter point

**Billing Role:**
- [ ] Query meter points of own utility
- [ ] Return: name, meter point ID, tariff, consumption sum, amount
- [ ] Mask load profile as "[NOT RELEASED]"
- [ ] Calculate sum in gateway (individual values don't leave function)

**Network Analyst Role:**
- [ ] Query cohorts (all meter points of a ZIP code) of own utility
- [ ] Return only hourly sum of cohort
- [ ] Export for analysis: pseudonyms instead of meter point IDs
- [ ] Never return names
- [ ] Small cell protection: reject if cohort has < k meter points
- [ ] Return n and k in rejection message

**Fault Service Role:**
- [ ] Initially NO data access
- [ ] Query meter points in approved network segment (ZIP)
- [ ] Return: meter point ID, ZIP, last measurement value
- [ ] Mask name as "[HIDDEN]"
- [ ] Verify valid, non-expired approval for exact segment

**Control Center Role:**
- [ ] View open requests of own utility
- [ ] Approve requests
- [ ] NO data access
- [ ] Cannot approve own requests (separation of duties)

#### 6.3 Pseudonym Service (A3)
- [ ] Implement HMAC-based pseudonymization
- [ ] Use separate key per utility (not main key)
- [ ] Generate stable pseudonyms for meter point IDs
- [ ] Ensure non-reversibility without key

**Implementation:**
```python
def generate_pseudonym(meter_point_id: str, utility_key: bytes) -> str:
    hmac = HMAC(utility_key, 'sha256')
    hmac.update(meter_point_id.encode())
    return hmac.hexdigest()
```

**Rationale for HMAC over SHA-256:**
- SHA-256 without key is vulnerable to rainbow table attacks
- HMAC with secret key provides security even if meter point IDs have low entropy
- Key separation prevents main key compromise from affecting pseudonymization

#### 6.4 Fault Approval Workflow (A4)
- [ ] Implement request creation endpoint
- [ ] Validate minimum justification length
- [ ] Generate ticket number
- [ ] Store request with status "pending"
- [ ] Implement approval endpoint
- [ ] Verify approver != requester
- [ ] Set approval expiry (default 30 min, configurable)
- [ ] Store approval with reference to request
- [ ] Implement access check middleware
- [ ] Verify valid approval for segment and time
- [ ] Automatic denial after expiry
- [ ] Audit all steps: request, approval, access, denial

**Database Models:**
```python
class Request(BaseModel):
    id: int
    user_id: int
    utility_id: int
    zip_code: str
    ticket_number: str  # UUID or sequential
    justification: str  # Free text
    status: str  # pending, approved, rejected, expired
    created_at: datetime

class Approval(BaseModel):
    id: int
    request_id: int
    approver_id: int
    approved_at: datetime
    expires_at: datetime  # approved_at + 30 min (or config)
```

---

## 7. Phase 4: Audit & Compliance (Week 3-4)

### Objectives
Implement audit trail, deletion functions, and verification tools.

### Tasks

#### 7.1 Audit Service (A5)
- [ ] Implement append-only audit log file
- [ ] Ensure file opened in append mode only
- [ ] Minimize personal data in logs
- [ ] Implement mandatory fields:
  - Sequential number
  - Timestamp
  - Utility company
  - Pseudonymous user identification
  - Role
  - Action
  - Minimized object identification
  - Result
  - Reason
  - Hash of previous entry
  - Own hash
- [ ] Exclude from logs:
  - Names
  - Plaintext load profiles
  - Free-text justifications
- [ ] Implement hash chain:
  - Each entry includes hash of previous entry
  - Calculate own hash for current entry
  - Use SHA-256 for hashing

**Audit Entry Structure:**
```json
{
  "seq": 1,
  "timestamp": "2026-11-05T10:00:00Z",
  "utility_id": "swn",
  "user_pseudo": "hmac_abc123",
  "role": "network_analyst",
  "action": "query_cohort",
  "object_id": "zip_74072",
  "result": "success",
  "reason": "n=5,k=3",
  "prev_hash": "a1b2c3...",
  "own_hash": "d4e5f6..."
}
```

#### 7.2 External Anchor (A5)
- [ ] Write hash of last entry to anchor file
- [ ] Store anchor file in separate directory
- [ ] Anchor directory should be outside application control
- [ ] Simulate WORM storage behavior

**Anchor Structure:**
```
audit/anchor.txt
# Contains only the hash of the last audit entry
d4e5f6...
```

#### 7.3 Verification Tool (A5)
- [ ] Create standalone script `scripts/verify_audit.py`
- [ ] NO login required (verification shouldn't append to log)
- [ ] Read audit trail file
- [ ] Verify hash chain integrity
- [ ] Compare last hash with anchor
- [ ] Detect and report:
  - Modified entry (hash mismatch)
  - Deleted entry (chain break with line number)
  - Truncated end (anchor mismatch)
- [ ] Provide clear error messages with locations

**Verification Logic:**
```python
def verify_audit_trail(log_path: str, anchor_path: str) -> VerificationResult:
    result = VerificationResult(ok=True, errors=[])
    
    # Read anchor hash
    with open(anchor_path) as f:
        expected_final_hash = f.read().strip()
    
    # Read and verify chain
    entries = read_log_entries(log_path)
    
    if not entries:
        result.ok = False
        result.errors.append("Empty audit log")
        return result
    
    prev_hash = None
    for i, entry in enumerate(entries):
        # Verify hash
        expected_hash = calculate_hash(entry, prev_hash)
        if entry.own_hash != expected_hash:
            result.ok = False
            result.errors.append(f"Line {i+1}: Hash mismatch")
        
        prev_hash = entry.own_hash
    
    # Check against anchor
    final_hash = entries[-1].own_hash
    if final_hash != expected_final_hash:
        result.ok = False
        result.errors.append("Anchor mismatch - possible truncation")
    
    return result
```

#### 7.4 Deletion Functions (A6)
- [ ] Implement configurable deletion cycle
- [ ] Support for:
  - Load profiles
  - Analysis exports
- [ ] Configurable retention periods
- [ ] Traceable start date for each data type
- [ ] Handle justified retention exceptions
- [ ] Backup restoration simulation:
  - Restore from backup
  - Reapply deletion cycle
  - Document event without rewriting deleted content
- [ ] Audit all deletion actions

**Deletion Configuration:**
```yaml
# config.yaml
retention:
  load_profiles:
    period_days: 365
    start_field: created_at
    exceptions:
      - legal_hold: true
  analysis_exports:
    period_days: 90
    start_field: created_at
```

#### 7.5 Data-Minimal Protocols (A8)
- [ ] Verify audit entries don't contain sensitive data
- [ ] Verify error messages don't contain sensitive data
- [ ] Test with:
  - Access denial scenarios
  - Deletion cycle execution
- [ ] Check for data leakage in:
  - Audit log messages
  - Error responses
  - Exception messages

---

## 8. Phase 5: Testing & Validation (Week 4)

### Objectives
Implement comprehensive test suite and validate all requirements.

### Tasks

#### 8.1 Test Infrastructure
- [ ] Set up pytest
- [ ] Create test fixtures for:
  - Database (PostgreSQL test container)
  - Test users
  - Test meter points
  - Test data
- [ ] Mock key service for tests
- [ ] Create test helper functions

#### 8.2 Unit Tests

**A1 - Identity, Session, Multi-Tenancy:**
- [ ] Test password hashing (bcrypt)
- [ ] Test constant-time comparison
- [ ] Test session creation and validation
- [ ] Test session expiry
- [ ] Test generic error messages for failed logins
- [ ] Test all 5 roles can be created
- [ ] Test 2 utilities with 6 users

**A2 - Encryption and Key Management:**
- [ ] Test AES-256-GCM encryption/decryption
- [ ] Test context binding with AAD
- [ ] Test integrity violation detection (T5)
- [ ] Test that wrong utility key fails to decrypt
- [ ] Test ciphertext swapping detection
- [ ] Bonus: Test two-level key concept
- [ ] Bonus: Test deletion via key destruction

**A3 - Gateway and Role Matrix:**
- [ ] Test check order enforcement
- [ ] Test each role's access patterns:
  - Customer: own meter only, all fields
  - Billing: own utility, masked load profile
  - Network Analyst: cohorts, pseudonymized exports
  - Fault Service: approved segments only
  - Control Center: requests only, no data
- [ ] Test small cell protection (n < k rejection)
- [ ] Test pseudonym generation and stability

**A4 - Fault Approval:**
- [ ] Test initial no access for fault service
- [ ] Test request creation
- [ ] Test approval by different person
- [ ] Test segment-specific access
- [ ] Test time-limited access
- [ ] Test automatic expiry
- [ ] Test self-approval prevention

**A5 - Audit Trail:**
- [ ] Test audit entry creation for all actions
- [ ] Test hash chain integrity
- [ ] Test anchor verification
- [ ] Test chain break detection (T6)
- [ ] Test truncation detection
- [ ] Test minimal personal data in logs

**A6 - Deletion:**
- [ ] Test configurable deletion cycle
- [ ] Test retention period enforcement
- [ ] Test exception handling
- [ ] Test backup restoration and reapplication
- [ ] Test audit documentation

**A7 - Rights and Roles:**
- [ ] Test role matrix enforcement
- [ ] Test analyst without individual value access
- [ ] Test technical support without read access
- [ ] Test permission revocation

**A8 - Data-Minimal Protocols:**
- [ ] Test audit entries for sensitive data
- [ ] Test error messages for sensitive data

#### 8.3 Integration Tests

**Test T1 - Login:**
- [ ] Login with wrong password → rejection without user existence hint
- [ ] Login with correct password → success with role and utility
- [ ] Verify both attempts in audit trail

**Test T2 - Billing Role:**
- [ ] (a) Billing requests own utility meter → sum and amount, masked load profile
- [ ] (b) Billing requests other utility meter → rejected
- [ ] (c) Billing attempts network analyst action → rejected

**Test T3 - Network Analyst:**
- [ ] Request cohort with n < 3 → rejected with n and k
- [ ] Request cohort with n >= 3 → hourly sum returned
- [ ] Export request → pseudonymized data only

**Test T4 - Fault Service:**
- [ ] Without approval → access denied
- [ ] Create request → request open
- [ ] Control center approves → approval granted
- [ ] Access in segment → value visible, name masked
- [ ] Access outside segment → denied
- [ ] Access after expiry → denied

**Test T5 - Integrity:**
- [ ] Swap ciphertexts of two hourly values in database
- [ ] Read as billing → integrity violation detected
- [ ] Verify audit entry created
- [ ] Explain why authenticated encryption alone doesn't detect this

**Test T6 - Audit Trail:**
- [ ] (a) Delete middle entry → chain break detected with line number
- [ ] (b) Truncate last entry → detection via anchor
- [ ] Explain why hash chain alone doesn't detect (b)

#### 8.4 Test Coverage
- [ ] Achieve > 90% code coverage
- [ ] Document test results
- [ ] Create test execution instructions for README

---

## 9. Phase 6: Documentation (Week 4-5)

### Objectives
Create all required documentation for submission.

### Tasks

#### 9.1 README.md
- [ ] Installation instructions
- [ ] Startup instructions
- [ ] Test user credentials
- [ ] Test reproduction commands
- [ ] Project structure overview
- [ ] Configuration options

#### 9.2 Part B Documentation

**B1 - Architecture Comparison:**
- [ ] Create comparison table: Klausur concept vs Implementation
- [ ] Include reflections on changes discovered during implementation
- [ ] Create decision table with rejected alternatives
- [ ] Append copy of graded M1 exam paper

**B2 - Protection Requirements:**
- [ ] Create CIA table for three data classes
- [ ] Document load profile vs monthly sum analysis
- [ ] Show re-identification example with concrete numbers
- [ ] Evaluate countermeasures against differential attacks

**B3 - Cloud Operation:**
- [ ] Create shared responsibility matrix
- [ ] Compare BYOK vs HYOK vs Cloud-native keys
- [ ] Evaluate public/private/hybrid deployment
- [ ] Explain audit trail protection in cloud

**B4 - Test Protocol:**
- [ ] Document all tests with console output
- [ ] Include corresponding audit entries
- [ ] Ensure reproducibility

**B5 - Legal Documentation:**
- [ ] Create purposes and legal bases table
- [ ] Analyze pseudonymized exports
- [ ] Create customer information text
- [ ] Create privacy notice PDF

**B6 - Compliance:**
- [ ] Create deletion concept table
- [ ] Document role implementation comparison
- [ ] Analyze data breach scenario

**B7 - International:**
- [ ] Evaluate EU hosting with US parent
- [ ] Analyze DPF certification implications
- [ ] Compare with Canada scenario

#### 9.3 KI Declaration
- [ ] Document all AI tools used
- [ ] Explain usage purpose
- [ ] List rejected suggestions
- [ ] Justify decisions

---

## 10. Phase 7: Finalization & Submission

### Tasks
- [ ] Final code review
- [ ] Security audit
- [ ] Performance testing
- [ ] Clean up temporary files
- [ ] Verify no secrets in source code
- [ ] Verify no sensitive data in git history
- [ ] Create final ZIP or ensure Git repository is clean
- [ ] Verify all tests pass
- [ ] Verify documentation is complete
- [ ] Create submission checklist

### Submission Checklist
- [ ] All source code
- [ ] README.md with installation and test instructions
- [ ] Test data generation script
- [ ] Verification script (verify_audit.py)
- [ ] All documentation (Part B)
- [ ] Copy of M1 exam paper
- [ ] KI declaration
- [ ] No keys or passwords in plaintext
- [ ] Proper module structure
- [ ] All tests documented and reproducible

---

## 11. Test Matrix

| Test ID | Description | Component | Status | Priority |
|---------|-------------|-----------|--------|----------|
| T1 | Login with wrong/correct password | A1 | Pending | High |
| T2a | Billing requests own utility meter | A3 | Pending | High |
| T2b | Billing requests other utility meter | A3 | Pending | High |
| T2c | Billing attempts network analyst action | A3 | Pending | High |
| T3a | Network analyst requests small cohort | A3 | Pending | High |
| T3b | Network analyst requests valid cohort | A3 | Pending | High |
| T4a | Fault service without approval | A4 | Pending | High |
| T4b | Fault service with approval | A4 | Pending | High |
| T4c | Fault service after expiry | A4 | Pending | High |
| T5 | Integrity violation detection | A2/A3 | Pending | High |
| T6a | Audit chain break detection | A5 | Pending | High |
| T6b | Audit truncation detection | A5 | Pending | High |
| Unit-A1-01 | Password hashing | A1 | Pending | Medium |
| Unit-A1-02 | Session validation | A1 | Pending | Medium |
| Unit-A2-01 | Encryption/decryption | A2 | Pending | Medium |
| Unit-A2-02 | Context binding | A2 | Pending | Medium |
| Unit-A3-01 | Gateway check order | A3 | Pending | Medium |
| Unit-A3-02 | Role transformations | A3 | Pending | Medium |
| Unit-A4-01 | Approval workflow | A4 | Pending | Medium |
| Unit-A5-01 | Audit logging | A5 | Pending | Medium |
| Unit-A5-02 | Hash chain | A5 | Pending | Medium |
| Integration-01 | End-to-end customer flow | All | Pending | Medium |
| Integration-02 | End-to-end billing flow | All | Pending | Medium |
| Integration-03 | Multi-tenancy isolation | All | Pending | High |

---

## 12. Architecture Decisions

### Decision 1: Technology Stack
**Decision:** FastAPI (Python) with PostgreSQL (Docker)  
**Rationale:**
- Python has excellent cryptography libraries (`cryptography`, `bcrypt`)
- FastAPI provides easy REST API development
- PostgreSQL provides better security, concurrency, and production-readiness
- Docker container ensures consistent environment
- All can run locally without external network dependencies (requirement)
- Good ecosystem for testing (pytest with test containers)

**Alternatives Considered:**
- Node.js + Express: Similar capabilities but less mature cryptography libraries
- Go: Excellent for security but more verbose for API development
- Java/Spring: Overkill for prototype, more setup required

### Decision 2: Context Binding Method
**Decision:** Option B - AES-GCM with Additional Authenticated Data (AAD)  
**Rationale:**
- More elegant than storing context in plaintext
- Provides cryptographic binding, not just logical
- Detects tampering and reordering attacks
- Built into AES-GCM, no additional processing needed
- Better performance (no JSON serialization/deserialization)

**Alternative:** Option A - Include context in plaintext JSON
- Simpler to implement
- But context is visible in ciphertext (though encrypted)
- Requires JSON parsing before decryption

### Decision 3: Session Management
**Decision:** JWT tokens with server-side session validation  
**Rationale:**
- Stateless tokens reduce server load
- Can still maintain server-side session for revocation
- JWT includes expiry by default
- Easy to include user ID, utility, role in token

**Alternative:** Server-side session storage only
- More control over session lifecycle
- But requires session store (PostgreSQL table or cache)

### Decision 4: Pseudonymization Method
**Decision:** HMAC-SHA256 with per-utility secret key  
**Rationale:**
- HMAC provides keyed hash, preventing rainbow table attacks
- Separate keys per utility prevent cross-utility de-pseudonymization
- Stable output (same input = same output)
- Not reversible without key
- Simple SHA-256 insufficient (vulnerable to precomputation)

### Decision 5: Audit Trail Storage
**Decision:** Append-only log file with hash chain  
**Rationale:**
- Simple to implement
- Tamper-evident (hash chain)
- External anchor provides additional protection
- Append-only mode prevents accidental overwrites
- Can be verified without application access

**Alternative:** Database table with hash chain
- More structured
- But requires database access for verification
- More complex to implement append-only behavior

### Decision 6: Key Storage
**Decision:** File-based keys in separate directory, outside code and DB  
**Rationale:**
- Simple for prototype
- Keys not in version control
- Can be placed on separate filesystem
- Easy to rotate (replace files)
- Simulates HSM/KMS for production

**Alternative:** Environment variables
- Also acceptable
- But harder to manage multiple keys (one per utility)
- Environment variables can be logged accidentally

---

## 13. Security Considerations

### Threat 1: Cloud Administrator
**Attack:** Read load profiles or delete audit entries undetected  
**Mitigation:**
- Main keys stored outside application (file system)
- Without keys, encrypted data is unreadable
- Audit trail hash chain with external anchor
- Cloud admin can't modify audit without breaking chain
- External anchor in separate location

**Residual Risk:**
- Cloud admin with key file access could read data
- Mitigation: In production, use HSM or KMS

### Threat 2: Database File Write Access
**Attack:** Modify, swap, or delete values  
**Mitigation:**
- Authenticated encryption (AES-GCM) with context binding
- Integrity check on every decryption
- Swapping ciphertexts detected (different AAD)
- Modification detected (authentication tag mismatch)

**Residual Risk:**
- Attacker could delete entire database
- Mitigation: Regular backups, but backups also encrypted

### Threat 3: Curious Network Analyst
**Attack:** Re-identify households via differential attacks  
**Mitigation:**
- Small cell protection: reject cohorts with n < k (k=3)
- Fixed cohorts (predefined ZIP code groups)
- Aggregated data only (sums, not individual values)
- Pseudonymization for exports

**Residual Risk:**
- If analyst can query overlapping cohorts, differential attack possible
- Mitigation: Fixed non-overlapping cohorts, query budget, noise

### Threat 4: Cross-Tenant Access
**Attack:** Employee of SWB accesses SWN data  
**Mitigation:**
- Utility company check in gateway
- Main keys are utility-specific
- Data encrypted with utility-specific key
- Session includes utility company
- All queries filtered by utility

**Residual Risk:**
- Bug in utility check could allow cross-tenant access
- Mitigation: Comprehensive testing, code reviews

### General Security Principles

1. **Defense in Depth:** Multiple layers of protection (encryption, access control, audit)
2. **Least Privilege:** Each role has minimum necessary access
3. **Separation of Duties:** Control center approves, fault service accesses
4. **Fail Secure:** Default to denial on any error
5. **Complete Mediation:** Every access goes through central gateway
6. **Audit Everything:** All actions logged with tamper-evidence
7. **Minimize Data:** Only necessary data exposed to each role
8. **No Plaintext Secrets:** Keys and passwords never in source code

---

## 14. Timeline & Milestones

### Week 1: Foundation
- [ ] Day 1-2: Project structure, data models, database
- [ ] Day 3-4: Authentication service (A1)
- [ ] Day 5-7: Key service and crypto service (A2)

**Deliverable:** Basic authentication and encryption working

### Week 2: Core Logic
- [ ] Day 8-10: Gateway service with role matrix (A3)
- [ ] Day 11-12: Fault approval workflow (A4)
- [ ] Day 13-14: Audit service and hash chain (A5)

**Deliverable:** Core business logic implemented

### Week 3: Compliance & Testing
- [ ] Day 15-17: Deletion functions (A6)
- [ ] Day 18-20: Rights and roles testing (A7, A8)
- [ ] Day 21: Verification tool and integration tests

**Deliverable:** All features implemented, tests passing

### Week 4: Validation & Documentation
- [ ] Day 22-24: Comprehensive testing and debugging
- [ ] Day 25-26: Written documentation (Part B)
- [ ] Day 27-28: Final review and polishing

**Deliverable:** Complete implementation with documentation

### Week 5: Buffer
- [ ] Final fixes based on testing
- [ ] Documentation review
- [ ] Submission preparation

**Deliverable:** Ready for submission

---

## 15. Dependencies & Resources

### Python Packages
```
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
python-multipart>=0.0.6
bcrypt>=4.1.1
cryptography>=41.0.7
python-jose[cryptography]>=3.3.0
pydantic>=2.5.0
pydantic-settings>=2.1.0
pytest>=7.4.0
pytest-cov>=4.1.0
psycopg2-binary>=2.9.9
```

### Development Tools
- Python 3.11+
- pip or uv for package management
- PostgreSQL (Docker) for database
- Git for version control

### Documentation Resources
- FastAPI documentation
- cryptography library documentation
- Python bcrypt documentation
- DHBW Data Security lecture materials
- GDPR documentation
- Cloud security best practices

---

## 16. Risk Assessment

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Complexity of encryption | Medium | High | Use well-tested libraries, write unit tests |
| Performance with many records | Low | Medium | Optimize queries, use indexing |
| Bug in gateway logic | Medium | High | Comprehensive testing, code reviews |
| Session management issues | Medium | Medium | Use established patterns, test thoroughly |

### Security Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Incomplete multi-tenancy isolation | Medium | Very High | Strict utility checks, separate keys |
| Audit trail tampering | Low | High | Hash chain, external anchor, verification tool |
| Data leakage in logs | Medium | High | Minimal logging, data-minimal protocols |
| Key compromise | Low | Very High | Secure key storage, separate keys per utility |

### Schedule Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Underestimated complexity | Medium | High | Break into small tasks, early prototyping |
| Integration issues | Medium | Medium | Test integration early and often |
| Documentation takes longer | Medium | Medium | Start documentation early, write as you code |

---

## Next Steps

1. **Immediate (Today):**
   - [ ] Review and approve this plan
   - [ ] Set up project structure as defined in Phase 1
   - [ ] Create GitHub/GitLab repository (if not using local only)

2. **This Week:**
   - [ ] Implement Phase 1: Project structure and data models
   - [ ] Implement Phase 2: Authentication and encryption
   - [ ] Begin Phase 3: Gateway logic

3. **Priority:**
   - Start with authentication (A1) as it's prerequisite for everything
   - Then encryption (A2) as it's needed for data storage
   - Then gateway (A3) as it orchestrates everything

---

**Document Version:** 1.0  
**Created:** 2026-11-05  
**Author:** Development Team  
**Status:** Draft - Awaiting Review

---

*Note: This plan is based on the GridVault requirements from BasisSzenario.md, M1-DONE.md, and M2-TODO.md. It should be reviewed and adjusted as implementation progresses.*
