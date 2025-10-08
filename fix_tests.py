#!/usr/bin/env python3
"""Fix scoring tests to use valid schemas."""

import re

# Read the test file
with open('tests/test_scoring.py', 'r') as f:
    content = f.read()

# Define the replacement patterns
replacements = [
    # Fix CloudTrailEvent creations
    (
        r'CloudTrailEvent\(\s*eventTime=([^,]+),\s*eventName=([^,]+),\s*userIdentity=CloudTrailUserIdentity\(\s*type=([^,]+),\s*principalId=([^,]+),\s*arn=([^,]+),\s*accountId=([^,]+),\s*userName=([^)]+)\s*\),\s*awsRegion=([^,]+),\s*sourceIPAddress=([^,]+),\s*userAgent=([^,]+),\s*requestParameters=([^,]+),\s*responseElements=([^)]+)\s*\)',
        r'create_test_cloudtrail_event(event_name=\2, event_time=\1, source_ip=\9, aws_region=\8)'
    ),
    
    # Fix simpler CloudTrailEvent patterns
    (
        r'CloudTrailEvent\(\s*eventTime=([^,]+),\s*eventName=([^,]+),\s*([^)]+)\)',
        r'create_test_cloudtrail_event(event_name=\2, event_time=\1)'
    ),
    
    # Fix ExtractedEntity with wrong types
    (
        r'ExtractedEntity\(\s*entity_id=([^,]+),\s*entity_type="USER",\s*context=([^,]+),\s*confidence=([^)]+)\)',
        r'create_test_extracted_entity(entity_id=\1, entity_type=EntityType.IAM_USER_ARN, confidence=\3, context="user context", source_field="userIdentity")'
    ),
    
    (
        r'ExtractedEntity\(\s*entity_id=([^,]+),\s*entity_type="IP",\s*context=([^,]+),\s*confidence=([^)]+)\)',
        r'create_test_extracted_entity(entity_id=\1, entity_type=EntityType.IP_ADDRESS, confidence=\3, context="IP context", source_field="sourceIPAddress")'
    ),
    
    (
        r'ExtractedEntity\(\s*entity_id=([^,]+),\s*entity_type="ROLE",\s*context=([^,]+),\s*confidence=([^)]+)\)',
        r'create_test_extracted_entity(entity_id=\1, entity_type=EntityType.IAM_ROLE_ARN, confidence=\3, context="role context", source_field="userIdentity")'
    ),
    
    # Fix simple ExtractedEntity patterns
    (
        r'ExtractedEntity\(entity_id=([^,]+), entity_type="USER", context=\{\}, confidence=([^)]+)\)',
        r'create_test_extracted_entity(entity_id=\1, entity_type=EntityType.IAM_USER_ARN, confidence=\2, context="user context", source_field="userIdentity")'
    ),
    
    (
        r'ExtractedEntity\(entity_id=([^,]+), entity_type="IP", context=\{\}, confidence=([^)]+)\)',
        r'create_test_extracted_entity(entity_id=\1, entity_type=EntityType.IP_ADDRESS, confidence=\2, context="IP context", source_field="sourceIPAddress")'
    ),
    
    (
        r'ExtractedEntity\(entity_id=([^,]+), entity_type="ROLE", context=\{\}, confidence=([^)]+)\)',
        r'create_test_extracted_entity(entity_id=\1, entity_type=EntityType.IAM_ROLE_ARN, confidence=\2, context="role context", source_field="userIdentity")'
    ),
]

# Apply replacements
for pattern, replacement in replacements:
    content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

# Write back the fixed content
with open('tests/test_scoring.py', 'w') as f:
    f.write(content)

print("Fixed test file!")