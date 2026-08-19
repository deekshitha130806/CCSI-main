from app import create_app
import io

app = create_app()
client = app.test_client()

# Login
r = client.post('/login', data={'username':'admin','password':'admin123','investigator_id':'CCSI-001'}, follow_redirects=True)
assert r.status_code == 200, f'login failed {r.status_code}'

# Protected route
r = client.get('/cases')
assert r.status_code == 200

# Create case
r = client.post('/cases/new', data={
    'case_id': 'CCSI-CASE-2026-9999',
    'case_title': 'Test Case Integration',
    'crime_type': 'Phishing',
    'case_date': '2026-07-09',
    'location': 'Test City',
    'description': 'Integration test case',
    'priority': 'Medium',
}, follow_redirects=True)
assert r.status_code == 200, 'case create failed'

# Upload evidence txt file
data = {
    'evidence_id': 'CCSI-EVD-999999',
    'case_id': 'CCSI-CASE-2026-9999',
    'evidence_type': 'Documents',
    'notes': 'test',
}
data['evidence_file'] = (io.BytesIO(b'hello forensic test'), 'test_evidence.txt')
r = client.post('/evidence/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
assert r.status_code == 200, f'evidence upload failed {r.status_code}'

# Verify integrity
r = client.post('/evidence/CCSI-EVD-999999/verify', follow_redirects=True)
assert r.status_code == 200

# Analysis
r = client.post('/analysis/CCSI-EVD-999999/run', follow_redirects=True)
assert r.status_code == 200

# Reports generate (case_id must be in the URL path — one report per case)
r = client.post('/reports/generate/CCSI-CASE-2026-9999', follow_redirects=True)
assert r.status_code == 200

# Custody page
r = client.get('/custody')
assert r.status_code == 200

print('ALL INTEGRATION TESTS PASSED')
