INSERT INTO apps (id, name, secret)
VALUES (2, 'test', 'test-secret')
ON CONFLICT DO NOTHING;