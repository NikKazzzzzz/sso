INSERT INTO apps (name, secret)
VALUES ('url-shortener', 'shortener')
ON CONFLICT DO NOTHING;