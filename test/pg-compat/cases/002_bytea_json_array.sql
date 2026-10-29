-- transactional: false
SELECT '\xdeadbeef'::bytea, '{"a":1}'::jsonb, ARRAY[1,2,3]::int4[], '192.168.0.1'::inet, '00000000-0000-0000-0000-000000000001'::uuid;
