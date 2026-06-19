"""Add PostgreSQL trigger that prevents UPDATE/DELETE on audit_auditevent.

The model docstring already advertises this guarantee (EVS-N02).
This migration creates the backing trigger so the claim is actually enforced.
"""

from django.db import migrations

_CREATE_SQL = """
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'audit_auditevent rows are immutable (EVS-N02)';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_immutable
BEFORE UPDATE OR DELETE ON audit_auditevent
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
"""

_DROP_SQL = """
DROP TRIGGER IF EXISTS audit_immutable ON audit_auditevent;
DROP FUNCTION IF EXISTS prevent_audit_mutation();
"""


class Migration(migrations.Migration):

    dependencies = [
        ("audit", "0001_initial"),
    ]

    operations = [
        migrations.RunSQL(sql=_CREATE_SQL, reverse_sql=_DROP_SQL),
    ]
