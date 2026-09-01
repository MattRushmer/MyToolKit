from __future__ import annotations

from tests.conftest import make_source
from vibecheck.models import Language
from vibecheck.rules.catalog import VIBE_SEC_SQL_INJECTION
from vibecheck.rules.injection import check_injection


def test_flags_fstring_query_inline():
    source = make_source('cursor.execute(f"SELECT * FROM t WHERE id={user_id}")\n')
    findings = check_injection(source)
    assert any(f.rule_id == VIBE_SEC_SQL_INJECTION for f in findings)


def test_flags_query_built_in_variable_then_executed():
    source = make_source('query = f"SELECT * FROM t WHERE id={user_id}"\ncursor.execute(query)\n')
    findings = check_injection(source)
    assert any(f.rule_id == VIBE_SEC_SQL_INJECTION for f in findings)


def test_flags_string_concatenation():
    source = make_source('cursor.execute("SELECT * FROM t WHERE id=" + user_id)\n')
    findings = check_injection(source)
    assert any(f.rule_id == VIBE_SEC_SQL_INJECTION for f in findings)


def test_flags_percent_formatting():
    source = make_source('cursor.execute("SELECT * FROM t WHERE id=%s" % user_id)\n')
    findings = check_injection(source)
    assert any(f.rule_id == VIBE_SEC_SQL_INJECTION for f in findings)


def test_flags_dot_format():
    source = make_source('cursor.execute("SELECT * FROM t WHERE id={}".format(user_id))\n')
    findings = check_injection(source)
    assert any(f.rule_id == VIBE_SEC_SQL_INJECTION for f in findings)


def test_does_not_flag_parameterized_query():
    source = make_source('cursor.execute("SELECT * FROM t WHERE id=%s", (user_id,))\n')
    findings = check_injection(source)
    assert findings == []


def test_does_not_flag_static_query_no_params():
    source = make_source('cursor.execute("SELECT * FROM t")\n')
    findings = check_injection(source)
    assert findings == []


def test_flags_js_template_literal_in_query_call():
    source = make_source("db.query(`SELECT * FROM t WHERE id=${userId}`);\n", rel_path="test.js", language=Language.JAVASCRIPT)
    findings = check_injection(source)
    assert any(f.rule_id == VIBE_SEC_SQL_INJECTION for f in findings)


def test_does_not_flag_js_parameterized_query():
    source = make_source('db.query("SELECT * FROM t WHERE id = ?", [userId]);\n', rel_path="test.js", language=Language.JAVASCRIPT)
    findings = check_injection(source)
    assert findings == []
