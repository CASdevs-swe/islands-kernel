from capture_bridge.classify import classify

ALLOWED = ["work-task", "personal-task", "meal", "goal", "event", "team-knowledge", "private-journal"]


def test_returns_the_type_the_cli_emits_when_in_the_allowed_set():
    out = classify("kom ihag att kopa mjolk", ALLOWED, "claude",
                   runner=lambda b, p: "personal-task\n")
    assert out == "personal-task"


def test_falls_back_to_unclassifiable_when_cli_output_not_in_set():
    out = classify("???", ALLOWED, "claude", runner=lambda b, p: "banana")
    assert out == "unclassifiable"


def test_falls_back_to_unclassifiable_when_runner_raises():
    def boom(b, p):
        raise RuntimeError("cli down")
    assert classify("x", ALLOWED, "claude", runner=boom) == "unclassifiable"


def test_prompt_contains_the_allowed_types():
    seen = {}
    def capture(b, p):
        seen["prompt"] = p
        return "meal"
    classify("jag at lunch", ALLOWED, "claude", runner=capture)
    for t in ALLOWED:
        assert t in seen["prompt"]
