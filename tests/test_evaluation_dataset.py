from pathlib import Path

import yaml


def test_graylog_evaluation_dataset_is_valid():
    path = Path(__file__).parents[1] / "evals" / "graylog_questions.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    scenarios = data["scenarios"]
    assert len(scenarios) >= 4
    assert len({item["id"] for item in scenarios}) == len(scenarios)
    for item in scenarios:
        assert item["question"]
        assert item["preferred_tools"]
        assert item["required_evidence"]
