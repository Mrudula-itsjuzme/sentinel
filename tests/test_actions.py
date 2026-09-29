import pytest

from sentinel.domain.actions import INTERVENTIONS, ActionType, Intervention, apply_intervention
from sentinel.scenarios.lateral_movement import build_world


@pytest.mark.parametrize("intervention", INTERVENTIONS)
def test_action_does_not_change_original(intervention) -> None:
    original = build_world()
    snapshot = original.model_dump(mode="json")
    changed = original.clone()
    apply_intervention(changed, intervention)
    assert original.model_dump(mode="json") == snapshot


def test_isolate_changes_only_target_host() -> None:
    initial = build_world()
    changed = initial.clone()
    apply_intervention(changed, INTERVENTIONS[0])
    assert changed.hosts["workstation_a"].isolated
    assert {key: value for key, value in changed.hosts.items() if key != "workstation_a"} == {
        key: value for key, value in initial.hosts.items() if key != "workstation_a"
    }


def test_block_smb_adds_deny_rule() -> None:
    changed = build_world()
    apply_intervention(changed, INTERVENTIONS[1])
    assert changed.firewall_rules["response_block_smb"].allow is False


def test_disable_changes_only_target_account() -> None:
    changed = build_world()
    apply_intervention(changed, INTERVENTIONS[2])
    assert not changed.users["alice"].enabled
    assert changed.users["payroll_service"].enabled
    assert INTERVENTIONS[2].action is ActionType.DISABLE_ACCOUNT


def test_revoke_session_has_deterministic_state_semantics() -> None:
    changed=build_world()
    apply_intervention(changed,Intervention(action=ActionType.REVOKE_SESSION,target="alice"))
    assert changed.revoked_session_accounts=={"alice"}
    assert changed.users["alice"].enabled


def test_targeted_restriction_changes_only_named_connection_availability() -> None:
    changed=build_world()
    apply_intervention(changed,Intervention(action=ActionType.RESTRICT_CONNECTION,target="workstation_internal_smb"))
    assert changed.restricted_connection_ids=={"workstation_internal_smb"}
