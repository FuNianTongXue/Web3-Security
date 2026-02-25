package audit

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestRuleStoreToggleWithProjectScope(t *testing.T) {
	store := NewRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	rules, err := store.Load()
	if err != nil {
		t.Fatalf("load default rules failed: %v", err)
	}
	if len(rules) == 0 {
		t.Fatalf("expected default rules")
	}

	ruleID := rules[0].ID
	_, err = store.Toggle(ruleID, true, []string{"project-b", "project-a", "project-a"})
	if err != nil {
		t.Fatalf("toggle with scope failed: %v", err)
	}

	updated, err := store.Load()
	if err != nil {
		t.Fatalf("reload rules failed: %v", err)
	}
	var target Rule
	found := false
	for _, one := range updated {
		if one.ID == ruleID {
			target = one
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("rule not found after toggle: %s", ruleID)
	}
	if !target.Enabled {
		t.Fatalf("expected rule enabled after toggle")
	}
	wantScope := []string{"project-a", "project-b"}
	if !reflect.DeepEqual(target.ApplyProjects, wantScope) {
		t.Fatalf("scope mismatch: got=%v want=%v", target.ApplyProjects, wantScope)
	}

	_, err = store.Toggle(ruleID, false, nil)
	if err != nil {
		t.Fatalf("disable rule failed: %v", err)
	}
	disabled, err := store.Load()
	if err != nil {
		t.Fatalf("reload after disable failed: %v", err)
	}
	for _, one := range disabled {
		if one.ID == ruleID {
			if one.Enabled {
				t.Fatalf("expected rule disabled")
			}
			if !reflect.DeepEqual(one.ApplyProjects, wantScope) {
				t.Fatalf("scope should remain unchanged when disabling: got=%v want=%v", one.ApplyProjects, wantScope)
			}
			return
		}
	}
	t.Fatalf("rule not found after disable: %s", ruleID)
}
