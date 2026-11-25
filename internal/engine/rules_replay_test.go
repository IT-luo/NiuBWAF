package engine

import (
	"fmt"
	"testing"
)

func TestMatchReplayThreeValuedTruthTables(t *testing.T) {
	conditions := map[MatchState]string{
		MatchTrue:    `{"field":"method","op":"eq","value":"GET"}`,
		MatchFalse:   `{"field":"method","op":"eq","value":"POST"}`,
		MatchUnknown: `{"field":"header","op":"eq","name":"X-Replay","value":"yes"}`,
	}
	states := []MatchState{MatchFalse, MatchUnknown, MatchTrue}
	for _, left := range states {
		for _, right := range states {
			and, or := MatchTrue, MatchFalse
			switch {
			case left == MatchFalse || right == MatchFalse:
				and = MatchFalse
			case left == MatchUnknown || right == MatchUnknown:
				and = MatchUnknown
			}
			switch {
			case left == MatchTrue || right == MatchTrue:
				or = MatchTrue
			case left == MatchUnknown || right == MatchUnknown:
				or = MatchUnknown
			}

			for _, logic := range []string{"and", "or"} {
				raw := fmt.Sprintf(`[%s,%s]`, conditions[left], conditions[right])
				cr, err := CompileRule(RuleDef{Logic: logic, Conditions: raw, Action: "block", Shadow: true})
				if err != nil {
					t.Fatal(err)
				}
				if !cr.Shadow {
					t.Fatal("RuleDef.Shadow 应传递到 CompiledRule")
				}
				got := cr.MatchReplay(input("192.0.2.1", "GET", "/", "/", "", nil, nil))
				want := and
				if logic == "or" {
					want = or
				}
				if got != want {
					t.Errorf("%s (%v,%v) = %v, 期望 %v", logic, left, right, got, want)
				}
			}
		}
	}

	// 实时 Match 仍是布尔接口：无法取得的 header 按原逻辑得到空值并返回 false。
	headerOnly, err := CompileRule(RuleDef{Logic: "and", Conditions: `[` + conditions[MatchUnknown] + `]`, Action: "log"})
	if err != nil {
		t.Fatal(err)
	}
	in := input("192.0.2.1", "GET", "/", "/", "", nil, nil)
	if headerOnly.Match(in) {
		t.Fatal("实时布尔 Match 语义不应被回放三值逻辑改变")
	}
	if got := headerOnly.MatchReplay(in); got != MatchUnknown {
		t.Fatalf("缺失 header 的回放结果应为 unknown, got %v", got)
	}
}
