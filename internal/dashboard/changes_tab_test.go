package dashboard

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// changesBlock returns the Changes tab's script (changes:begin .. changes:end).
func changesBlock(t *testing.T, html string) string {
	t.Helper()
	a, b := strings.Index(html, "/* changes:begin */"), strings.Index(html, "/* changes:end */")
	if a < 0 || b < a {
		t.Fatal("index.html has no changes:begin/changes:end script block")
	}
	return html[a:b]
}

// stubChanges is a ChangeDrafts that only has to exist: the setup response
// looks at whether the seam is set, not at what it serves.
type stubChanges struct{ ChangeDrafts }

// TestChangesTabSetup: approvalsEnabled is true only when the ChangeDrafts seam
// is set, and always present; the replay timeout is reported only then.
func TestChangesTabSetup(t *testing.T) {
	for _, c := range []struct {
		name    string
		seam    ChangeDrafts
		timeout time.Duration
		want    bool
		wantSec int
	}{
		{"approvals off (P1 behaviour)", nil, 0, false, 0},
		{"approvals off ignores a timeout", nil, time.Minute, false, 0},
		{"approvals on", stubChanges{}, 90 * time.Second, true, 90},
		{"approvals on, timeout not told", stubChanges{}, 0, true, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
			if c.seam != nil {
				srv.SetChangeDrafts(c.seam)
			}
			srv.SetApprovalsReplayTimeout(c.timeout)
			rr := doGet(t, srv.Handler(), "/dashboard/api/setup")
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if string(raw["approvalsEnabled"]) != map[bool]string{true: "true", false: "false"}[c.want] {
				t.Errorf("approvalsEnabled = %s, want %v (body %s)", raw["approvalsEnabled"], c.want, rr.Body.String())
			}
			got := getSetup(t, srv)
			if got.ApprovalsEnabled != c.want || got.ApprovalsReplayTimeoutSec != c.wantSec {
				t.Errorf("setup = {enabled %v, timeout %ds}, want {%v, %ds}", got.ApprovalsEnabled, got.ApprovalsReplayTimeoutSec, c.want, c.wantSec)
			}
		})
	}
}

// TestChangesTab pins the Changes tab: hidden until setup says approvalsEnabled
// (so a P1 console is unchanged), the container and list, the API it calls, the
// PVER-04 renderer for the diff, the approve body, the acknowledge rule, the
// replay poll, and the role gating of every control.
func TestChangesTab(t *testing.T) {
	html := servedIndex(t)
	for _, want := range []string{
		`id="changesNav" style="display:none"`,
		`id="page-changes"`,
		`id="ch-list"`,
		`id="ch-detail"`,
		`id="ch-more"`,
		`cn.style.display=s.approvalsEnabled===true?'':'none'`,
		`case 'changes':     loadChanges(); break;`,
		`id="held-notice"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	js := changesBlock(t, html)
	for _, want := range []string{
		`const CH_BASE='/dashboard/api/changes';`,
		`api('GET',CH_BASE+'?'+q.toString())`,
		`q.set('cursor',ch.next)`,
		`d.next_cursor`,
		`api('GET',CH_BASE+'/'+encodeURIComponent(id)+p)`,
		`get('/diff')`,
		// The diff is the server's; the PVER-04 renderer draws it.
		`phChangeList('Allowlist',allow,c=>c.key)`,
		`phChangeList('Denylist',deny,c=>c.key)`,
		`phChangeList('Settings',settings,c=>c.path)`,
		// Approve names the revision, the doc digest and the replay it saw.
		`{revision:d.revision,doc_sha256:d.doc_sha256,replay_id:usable?rp.id:'',acknowledgeNoReplay:!usable,comment:ch.ui.comment}`,
		`const usable=d.target==='policy'&&!!rp&&rp.status==='done';`,
		`if(!usable&&!(ack&&ack.checked))`,
		`rp.status==='failed'||rp.status==='unavailable'`,
		// Transitions carry the revision they saw.
		`{'If-Match':'"r'+d.revision+'"'}`,
		`/approve'`, `/reject'`, `/replay'`, `/emergency-apply'`, `/review'`,
		// The replay poll: every 2s, up to the server's replayTimeout, then re-run.
		`const CH_POLL_MS=2000;`,
		`setupData.approvalsReplayTimeoutSec`,
		`Date.now()-start>=ch.replayMs`,
		`'Re-run replay'`,
		// Closed gates: the author and a break-glass session never approve.
		`d.author.sub===me.sub`,
		`me.authMethod==='breakglass'`,
		`!chIsAuthor(d)&&!chBreakGlass()&&roleAllows(chReqRole(d))`,
		// The states with their own action or read-only badge.
		`st==='needs_rebase'`, `st==='applied_unreviewed'`, `and read only.`,
		`This draft cannot be rebased: withdraw it and make the change again.`,
		// What the replay does not cover is said on the page.
		`compares allow and deny decisions only`,
		`Truncated: the event cap was reached`,
		`['Destination','Method','Events','Affected users','To judge','Rate-limited']`,
		`res.changed_to_allow`, `res.changed_to_deny`, `g.affected_users_total`,
		`rp.window_from`, `rp.window_to`,
		// The entity shapes of the other targets.
		`['id','display_name','status','sub','email','has_sub','has_email']`,
		`df.diff.current`, `df.diff.proposed`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("changes script lacks %q", want)
		}
	}
	// Every write control names the role that sees it.
	for _, want := range []string{
		`chBtn('Approve','primary','editor'`,
		`chBtn('Reject','','editor'`,
		`chBtn('Submit for review','primary','editor'`,
		`chBtn('Rebase onto the head','primary','editor'`,
		`chBtn('Emergency apply','','admin'`,
		`chBtn('Mark reviewed','primary','admin'`,
		`b.setAttribute('data-min-role',minRole)`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("changes script lacks %q", want)
		}
	}
	// Every request goes through api() (CSRF header, bearer fallback).
	for _, bad := range []string{"fetch(", "XMLHttpRequest", "sendBeacon"} {
		if strings.Contains(js, bad) {
			t.Errorf("changes script uses %q; writes go through api()", bad)
		}
	}
	if n := strings.Count(js, "api('POST'"); n < 6 {
		t.Errorf("changes script has %d api('POST' calls, want the transition, replay, approve, reject, emergency and review", n)
	}
}

// TestChangesTabTextContent: every server or person supplied string (author,
// message, comment, domain, user, reason, block and agent fields) reaches the
// DOM through textContent, never as markup, and the key material of an agent is
// never read. The rule covers the held notice and the 202 link too.
func TestChangesTabTextContent(t *testing.T) {
	html := servedIndex(t)
	js := changesBlock(t, html)
	for _, bad := range []string{
		"innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "createContextualFragment", "DOMParser",
		"eval(", "new Function", ".jwk", "jwk",
	} {
		if strings.Contains(js, bad) {
			t.Errorf("changes script uses %q", bad)
		}
	}
	if !strings.Contains(js, "if(text!=null) e.textContent=String(text);") {
		t.Error("chEl must set text with textContent")
	}
	// The only attribute built from a server value is the draft link, and its id is
	// checked against the draft id pattern first.
	if !strings.Contains(js, "const CH_ID=/^[A-Za-z0-9_-]{1,64}$/;") ||
		!strings.Contains(js, "CH_ID.test(b.draft_id)?b.draft_id:''") ||
		!strings.Contains(js, "a.setAttribute('href','#changes/'+id)") {
		t.Error("the draft link must be built only from an id that passed CH_ID")
	}
	for _, line := range strings.Split(js, "\n") {
		if strings.Contains(line, "setAttribute(") && !strings.Contains(line, "'href'") && !strings.Contains(line, "'data-min-role'") {
			t.Errorf("an attribute is set from a value: %.120s", strings.TrimSpace(line))
		}
	}
	// Text-bearing fields go through chEl or phEl (textContent), by name.
	for _, want := range []string{
		`chEl('td',chWho(x.author))`,
		`chEl('div',d.message,'ch-message')`,
		`chEl('div',a.comment,'muted')`,
		`chEl('td',String(g.domain||'')+(g.port?':'+g.port:''),'mono')`,
		`chEl('td',users.join(', ')+(more>0?' and '+more+' more':''))`,
		`chEl('div',x.detail,'muted')`,
		`chEl('span',x.code,'pill p-high')`,
		`chEl('span',' '+chWho(a.approver)`,
		`chFact(k,typeof obj[k]==='boolean'?String(obj[k]):obj[k])`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("changes script lacks %q", want)
		}
	}
	// Rows key on the draft's target: a blocked_users or agents draft is not
	// rendered as a policy diff, and the non-admin block shape ({id, has_sub,
	// has_email}) renders as the booleans it is.
	if !strings.Contains(js, `if(d.target==='policy'){`) || !strings.Contains(js, `chEl('b',x.target)`) {
		t.Error("the detail and the list must key on the draft's target")
	}
	for _, want := range []string{
		`if(obj==null){ wrap.appendChild(chEl('div',emptyText,'note')); return wrap; }`,
		`cur.appendChild(chShape(df.diff.current,'none (a new entry)'))`,
		`d.target==='blocked_users'?'removes this entry':'none'`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("changes script lacks %q (a null current is a new entry, a null proposed block is a removal)", want)
		}
	}
	// Nothing else in the page assigns held-save text as markup either.
	for _, line := range strings.Split(html, "\n") {
		if strings.Contains(line, "noteHeldResponse") && strings.Contains(line, "innerHTML") {
			t.Errorf("a held-save handler builds markup: %.120s", strings.TrimSpace(line))
		}
	}
}

// TestPolicySaveDraft: a save that the server holds (202) is shown as
// submitted for review with a link to the draft and is never reported as
// saved, in the policy, settings and llmProviders flows and in the agents and
// block list flows that share the notice.
func TestPolicySaveDraft(t *testing.T) {
	html := servedIndex(t)
	i := strings.Index(html, "async function policyWrite(")
	if i < 0 {
		t.Fatal("no policyWrite")
	}
	pw := html[i : i+strings.Index(html[i:], "\n}\n")]
	held := strings.Index(pw, "if(r.status===202){")
	ok := strings.Index(pw, "if(r.ok) loadPolicyHistory(true);")
	if held < 0 || ok < 0 || held > ok {
		t.Fatalf("policyWrite must handle 202 before it treats the response as a save:\n%s", pw)
	}
	for _, want := range []string{"await noteHeldResponse(r);", "new Error('submitted for review')", "e.held=true; throw e;"} {
		if !strings.Contains(pw, want) {
			t.Errorf("policyWrite lacks %q", want)
		}
	}
	js := changesBlock(t, html)
	for _, want := range []string{
		`'Submitted for review: the change is not saved until a second person approves it. '`,
		`'Open draft '+id`,
		`a.setAttribute('href','#changes/'+id)`,
		`function heldText(err){ return err&&err.held?err.message:'✕ '+(err&&err.message); }`,
		`window.addEventListener('hashchange',()=>{ if(setupData&&setupData.approvalsEnabled===true) applyChangesHash(); })`,
		`if(h.indexOf('#changes/')!==0) return;`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("changes script lacks %q", want)
		}
	}
	// Each save flow's failure path says submitted for review (heldText) or stays
	// quiet when held; none of them reaches its success text for a held save,
	// because policyWrite threw.
	for _, want := range []string{
		`if(!err.held) window.alert('Mode switch failed: '+err.message);`,
		`note.textContent=heldText(err);`,
		`if(!err.cancelled&&!err.held) window.alert('Policy save failed: '+err.message);`,
		`msg.textContent=heldText(err);`,
		`if(!err.held) window.alert('MCP save failed: '+err.message);`,
		`if(!err.held) window.alert('Judge save failed: '+err.message);`,
		`llmpMsg(heldText(err),false);`,
		`st.textContent=heldText(err);`,
		// agents and the block list
		`if(r&&r.status===202){ agHideForm(); await noteHeldResponse(r);`,
		`if(r&&r.status===202){ await noteHeldResponse(r); agMsg(verb+' of `,
		`if(r&&r.status===202){ await noteHeldResponse(r); buMsg('Unblock submitted for review`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	// A widening rollback is held too: the 202 is handled before the ok check and
	// shows the notice with the draft link, never "rolled back".
	i = strings.Index(html, "async function rollbackTo(")
	if i < 0 {
		t.Fatal("no rollbackTo")
	}
	rb := html[i : i+strings.Index(html[i:], "\n}\n")]
	held = strings.Index(rb, "if(r.status===202){")
	ok = strings.Index(rb, "if(!r.ok){")
	if held < 0 || ok < 0 || held > ok || strings.Index(rb, "rolled back: head is now") < held {
		t.Errorf("rollbackTo must handle 202 before the ok check and the rolled back text:\n%s", rb)
	}
	for _, want := range []string{"const id=noteHeld(b);", "Rollback submitted for review: v'+v+' is not live until it is approved."} {
		if !strings.Contains(rb, want) {
			t.Errorf("rollbackTo lacks %q", want)
		}
	}
	if !strings.Contains(html, "function noteHeld(b){") || !strings.Contains(html, "return noteHeld(b);") {
		t.Error("noteHeldResponse must share noteHeld with callers that already read the body")
	}
	// A held save is never followed by a saved message on the same path: the
	// 202 branches above return before 'Saved'/'saved'.
	if strings.Contains(pw, "saved") || strings.Contains(pw, "Saved") {
		t.Error("policyWrite must not report a save itself")
	}
}

// TestChangesTabReviewFixes pins the review fixes: a policy draft with no replay
// asks for the replay (the server answers replay_required) instead of offering
// the acknowledgement, the replay poll stops off the tab, and the hash handler
// only runs when approvals are enabled.
func TestChangesTabReviewFixes(t *testing.T) {
	html := servedIndex(t)
	js := changesBlock(t, html)
	for _, want := range []string{
		`const needReplay=d.target==='policy'&&!rp;`,
		`const needAck=d.target!=='policy'||(!!rp&&(rp.status==='failed'||rp.status==='unavailable'));`,
		`Run replay first: a policy change is approved against a replay of recent traffic.`,
		`if(!needReplay) acts.appendChild(chBtn('Approve'`,
		`if(d.target==='policy'&&!rp){ chMsg('Run replay first.'); return; }`,
		`if(currentTab()!=='changes'){ chStopPoll(); return; }`,
		`if(setupData&&setupData.approvalsEnabled===true) applyChangesHash();`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("changes script lacks %q", want)
		}
	}
	if !strings.Contains(html, "function loadTab(page){\n  if(page!=='changes'&&typeof chStopPoll==='function') chStopPoll();") {
		t.Error("loadTab must stop the replay poll when another page loads")
	}
	if !strings.Contains(html, "llmpMsg(heldText(err),false);") {
		t.Error("a held llmProviders save must show in the warning style, not the success style")
	}
}
