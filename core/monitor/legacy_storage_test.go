package monitor

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io/fs"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/web"
)

func TestLegacyStorageIdentityValidation(t *testing.T) {
	for _, value := range []string{"../other", ".", "..", "invalid space", "bad\nvalue", "bad<script>"} {
		if ValidateMonitorIdentity(&MonitorIdentityConfig{LegacyStorageNamespace: value}) == nil {
			t.Errorf("accepted invalid legacy namespace %q", value)
		}
	}
	for _, value := range []string{"", "previous-app", "previous.v1", "previous_app"} {
		cfg, err := resolvedMonitorIdentity(&MonitorIdentityConfig{LegacyStorageNamespace: value})
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var decoded MonitorIdentityConfig
		if err := json.Unmarshal(wire, &decoded); err != nil || decoded.LegacyStorageNamespace != value {
			t.Fatal("legacy identity did not survive JSON")
		}
	}
	cfg, err := resolvedMonitorIdentity(nil)
	if err != nil || cfg.LegacyStorageNamespace != "" {
		t.Fatal("default must not enable migration")
	}
}

func TestLegacyStoragePreferenceMigration(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for synthetic storage validation")
	}
	source, err := fs.ReadFile(web.Templates(), "layout.html")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)<script>\s*(.*?)</script>`).Find(source)
	if len(block) == 0 {
		t.Fatal("layout identity script missing")
	}
	tmpl, err := template.New("identity").Parse(string(block))
	if err != nil {
		t.Fatal(err)
	}
	render := func(legacy string) string {
		t.Helper()
		identity, err := resolvedMonitorIdentity(&MonitorIdentityConfig{StorageNamespace: "current", LegacyStorageNamespace: legacy})
		if err != nil {
			t.Fatal(err)
		}
		page := PageData{Identity: identity, AppBase: "/example", Cards: map[string]template.HTML{}, CardAliases: map[string]string{"old-card": "new-card"}}
		var body bytes.Buffer
		if err := tmpl.Execute(&body, page); err != nil {
			t.Fatal(err)
		}
		return strings.TrimSuffix(strings.TrimPrefix(body.String(), "<script>"), "</script>")
	}
	shared, err := fs.ReadFile(web.Static(), "js/shared.js")
	if err != nil {
		t.Fatal(err)
	}
	functions := ""
	for _, name := range []string{"configuredCardId", "loadCollapsedSet", "loadSidenavServerTreeOpen", "loadSidenavOrder"} {
		helper := regexp.MustCompile(`(?s)function ` + name + `\([^)]*\) \{.*?\n\}`).Find(shared)
		if len(helper) == 0 {
			t.Fatalf("missing helper %s", name)
		}
		functions += string(helper) + "\n"
	}
	payload, _ := json.Marshal(map[string]string{"script": render("previous"), "defaultScript": render(""), "functions": functions})
	program := `
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const payload=JSON.parse(fs.readFileSync(0,'utf8'));
const suffixes=['.monitor.collapsed.v1','.monitor.sidenav.server_tree.v1','.monitor.sidenav.order.v1'];
const old={};old['previous'+suffixes[0]]='["old-card"]';old['previous'+suffixes[1]]='0';old['previous'+suffixes[2]]='{"pinned":["old-card"],"groups":{"Example":["unrelated-card"]}}';
function run(initial,options={}) {
 const data={...initial};let writes=0,reads=0;
 const c={localStorage:{getItem(k){reads++;if(options.readError)throw Error('unavailable');return Object.hasOwn(data,k)?data[k]:null},setItem(k,v){if(options.writeError)throw Error('unavailable');writes++;data[k]=v},removeItem(){throw Error('migration must never delete legacy preferences')}}};
 vm.createContext(c);vm.runInContext(options.disabled?payload.defaultScript:payload.script,c);
 c.COLLAPSE_KEY=c.HD_COLLAPSE_KEY;c.SIDENAV_SERVER_TREE_KEY=c.HD_SIDENAV_SERVER_TREE_KEY;c.SIDENAV_ORDER_KEY=c.HD_SIDENAV_ORDER_KEY;vm.runInContext(payload.functions,c);
 const before=JSON.stringify(data),beforeWrites=writes;
 const collapsed=c.loadCollapsedSet(),tree=c.loadSidenavServerTreeOpen(),order=c.loadSidenavOrder();
 assert.strictEqual(JSON.stringify(data),before,'preference loads must stay read-only');assert.strictEqual(writes,beforeWrites);
 return {data,writes,reads,collapsed,tree,order};
}
const migrated=run(old);assert.strictEqual(migrated.writes,3);
suffixes.forEach(s=>{assert.strictEqual(migrated.data['current'+s],old['previous'+s]);assert.strictEqual(migrated.data['previous'+s],old['previous'+s])});
assert.strictEqual(migrated.collapsed['new-card'],true);assert.strictEqual(migrated.tree,false);assert.deepStrictEqual(JSON.parse(JSON.stringify(migrated.order)),{pinned:['new-card'],groups:{Example:['unrelated-card']}});
assert.strictEqual(run(migrated.data).writes,0,'reload must not repeat migration');
const current={};suffixes.forEach(s=>current['current'+s]='');
assert.strictEqual(run({...old,...current}).writes,0,'even empty current keys must win');
const newOnly=run({['current'+suffixes[0]]:'[]'});assert.strictEqual(newOnly.writes,0);
assert.strictEqual(run({}).writes,0);assert.strictEqual(run(old,{disabled:true}).writes,0);
assert.strictEqual(run(old,{readError:true}).writes,0);assert.strictEqual(run(old,{writeError:true}).writes,0);
for(const bad of ['not-json','null','{}','[7]','[""]'])assert.strictEqual(run({['previous'+suffixes[0]]:bad}).writes,0);
for(const bad of ['true','false','2',' 1'])assert.strictEqual(run({['previous'+suffixes[1]]:bad}).writes,0);
for(const bad of ['not-json','null','[]','{"pinned":[],"groups":[]}','{"pinned":[7],"groups":{}}','{"pinned":[],"groups":{"Example":[null]}}'])assert.strictEqual(run({['previous'+suffixes[2]]:bad}).writes,0);
const scoped=run({...old,'previous.theme':'dark','previous.unrelated':'value'});assert(!Object.hasOwn(scoped.data,'current.theme'));assert(!Object.hasOwn(scoped.data,'current.unrelated'));
console.log('legacy/current preference shapes, precedence, reload and blocked storage PASS');
`
	cmd := exec.Command(node, "-e", program)
	cmd.Stdin = strings.NewReader(string(payload))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rendered layout migration: %v\n%s", err, output)
	}
}
