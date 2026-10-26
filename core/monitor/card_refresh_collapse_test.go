package monitor

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRefreshCardClearsCollapsedAliases(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the synthetic JS storage test")
	}
	program := `
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const refresh=fs.readFileSync(process.argv[1],'utf8');
const shared=fs.readFileSync(process.argv[2],'utf8');
const start=shared.indexOf('function configuredCardId(');
const end=shared.indexOf('function saveCollapsedSet(',start);
assert(start>=0&&end>start,'shared collapse loader must exist');
const loader=shared.slice(start,end);
function run(initial, options={}) {
  let stored=initial,writes=0,reads=0;
  const classes=new Set(['collapsed']);
  const card={classList:{contains:n=>classes.has(n),remove:n=>classes.delete(n)},
    _refreshConfig:{apiName:'example',sectionId:'example-section'}};
  const storage={getItem(k){reads++;assert.strictEqual(k,'example.monitor.collapsed.v1');if(options.readError)throw Error('storage unavailable');return stored},
    setItem(k,v){assert.strictEqual(k,'example.monitor.collapsed.v1');if(options.writeError)throw Error('storage unavailable');writes++;stored=v}};
  const c={window:{},document:{readyState:'loading',addEventListener(){},getElementById(){return card}},
    HD_COLLAPSE_KEY:'example.monitor.collapsed.v1',HD_CARD_ALIASES:{'example-old-card':'example-card','other-old-card':'other-card'},
    localStorage:storage,fetch(){return new Promise(()=>{})},getAppBase(){return '/example'},console};
  vm.createContext(c);vm.runInContext(refresh,c);c.COLLAPSE_KEY=c.HD_COLLAPSE_KEY;vm.runInContext(loader,c);
  const before=stored;
  c.loadCollapsedSet();assert.strictEqual(stored,before);assert.strictEqual(writes,0,'load must remain read-only');
  c.window.refreshCard('example-card');assert(!classes.has('collapsed'),'refresh opens the card');
  const reloaded=c.loadCollapsedSet();assert(!reloaded['example-card'],'card must stay open after reload');
  return {stored,writes,reloaded};
}
const original=['example-old-card','example-card','example-old-card','unrelated-card','other-old-card'];
const result=run(JSON.stringify(original));
assert.deepStrictEqual(JSON.parse(result.stored),['unrelated-card','other-old-card']);
assert.strictEqual(result.reloaded['unrelated-card'],true);
assert.strictEqual(result.reloaded['other-card'],true);
assert.deepStrictEqual(JSON.parse(run('["example-card","unrelated-card"]').stored),['unrelated-card']);
assert.deepStrictEqual(JSON.parse(run('["example-old-card"]').stored),[]);
run(null);run('not-json');run('{}');run('null');run('[]');
run('["example-old-card"]',{readError:true});
const blocked=run('[]',{writeError:true});assert.strictEqual(blocked.writes,0);
console.log('synthetic refresh/reload, alias duplicates, unrelated IDs and unavailable/malformed storage PASS');
`
	cmd := exec.Command(node, "-e", program,
		filepath.Join("..", "..", "web", "static", "js", "card_refresh.js"),
		filepath.Join("..", "..", "web", "static", "js", "shared.js"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("card refresh storage contract: %v\n%s", err, output)
	}
}
