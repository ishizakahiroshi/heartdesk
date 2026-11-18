package monitor

import (
	"encoding/json"
	"io/fs"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/web"
)

func TestNcStorageRendersIndividualQuotas(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for quota render validation")
	}
	source, err := fs.ReadFile(web.Static(), "js/shared.js")
	if err != nil {
		t.Fatal(err)
	}
	var functions string
	for _, name := range []string{"renderNcStorageCard", "buildQuotaStatBox"} {
		body := regexp.MustCompile(`(?s)function ` + name + `\([^)]*\) \{.*?\n\}`).Find(source)
		if len(body) == 0 {
			t.Fatalf("missing function %s", name)
		}
		functions += string(body) + "\n"
	}
	payload, _ := json.Marshal(functions)
	program := `
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=JSON.parse(fs.readFileSync(0,'utf8'));
function el(){return {children:[],style:{},className:'',textContent:'',appendChild(x){this.children.push(x);}}}
const ctx={document:{createElement:el},formatBytes:n=>n+' B',formatCount:n=>String(n),barColorClass:()=>'',renderR2StatBoxPlaceholder:()=>{}};
vm.createContext(ctx);vm.runInContext(source,ctx);
const container=el();ctx.renderNcStorageCard(container,{users:{used:0,quota:0,unlimited:0,users:1},groupfolders_totals:{size:15,quota:100,unlimited:1},groupfolders:[{mount_point:'unlimited',size:7,quota:null},{mount_point:'zero',size:5,quota:0},{mount_point:'limited',size:3,quota:100}]},null);
const boxes=container.children[2].children;
const values=Object.fromEntries(boxes.map(b=>[b.children[0].textContent,b.children[1].textContent]));
assert.strictEqual(values.unlimited,'7 B / 無制限');
assert.strictEqual(values.zero,'5 B / 0 B');
assert.strictEqual(values.limited,'3 B / 100 B (3.0%)');
assert(container.children[0].children[1].children[1].textContent.includes('無制限1件'));
`
	cmd := exec.Command(node, "-e", program)
	cmd.Stdin = strings.NewReader(string(payload))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("quota render: %v\n%s", err, output)
	}
}
