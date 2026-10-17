package archtest

import (
	"fmt"
	"go/ast"
	"go/token"
	"path"
	"reflect"
	"strconv"
	"strings"
)

// checkFiles runs the per-file rules over a package: banned calls (L3, X1, X3,
// X4, X7, X9), reserved key literals (X5) and package-level mutable state (S4).
// Production files only, except os.Environ which the ticket bans everywhere.
func (e *Engine) checkFiles(p *Package) {
	if p.Class == nil {
		return // L8 already reported; the file rules all need the class
	}
	for _, f := range p.Files {
		e.checkCalls(p, f)
		e.checkLiterals(p, f)
		e.checkExec(p, f)
		e.checkEnviron(p, f)
	}
	for _, f := range p.TestFiles {
		e.checkEnviron(p, f)
	}
	e.checkS4(p)
}

// bannedCall is one entry of a rule's banned-calls list, split into the
// imported package path and the selector ("crypto/ed25519.Sign").
type bannedCall struct{ path, sel string }

func parseBannedCalls(entries []string) []bannedCall {
	out := make([]bannedCall, 0, len(entries))
	for _, entry := range entries {
		// The path itself contains slashes; the selector is what follows the
		// last dot ("crypto/ed25519.Sign").
		i := strings.LastIndex(entry, ".")
		if i < 0 {
			out = append(out, bannedCall{path: "", sel: entry})
			continue
		}
		out = append(out, bannedCall{path: entry[:i], sel: entry[i+1:]})
	}
	return out
}

func (e *Engine) checkCalls(p *Package, f *File) {
	type callRule struct {
		calls []bannedCall
		id    string
		msg   func(bannedCall) string
	}
	var rules []callRule
	add := func(id string, entries []string, msg func(bannedCall) string) {
		if r := e.Arch.Rule(id); e.on(id) && len(entries) > 0 && e.ruleApplies(r, p) {
			rules = append(rules, callRule{calls: parseBannedCalls(entries), id: id, msg: msg})
		}
	}
	add("X1", ruleCalls(e, "X1"), func(bc bannedCall) string {
		return fmt.Sprintf("calls %s.%s outside a signer adapter", bc.path, bc.sel)
	})
	add("X7", ruleCalls(e, "X7"), func(bc bannedCall) string {
		return fmt.Sprintf("calls %s.%s (no dumping, no printing in internal/)", bc.path, bc.sel)
	})
	add("L3", ruleCalls(e, "L3"), func(bc bannedCall) string {
		return fmt.Sprintf("calls %s.%s (non-deterministic I/O in pure code)", bc.path, bc.sel)
	})
	add("X4", ruleCalls(e, "X4"), func(bc bannedCall) string {
		return fmt.Sprintf("calls http.%s (uncontrolled outbound client)", bc.sel)
	})

	// X1 does not apply inside the signer adapters themselves.
	if x1 := e.Arch.Rule("X1"); x1 != nil && e.match.matchAny(x1.SignerPaths, f.Name) {
		var kept []callRule
		for _, r := range rules {
			if r.id != "X1" {
				kept = append(kept, r)
			}
		}
		rules = kept
	}

	x4on := e.on("X4")
	x9 := e.Arch.Rule("X9")
	x9on := e.on("X9") && !e.match.matchAny(x9.RouteFiles, path.Base(f.Name))
	ast.Inspect(f.AST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			switch fun := node.Fun.(type) {
			case *ast.SelectorExpr:
				id, ok := fun.X.(*ast.Ident)
				if !ok {
					return true
				}
				imp := f.Imports[id.Name]
				for _, r := range rules {
					for _, bc := range r.calls {
						if bc.path == imp && bc.sel == fun.Sel.Name {
							e.fireItem(r.id, p, f.Name, p.Fset.Position(node.Pos()).Line, bc.path+"."+bc.sel, r.msg(bc))
						}
					}
				}
				// X3 — exec only where the rule allows it; the environment
				// requirement is checked per call in checkExec.
				if x3 := e.Arch.Rule("X3"); e.on("X3") && imp == "os/exec" &&
					(fun.Sel.Name == "Command" || fun.Sel.Name == "CommandContext") &&
					!contains(x3.ExecAllowedIn, p.Class.ID) {
					e.fireItem("X3", p, f.Name, e.line(p, f, node), "os/exec."+fun.Sel.Name,
						fmt.Sprintf("calls exec.%s outside an adapter (class %s)", fun.Sel.Name, p.Class.ID))
				}
				// X9 — routes are registered only in routes.go.
				if x9on && (fun.Sel.Name == "Handle" || fun.Sel.Name == "HandleFunc") &&
					hashtagsPath(node.Args) {
					e.fireItem("X9", p, f.Name, e.line(p, f, node), routePattern(node.Args),
						"registers a route outside routes.go")
				}
			case *ast.Ident:
				// dot-imported call: a bare Sign(...) when crypto/ed25519 is dot-imported
				for _, r := range rules {
					for _, bc := range r.calls {
						if bc.sel == fun.Name && contains(f.DotImports, bc.path) {
							e.fireItem(r.id, p, f.Name, p.Fset.Position(node.Pos()).Line, bc.path+"."+bc.sel, r.msg(bc))
						}
					}
				}
			}
		case *ast.SelectorExpr:
			// X4 — http.DefaultClient used as a value (x := http.DefaultClient,
			// http.DefaultClient.Do(...)).
			if x4on {
				if id, ok := node.X.(*ast.Ident); ok && f.Imports[id.Name] == "net/http" && node.Sel.Name == "DefaultClient" {
					e.fireItem("X4", p, f.Name, e.line(p, f, node), "net/http.DefaultClient",
						"uses http.DefaultClient (uncontrolled outbound client)")
				}
			}
		case *ast.CompositeLit:
			// X4 — &http.Client{...} built by hand.
			if x4on {
				if sel, ok := node.Type.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && f.Imports[id.Name] == "net/http" && sel.Sel.Name == "Client" {
						e.fireItem("X4", p, f.Name, e.line(p, f, node), "net/http.Client{}",
							"constructs &http.Client{} directly (bare client)")
					}
				}
			}
		}
		return true
	})
}

// hashtagsPath reports whether a call's first argument is a string literal
// starting with "/" (a route pattern).
func hashtagsPath(args []ast.Expr) bool {
	return strings.HasPrefix(routePattern(args), "/")
}

// routePattern returns the route pattern a registration call passes (its first
// string-literal argument) — the violation item the baseline ratchet records
// for X9. Empty when the pattern is not a literal.
func routePattern(args []ast.Expr) string {
	if len(args) == 0 {
		return ""
	}
	lit, ok := args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

// ruleCalls returns a rule's banned-calls list, or nil.
func ruleCalls(e *Engine, id string) []string {
	if r := e.Arch.Rule(id); r != nil {
		return r.BannedCalls
	}
	return nil
}

// checkEnviron flags os.Environ in any file — production or test.
func (e *Engine) checkEnviron(p *Package, f *File) {
	if !e.on("X3") {
		return
	}
	ast.Inspect(f.AST, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && f.Imports[id.Name] == "os" && sel.Sel.Name == "Environ" {
					e.fireItem("X3", p, f.Name, e.line(p, f, call), "os.Environ",
						"reads os.Environ() (the process environment)")
				}
			}
		}
		return true
	})
}

// checkExec enforces X3's second half: exec.Command in a repository adapter
// must run with an explicit environment. A call bound to a variable needs a
// `cmd.Env = ...` assignment in the same function; an inline call
// (`exec.Command("ls").Run()`) has nothing to attach cmd.Env to, so it is
// always a violation.
func (e *Engine) checkExec(p *Package, f *File) {
	x3 := e.Arch.Rule("X3")
	if x3 == nil || !e.on("X3") || !contains(x3.ExecAllowedIn, p.Class.ID) || p.Class.ID != "repository" {
		return // the outside-an-adapter verdict is checkCalls'; devtool is exempt
	}
	for _, fn := range funcBodies(f.AST) {
		// exec.Command* call sites that are not bound to a cmd variable, by
		// line → the constructor they call.
		inline := map[int]string{}
		// cmd variables bound to an exec call, by name → where and with what.
		type binding struct {
			line int
			sel  string
		}
		bound := map[string]binding{}
		envSet := map[string]bool{}
		ast.Inspect(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel := hasExecCall(f, call); sel != "" {
					inline[p.Fset.Position(call.Pos()).Line] = sel
				}
			}
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, rhs := range assign.Rhs {
				sel := hasExecCall(f, rhs)
				if sel == "" {
					continue
				}
				for _, lhs := range assign.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
						bound[id.Name] = binding{p.Fset.Position(id.Pos()).Line, sel}
					}
				}
			}
			if assign.Tok == token.ASSIGN {
				for _, lhs := range assign.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && sel.Sel.Name == "Env" {
							envSet[id.Name] = true
						}
					}
				}
			}
			return true
		})
		for _, b := range bound {
			delete(inline, b.line) // a bound call is judged by its cmd.Env below
		}
		for line, sel := range inline {
			e.fireItem("X3", p, f.Name, line, "os/exec."+sel,
				fmt.Sprintf("spawns exec.%s inline — nothing to attach cmd.Env to", sel))
		}
		for name, b := range bound {
			if !envSet[name] {
				e.fireItem("X3", p, f.Name, b.line, "os/exec."+b.sel,
					fmt.Sprintf("spawns exec.%s %q without an explicit environment (cmd.Env)", b.sel, name))
			}
		}
	}
}

// hasExecCall returns the os/exec constructor an expression calls ("Command"
// or "CommandContext"), or "" when it calls neither.
func hasExecCall(f *File, expr ast.Expr) string {
	found := ""
	ast.Inspect(expr, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && f.Imports[id.Name] == "os/exec" &&
					(sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
					found = sel.Sel.Name
				}
			}
		}
		return found == ""
	})
	return found
}

// funcBodies returns the body of every function literal and declaration.
func funcBodies(file *ast.File) (out []*ast.BlockStmt) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body != nil {
				out = append(out, fn.Body)
			}
		case *ast.FuncLit:
			if fn.Body != nil {
				out = append(out, fn.Body)
			}
		}
		return true
	})
	return out
}

// checkLiterals enforces X5: reserved storage key prefixes are only formatted
// inside their owner packages.
func (e *Engine) checkLiterals(p *Package, f *File) {
	x5 := e.Arch.Rule("X5")
	if x5 == nil || !e.on("X5") {
		return
	}
	var prefixes []PrefixRule
	for _, pr := range x5.Prefixes {
		if !contains(pr.OwnerPackages, p.Path) {
			prefixes = append(prefixes, pr)
		}
	}
	if len(prefixes) == 0 {
		return
	}
	ast.Inspect(f.AST, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		for _, pr := range prefixes {
			if strings.HasPrefix(s, pr.Prefix) {
				e.fireItem("X5", p, f.Name, e.line(p, f, lit), pr.Prefix,
					fmt.Sprintf("formats the reserved key prefix %q by hand (built by %s)", pr.Prefix, pr.Builder))
			}
		}
		return true
	})
}

// checkS4 enforces no init() and no package-level mutable state. A package var
// is state when it has a mutable kind (map/slice/chan/func/pointer) or a
// composite/& value — unless it is one of the allowed conventions
// (*regexp.Regexp, go:embed) — and something outside its own declaration
// assigns it in production code.
func (e *Engine) checkS4(p *Package) {
	if !e.on("S4") {
		return
	}
	type pkgVar struct {
		name string
		f    *File
		line int
	}
	var decls []pkgVar
	for _, f := range p.Files {
		for _, d := range f.AST.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR || hasDirective(gd.Doc, "go:embed") {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || hasDirective(vs.Doc, "go:embed") {
					continue
				}
				for _, name := range vs.Names {
					if name.Name == "_" || !varKindMutable(vs) {
						continue
					}
					decls = append(decls, pkgVar{name.Name, f, p.Fset.Position(name.Pos()).Line})
				}
			}
		}
	}
	for _, f := range p.Files {
		for _, d := range f.AST.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "init" {
				e.fireItem("S4", p, f.Name, p.Fset.Position(fd.Pos()).Line, "init()",
					"declares init() — build and register in a constructor")
			}
		}
	}
	if len(decls) == 0 {
		return
	}
	mutated := map[string]bool{}
	for _, f := range p.Files {
		ast.Inspect(f.AST, func(n ast.Node) bool {
			var roots []string
			switch a := n.(type) {
			case *ast.AssignStmt:
				if a.Tok == token.ASSIGN { // := declares a fresh local, not a mutation
					for _, lhs := range a.Lhs {
						roots = append(roots, rootIdent(lhs))
					}
				}
			case *ast.IncDecStmt:
				roots = append(roots, rootIdent(a.X))
			}
			for _, r := range roots {
				mutated[r] = true
			}
			return true
		})
	}
	for _, v := range decls {
		if mutated[v.name] {
			e.fireItem("S4", p, v.f.Name, v.line, v.name,
				fmt.Sprintf("package-level mutable state %q", v.name))
		}
	}
}

// varKindMutable reports whether a var's declared kind is mutable-by-shape
// (map, slice, channel, function, pointer, or a composite/& value). Named and
// scalar types are left to the mutation scan.
func varKindMutable(vs *ast.ValueSpec) bool {
	if typeExprMutable(vs.Type) {
		return true
	}
	for _, v := range vs.Values {
		switch v.(type) {
		case *ast.CompositeLit, *ast.UnaryExpr:
			return true
		}
	}
	return false
}

func typeExprMutable(t ast.Expr) bool {
	switch t := t.(type) {
	case nil:
		return false
	case *ast.MapType, *ast.ArrayType, *ast.ChanType, *ast.FuncType:
		return true
	case *ast.StarExpr:
		// *regexp.Regexp is the compile-once convention.
		sel, ok := t.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		return !ok || id.Name != "regexp" || sel.Sel.Name != "Regexp"
	default:
		return false
	}
}

// rootIdent finds the identifier an assignment target is rooted at:
// registry[k] -> registry, cfg.Mu -> cfg, *p -> p.
func rootIdent(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return rootIdent(e.X)
	case *ast.SelectorExpr:
		return rootIdent(e.X)
	case *ast.StarExpr:
		return rootIdent(e.X)
	case *ast.ParenExpr:
		return rootIdent(e.X)
	case *ast.TypeAssertExpr:
		return rootIdent(e.X)
	}
	return ""
}

func hasDirective(g *ast.CommentGroup, directive string) bool {
	if g == nil {
		return false
	}
	return strings.Contains(g.Text(), directive)
}

// checkPackage runs the package-level rules: C3 (tests exist). X2 is a
// whole-module struct check and runs once from Run.
func (e *Engine) checkPackage(p *Package) {
	if e.on("C3") && len(p.Files) > 0 && len(p.TestFiles) == 0 {
		e.fire("C3", p, e.fileOf(p), e.lineOf(p), "package has no tests")
	}
}

// checkX2 enforces the control-plane config rule on every struct the rule
// names: every exported field must carry json:"-" or be one of the declared
// wire fields (Policy's Allowlist/Denylist genuinely ride the wire — policyWire
// re-projects them). A struct — or its package — the rule cannot find is a HARD
// error: a typo in architecture.yaml must fail the gate, never silently check
// nothing.
func (e *Engine) checkX2(x2 *Rule) {
	for _, sr := range x2.Structs {
		pkg := e.byPath[e.Module+"/"+sr.Package]
		if pkg == nil {
			e.hard(Finding{Rule: x2.ID, Package: sr.Package, File: "architecture.yaml",
				Message: fmt.Sprintf("struct %s.%s: package %s is not part of this run, so X2 checks nothing", sr.Package, sr.Type, sr.Package),
				Fix:     "keep the struct's package inside the module (the gate loads ./...)"})
			continue
		}
		found := false
		for _, f := range pkg.Files {
			ast.Inspect(f.AST, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok || ts.Name.Name != sr.Type {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				found = true
				for _, field := range st.Fields.List {
					for _, name := range field.Names {
						if !name.IsExported() || contains(sr.WireFields, name.Name) || jsonTagOff(field) {
							continue
						}
						e.fireItem("X2", pkg, f.Name, pkg.Fset.Position(name.Pos()).Line, name.Name,
							fmt.Sprintf("control-plane config field %s can reach the wire (no json:\"-\", not a declared wire field)", name.Name))
					}
				}
				return true
			})
		}
		if !found {
			e.hard(Finding{Rule: x2.ID, Package: sr.Package, File: "architecture.yaml",
				Message: fmt.Sprintf("struct %s.%s does not exist in package %s — X2 checks nothing", sr.Package, sr.Type, sr.Package),
				Fix:     "name the real struct in architecture.yaml (X2), or restore it"})
		}
	}
}

// jsonTagOff reports whether the field's json tag keeps it off the wire.
func jsonTagOff(field *ast.Field) bool {
	if field.Tag == nil {
		return false
	}
	tag, err := strconv.Unquote(field.Tag.Value)
	if err != nil {
		return false
	}
	name, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
	return name == "-"
}

// line converts a position in f to a line number.
func (e *Engine) line(p *Package, f *File, n ast.Node) int {
	return p.Fset.Position(n.Pos()).Line
}
