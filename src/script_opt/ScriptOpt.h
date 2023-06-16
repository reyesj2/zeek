// See the file "COPYING" in the main distribution directory for copyright.

// Classes for controlling/orchestrating script optimization & compilation.

#pragma once

#include <optional>
#include <regex>
#include <string>

#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"

namespace zeek
	{
struct Options;
	}

namespace zeek::detail
	{

// Flags controlling what sorts of analysis to do.

struct AnalyOpt
	{

	// If non-nil, then only analyze function/event/hook(s) whose names
	// match one of the given regular expressions.
	//
	// Applies to both ZAM and C++.
	std::vector<std::regex> only_funcs;

	// Same, but for the filenames where the function is found.
	std::vector<std::regex> only_files;

	// For a given compilation target, report functions that can't
	// be compiled.
	bool report_uncompilable = false;

	////// Options relating to ZAM:

	// Whether to analyze scripts.
	bool activate = false;

	// If true, compile all compilable functions, even those that
	// are inlined.  Mainly useful for ensuring compatibility for
	// some tests in the test suite.
	bool compile_all = false;

	// Whether to optimize the AST.
	bool optimize_AST = false;

	// If true, do global inlining.
	bool inliner = false;

	// If true, report which functions are directly and indirectly
	// recursive, and exit.  Only germane if running the inliner.
	bool report_recursive = false;

	// If true, generate ZAM code for applicable function bodies,
	// activating all optimizations.
	bool gen_ZAM = false;

	// Generate ZAM code, but do not turn on optimizations unless
	// specified.
	bool gen_ZAM_code = false;

	// Deactivate the low-level ZAM optimizer.
	bool no_ZAM_opt = false;

	// Produce a profile of ZAM execution.
	bool profile_ZAM = false;

	// If true, dump out transformed code: the results of reducing
	// interpreted scripts, and, if optimize is set, of then optimizing
	// them.
	bool dump_xform = false;

	// If true, dump out the use-defs for each analyzed function.
	bool dump_uds = false;

	// If true, dump out generated ZAM code.
	bool dump_ZAM = false;

	// If non-zero, looks for variables that are used-but-possibly-not-set,
	// or set-but-not-used.  We store this as an int rather than a bool
	// because we might at some point extend the analysis to deeper forms
	// of usage issues, such as those present in record fields.
	//
	// Included here with other ZAM-related options since conducting
	// the analysis requires activating some of the machinery used
	// for ZAM.
	int usage_issues = 0;

	////// Options relating to C++:

	// If true, generate C++;
	bool gen_CPP = false;

	// If true, the C++ should be standalone (not require the presence
	// of the corresponding script, and not activated by default).
	bool gen_standalone_CPP = false;

	// If true, use C++ bodies if available.
	bool use_CPP = false;

	// If true, report on available C++ bodies.
	bool report_CPP = false;

	// If true, allow standalone compilation in the presence of
	// conditional code.
	bool allow_cond = false;
	};

extern AnalyOpt analysis_options;

class ProfileFunc;

using ScriptFuncPtr = IntrusivePtr<ScriptFunc>;

// Info we need for tracking an instance of a function.
class FuncInfo
	{
public:
	FuncInfo(ScriptFuncPtr _func, ScopePtr _scope, StmtPtr _body, int _priority)
		: func(std::move(_func)), scope(std::move(_scope)), body(std::move(_body)),
		  priority(_priority)
		{
		}

	ScriptFunc* Func() const { return func.get(); }
	const ScriptFuncPtr& FuncPtr() const { return func; }
	const ScopePtr& Scope() const { return scope; }
	const StmtPtr& Body() const { return body; }
	int Priority() const { return priority; }
	const ProfileFunc* Profile() const { return pf.get(); }
	std::shared_ptr<ProfileFunc> ProfilePtr() const { return pf; }

	void SetBody(StmtPtr new_body) { body = std::move(new_body); }
	// void SetProfile(std::shared_ptr<ProfileFunc> _pf);
	void SetProfile(std::shared_ptr<ProfileFunc> _pf) { pf = std::move(_pf); }

	// The following provide a way of marking FuncInfo's as
	// should-be-skipped for script optimization, generally because
	// the function body has a property that a given script optimizer
	// doesn't know how to deal with.  Defaults to don't-skip.
	bool ShouldSkip() const { return skip; }
	void SetSkip(bool should_skip) { skip = should_skip; }

protected:
	ScriptFuncPtr func;
	ScopePtr scope;
	StmtPtr body;
	std::shared_ptr<ProfileFunc> pf;
	int priority;

	// Whether to skip optimizing this function.
	bool skip = false;
	};

// We track which functions are definitely not recursive.  We do this
// as the negative, rather than tracking functions known to be recursive,
// so that if we don't do the analysis at all (it's driven by inlining),
// we err on the conservative side and assume every function is recursive.
extern std::unordered_set<const Func*> non_recursive_funcs;

// Analyze a given function for optimization.
extern void analyze_func(ScriptFuncPtr f);

// Same, for lambdas.
extern void analyze_lambda(LambdaExpr* f);

// Same, for lambdas used in "when" statements.  For these, analyze_lambda()
// has already been called.
extern void analyze_when_lambda(LambdaExpr* f);

// Whether a given script function is a "when" lambda.
extern bool is_when_lambda(const ScriptFunc* f);

// Analyze the given top-level statement(s) for optimization.  Returns
// a pointer to a FuncInfo for an argument-less quasi-function that can
// be Invoked, or its body executed directly, to execute the statements.
extern const FuncInfo* analyze_global_stmts(Stmt* stmts);

// Add a pattern to the "only_funcs" list.
extern void add_func_analysis_pattern(AnalyOpt& opts, const char* pat);

// Add a pattern to the "only_files" list.
extern void add_file_analysis_pattern(AnalyOpt& opts, const char* pat);

// True if the given script function & body should be analyzed; otherwise
// it should be skipped.
extern bool should_analyze(const ScriptFuncPtr& f, const StmtPtr& body);

// Analyze all of the parsed scripts collectively for usage issues (unless
// suppressed by the flag) and optimization.
extern void analyze_scripts(bool no_unused_warnings);

// Called when Zeek is terminating.
extern void finish_script_execution();

// Used for C++-compiled scripts to signal their presence, by setting this
// to a non-empty value.
extern void (*CPP_init_hook)();

// Used for "standalone" C++-compiled scripts to complete their activation;
// called after parsing and BiF initialization, but before zeek_init.
extern void (*CPP_activation_hook)();

	} // namespace zeek::detail
