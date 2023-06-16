// See the file "COPYING" in the main distribution directory for copyright.

// ZBody: ZAM function body that replaces a function's original AST body.

#pragma once

#include "zeek/script_opt/ZAM/IterInfo.h"
#include "zeek/script_opt/ZAM/Support.h"

namespace zeek::detail
	{

// Static information about globals used in a function.
class GlobalInfo
	{
public:
	IDPtr id;
	int slot;
	};

// These are the counterparts to CaseMapI and CaseMapsI in ZAM.h,
// but concretized to use instruction numbers rather than pointers
// to instructions.
template <typename T> using CaseMap = std::map<T, int>;
template <typename T> using CaseMaps = std::vector<CaseMap<T>>;

using TableIterVec = std::vector<TableIterInfo>;

class ZBody : public Stmt
	{
public:
	ZBody(const char* _func_name, const ZAMCompiler* zc);

	~ZBody() override;

	// These are split out from the constructor to allow construction
	// of a ZBody from either save-file full instructions (first method,
	// not currently supported) or intermediary instructions (second method).
	void SetInsts(std::vector<ZInst*>& insts);
	void SetInsts(std::vector<ZInstI*>& instsI);

	ValPtr Exec(Frame* f, StmtFlowType& flow) override;

	// Older code exists for save files, but let's see if we can
	// avoid having to support them, as they're a fairly elaborate
	// production.
	//
	// void SaveTo(FILE* f, int interp_frame_size) const;

	void Dump() const;

	void ProfileExecution() const;

protected:
	// Initializes profiling information, if needed.
	void InitProfile();

	ValPtr DoExec(Frame* f, StmtFlowType& flow);

	// Run-time checking for "any" type being consistent with
	// expected typed.  Returns true if the type match is okay.
	bool CheckAnyType(const TypePtr& any_type, const TypePtr& expected_type,
	                  const Location* loc) const;

	StmtPtr Duplicate() override { return {NewRef{}, this}; }

	void StmtDescribe(ODesc* d) const override;
	TraversalCode Traverse(TraversalCallback* cb) const override;

private:
	const char* func_name = nullptr;

	const ZInst* insts = nullptr;
	unsigned int end_pc = 0;

	FrameReMap frame_denizens;
	int frame_size;

	// A list of frame slots that correspond to managed values.
	std::vector<int> managed_slots;

	// This is non-nil if the function is (asserted to be) non-recursive,
	// in which case we pre-allocate this.
	ZVal* fixed_frame = nullptr;

	// Pre-allocated table iteration values.  For recursive invocations,
	// these are copied into a local stack variable, but for non-recursive
	// functions they can be used directly.
	TableIterVec table_iters;

	// Points to the TableIterVec used to manage iteration over tables.
	// For non-recursive functions, we just use the static one, but
	// for recursive ones this points to the local stack variable.
	TableIterVec* tiv_ptr = &table_iters;

	// Number of StepIterInfo's required by the function.  These we
	// always create using a local stack variable, since they don't
	// require any overhead or cleanup.
	int num_step_iters;

	std::vector<GlobalInfo> globals;
	int num_globals;

	// The following are only maintained if we're doing profiling.
	//
	// These need to be pointers so we can manipulate them in a
	// const method.
	std::vector<int>* inst_count = nullptr; // for profiling
	double* CPU_time = nullptr; // cumulative CPU time for the program
	std::vector<double>* inst_CPU = nullptr; // per-instruction CPU time.

	CaseMaps<zeek_int_t> int_cases;
	CaseMaps<zeek_uint_t> uint_cases;
	CaseMaps<double> double_cases;
	CaseMaps<std::string> str_cases;
	};

// Prints the execution profile.
extern void report_ZOP_profile();

	} // namespace zeek::detail
