// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

CPPCompile::CPPCompile(vector<FuncInfo>& _funcs, ProfileFuncs& _pfs, const string& gen_name,
                       const string& _addl_name, CPPHashManager& _hm, bool _update,
                       bool _standalone, bool report_uncompilable)
	: funcs(_funcs), pfs(_pfs), hm(_hm), update(_update), standalone(_standalone)
	{
	addl_name = _addl_name;
	bool is_addl = hm.IsAppend();
	auto target_name = is_addl ? addl_name.c_str() : gen_name.c_str();
	auto mode = is_addl ? "a" : "w";

	write_file = fopen(target_name, mode);
	if ( ! write_file )
		{
		reporter->Error("can't open C++ target file %s", target_name);
		exit(1);
		}

	if ( is_addl )
		{
		// We need a unique number to associate with the name
		// space for the code we're adding.  A convenient way to
		// generate this safely is to use the present size of the
		// file we're appending to.  That guarantees that every
		// incremental compilation will wind up with a different
		// number.
		struct stat st;
		if ( fstat(fileno(write_file), &st) != 0 )
			{
			char buf[256];
			util::zeek_strerror_r(errno, buf, sizeof(buf));
			reporter->Error("fstat failed on %s: %s", target_name, buf);
			exit(1);
			}

		// We use a value of "0" to mean "we're not appending,
		// we're generating from scratch", so make sure we're
		// distinct from that.
		addl_tag = st.st_size + 1;
		}

	else
		{
		// Create an empty "additional" file.
		auto addl_f = fopen(addl_name.c_str(), "w");
		if ( ! addl_f )
			{
			reporter->Error("can't open C++ additional file %s", addl_name.c_str());
			exit(1);
			}

		fclose(addl_f);
		}

	const_info[TYPE_BOOL] = InitGlobalInfo("Bool", "ValPtr");
	const_info[TYPE_INT] = InitGlobalInfo("Int", "ValPtr");
	const_info[TYPE_COUNT] = InitGlobalInfo("Count", "ValPtr");
	const_info[TYPE_ENUM] = InitGlobalInfo("Enum", "ValPtr");
	const_info[TYPE_DOUBLE] = InitGlobalInfo("Double", "ValPtr");
	const_info[TYPE_TIME] = InitGlobalInfo("Time", "ValPtr");
	const_info[TYPE_INTERVAL] = InitGlobalInfo("Interval", "ValPtr");
	const_info[TYPE_STRING] = InitGlobalInfo("String", "ValPtr");
	const_info[TYPE_PATTERN] = InitGlobalInfo("Pattern", "ValPtr");
	const_info[TYPE_ADDR] = InitGlobalInfo("Addr", "ValPtr");
	const_info[TYPE_SUBNET] = InitGlobalInfo("SubNet", "ValPtr");
	const_info[TYPE_PORT] = InitGlobalInfo("Port", "ValPtr");
	const_info[TYPE_LIST] = InitGlobalInfo("List", "ValPtr");
	const_info[TYPE_VECTOR] = InitGlobalInfo("Vector", "ValPtr");
	const_info[TYPE_RECORD] = InitGlobalInfo("Record", "ValPtr");
	const_info[TYPE_TABLE] = InitGlobalInfo("Table", "ValPtr");
	const_info[TYPE_FUNC] = InitGlobalInfo("Func", "ValPtr");
	const_info[TYPE_FILE] = InitGlobalInfo("File", "ValPtr");

	type_info = InitGlobalInfo("Type", "Ptr");
	attr_info = InitGlobalInfo("Attr", "Ptr");
	attrs_info = InitGlobalInfo("Attributes", "Ptr");
	call_exprs_info = InitGlobalInfo("CallExpr", "Ptr");

	lambda_reg_info = InitGlobalInfo("LambdaRegistration", "");
	global_id_info = InitGlobalInfo("GlobalID", "");

	Compile(report_uncompilable);
	}

CPPCompile::~CPPCompile()
	{
	fclose(write_file);
	}

shared_ptr<CPP_GlobalsInfo> CPPCompile::InitGlobalInfo(const char* tag, const char* type)
	{
	auto gi = make_shared<CPP_GlobalsInfo>(tag, type);
	all_global_info.insert(gi);

	if ( type[0] == '\0' )
		gi->SetCPPType("void*");

	return gi;
	}

void CPPCompile::Compile(bool report_uncompilable)
	{
	// Get the working directory so we can use it in diagnostic messages
	// as a way to identify this compilation.  Only germane when doing
	// incremental compilation (particularly of the test suite).
	char buf[8192];
	if ( ! getcwd(buf, sizeof buf) )
		reporter->FatalError("getcwd failed: %s", strerror(errno));

	working_dir = buf;

	if ( update && addl_tag > 0 && CheckForCollisions() )
		// Inconsistent compilation environment.
		exit(1);

	GenProlog();

	// Determine which functions we can call directly, and reuse
	// previously compiled instances of those if present.
	for ( const auto& func : funcs )
		{
		if ( func.Func()->Flavor() != FUNC_FLAVOR_FUNCTION )
			// Can't be called directly.
			continue;

		const char* reason;
		if ( IsCompilable(func, &reason) )
			compilable_funcs.insert(BodyName(func));
		else
			{
			if ( reason && report_uncompilable )
				fprintf(stderr, "%s cannot be compiled to C++ due to %s\n", func.Func()->Name(),
			                reason);
			not_fully_compilable.insert(func.Func()->Name());
			}

		auto h = func.Profile()->HashVal();
		if ( hm.HasHash(h) )
			{
			// Track the previously compiled instance
			// of this function.
			auto n = func.Func()->Name();
			hashed_funcs[n] = hm.FuncBodyName(h);
			}
		}

	// Track all of the types we'll be using.
	for ( const auto& t : pfs.RepTypes() )
		{
		TypePtr tp{NewRef{}, (Type*)(t)};
		types.AddKey(tp, pfs.HashType(t));
		(void)RegisterType(tp);
		}

	// ### This doesn't work for -O add-C++
	Emit("TypePtr types__CPP[%s];", Fmt(static_cast<int>(types.DistinctKeys().size())));

	NL();

	for ( const auto& c : pfs.Constants() )
		AddConstant(c);

	NL();

#if 0
	for ( auto gi : all_global_info )
		Emit(gi->Declare());

	NL();
#endif

	for ( auto& g : pfs.AllGlobals() )
		CreateGlobal(g);

	for ( const auto& e : pfs.Events() )
		if ( AddGlobal(e, "gl", false) )
			Emit("EventHandlerPtr %s_ev;", globals[string(e)]);

	for ( const auto& t : pfs.RepTypes() )
		{
		ASSERT(types.HasKey(t));
		TypePtr tp{NewRef{}, (Type*)(t)};
		RegisterType(tp);
		}

	// The scaffolding is now in place to go ahead and generate
	// the functions & lambdas.  First declare them ...
	for ( const auto& func : funcs )
		DeclareFunc(func);

	// We track lambdas by their internal names, because two different
	// LambdaExpr's can wind up referring to the same underlying lambda
	// if the bodies happen to be identical.  In that case, we don't
	// want to generate the lambda twice.
	unordered_set<string> lambda_names;
	for ( const auto& l : pfs.Lambdas() )
		{
		const auto& n = l->Name();
		if ( lambda_names.count(n) > 0 )
			// Skip it.
			continue;

		DeclareLambda(l, pfs.ExprProf(l).get());
		lambda_names.insert(n);
		}

	NL();

	// ... and now generate their bodies.
	for ( const auto& func : funcs )
		CompileFunc(func);

	lambda_names.clear();
	for ( const auto& l : pfs.Lambdas() )
		{
		const auto& n = l->Name();
		if ( lambda_names.count(n) > 0 )
			continue;

		CompileLambda(l, pfs.ExprProf(l).get());
		lambda_names.insert(n);
		}

	NL();
	Emit("std::vector<std::shared_ptr<CPP_RegisterBody>> CPP__bodies_to_register = {");

	for ( const auto& f : compiled_funcs )
		RegisterCompiledBody(f);

	Emit("};");

	GenEpilog();
	}

void CPPCompile::GenProlog()
	{
	if ( addl_tag == 0 )
		{
		Emit("#include \"zeek/script_opt/CPP/Runtime.h\"\n");
		Emit("namespace zeek::detail { //\n");
		}

	Emit("namespace CPP_%s { // %s\n", Fmt(addl_tag), working_dir);

	// The following might-or-might-not wind up being populated/used.
	Emit("std::vector<int> field_mapping;");
	Emit("std::vector<int> enum_mapping;");
	NL();
	}

void CPPCompile::RegisterCompiledBody(const string& f)
	{
	auto h = body_hashes[f];
	auto p = body_priorities[f];

	// Build up an initializer of the events relevant to the function.
	string events;
	if ( body_events.count(f) > 0 )
		for ( const auto& e : body_events[f] )
			{
			if ( events.size() > 0 )
				events += ", ";
			events = events + "\"" + e + "\"";
			}

	events = string("{") + events + "}";

	if ( addl_tag > 0 )
		// Hash in the location associated with this compilation
		// pass, to get a final hash that avoids conflicts with
		// identical-but-in-a-different-context function bodies
		// when compiling potentially conflicting additional code
		// (which we want to support to enable quicker test suite
		// runs by enabling multiple tests to be compiled into the
		// same binary).
		h = merge_p_hashes(h, p_hash(cf_locs[f]));

	Emit("\tstd::make_shared<CPP_RegisterBodyT<%s>>(\"%s\", %s, %s, std::vector<std::string>(%s)),", f + "_cl", f, Fmt(p), Fmt(h), events);

	if ( update )
		{
		fprintf(hm.HashFile(), "func\n%s%s\n", scope_prefix(addl_tag).c_str(), f.c_str());
		fprintf(hm.HashFile(), "%llu\n", h);
		}
	}

void CPPCompile::GenEpilog()
	{
	NL();
	for ( const auto& ii : init_infos )
		{
		auto& ie = ii.second;
		GenInitExpr(ie);
		if ( update )
			init_exprs.LogIfNew(ie->GetExpr(), addl_tag, hm.HashFile());
		}

	NL();

	// Generate the guts of compound types, and preserve type names
	// if present.
	for ( const auto& t : types.DistinctKeys() )
		{
		if ( update )
			types.LogIfNew(t, addl_tag, hm.HashFile());
		}

	for ( auto gi : all_global_info )
		gi->GenerateInitializers(this);

	unordered_set<const Obj*> to_do;
	for ( const auto& oi : obj_inits )
		to_do.insert(oi.first);

	if ( standalone )
		GenStandaloneActivation();

	NL();
	InitializeEnumMappings();

	NL();
	InitializeFieldMappings();

	NL();
	InitializeBiFs();

	NL();
	Emit("void init__CPP()");

	StartBlock();

	Emit("for ( auto& b : CPP__bodies_to_register )");
	Emit("\tb->Register();");
	NL();

	int max_cohort = 0;
	for ( auto gi : all_global_info )
		max_cohort = std::max(max_cohort, gi->MaxCohort());

	for ( auto c = 0; c <= max_cohort; ++c )
		for ( auto gi : all_global_info )
			if ( gi->CohortSize(c) > 0 )
				Emit("%s.InitializeCohort(%s);",
				     gi->InitializersName(), Fmt(c));

	NL();
	Emit("for ( auto& b : CPP__BiF_lookups__ )");
	Emit("\tb.ResolveBiF();");

	// Populate mappings for dynamic offsets.
	NL();
	Emit("for ( auto& em : CPP__enum_mappings__ )");
	Emit("\tenum_mapping.push_back(em.ComputeOffset());");
	NL();
	Emit("for ( auto& fm : CPP__field_mappings__ )");
	Emit("\tfield_mapping.push_back(fm.ComputeOffset());");

	if ( standalone )
		Emit("standalone_init__CPP();");

	EndBlock(true);

	GenInitHook();

	Emit("} // %s\n\n", scope_prefix(addl_tag));

	if ( update )
		UpdateGlobalHashes();

	if ( addl_tag > 0 )
		return;

	Emit("#include \"" + addl_name + "\"\n");
	Emit("} // zeek::detail");
	}

bool CPPCompile::IsCompilable(const FuncInfo& func, const char** reason)
	{
	if ( ! is_CPP_compilable(func.Profile(), reason) )
		return false;

	if ( reason )
		// Indicate that there's no fundamental reason it can't be
		// compiled.
		*reason = nullptr;

	if ( func.ShouldSkip() )
		return false;

	if ( hm.HasHash(func.Profile()->HashVal()) )
		// We've already compiled it.
		return false;

	return true;
	}

	} // zeek::detail
