// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/CPP/Compile.h"


namespace zeek::detail {

void CPPCompile::GenInitExpr(const ExprPtr& e)
	{
	NL();

	const auto& t = e->GetType();
	auto ename = InitExprName(e);

	// First, create a CPPFunc that we can compile to compute 'e'.
	auto name = std::string("wrapper_") + ename;

	// Forward declaration of the function that computes 'e'.
	Emit("static %s %s(Frame* f__CPP);", FullTypeName(t), name);

	// Create the Func subclass that can be used in a CallExpr to
	// evaluate 'e'.
	Emit("class %s_cl : public CPPFunc", name);
	StartBlock();

	Emit("public:");
	Emit("%s_cl() : CPPFunc(\"%s\", %s)", name, name, e->IsPure() ? "true" : "false");

	StartBlock();
	Emit("type = make_intrusive<FuncType>(make_intrusive<RecordType>(new type_decl_list()), %s, FUNC_FLAVOR_FUNCTION);", GenTypeName(t));

	NoteInitDependency(e, TypeRep(t));
	EndBlock();

	Emit("ValPtr Invoke(zeek::Args* args, Frame* parent) const override final");
	StartBlock();

	if ( IsNativeType(t) )
		GenInvokeBody(name, t, "parent");
	else
		Emit("return %s(parent);", name);

	EndBlock();
	EndBlock(true);

	// Now the implementation of computing 'e'.
	Emit("static %s %s(Frame* f__CPP)", FullTypeName(t), name);
	StartBlock();

	Emit("return %s;", GenExpr(e, GEN_NATIVE));
	EndBlock();

	Emit("CallExprPtr %s;", ename);

	NoteInitDependency(e, TypeRep(t));
	AddInit(e, ename, std::string("make_intrusive<CallExpr>(make_intrusive<ConstExpr>(make_intrusive<FuncVal>(make_intrusive<") +
		name + "_cl>())), make_intrusive<ListExpr>(), false)");
	}

bool CPPCompile::IsSimpleInitExpr(const ExprPtr& e) const
	{
	switch ( e->Tag() ) {
	case EXPR_CONST:
	case EXPR_NAME:
		return true;

	case EXPR_RECORD_COERCE:
		{ // look for coercion of empty record
		auto op = e->GetOp1();

		if ( op->Tag() != EXPR_RECORD_CONSTRUCTOR )
			return false;

		auto rc = static_cast<const RecordConstructorExpr*>(op.get());
		const auto& exprs = rc->Op()->AsListExpr()->Exprs();

		return exprs.length() == 0;
		}

	default:
		return false;
	}
	}

std::string CPPCompile::InitExprName(const ExprPtr& e)
	{
	return init_exprs.KeyName(e);
	}

void CPPCompile::GenGlobalInit(const ID* g, std::string& gl, const ValPtr& v)
	{
	const auto& t = v->GetType();

	if ( t->Tag() == TYPE_FUNC )
		// This should get initialized by recognizing hash of
		// the function's body.
		return;

	std::string init_val;
	if ( t->Tag() == TYPE_OPAQUE )
		{
		// We can only generate these by reproducing the expression
		// (presumably a function call) used to create the value.
		// That isn't fully sound, since if the global's value
		// was redef'd in terms of its original value (e.g.,
		// "redef x = f(x)"), then we'll wind up with a broken
		// expression.  It's difficult to detect that in full
		// generality, so um Don't Do That.  (Note that this
		// only affects execution of compiled code where the
		// original scripts are replaced by load-stubs.  If
		// the scripts are available, then the HasVal() test
		// we generate will mean we don't wind up using this
		// expression anyway.)
		init_val = GenExpr(g->GetInitExpr(), GEN_VAL_PTR, false);
		}
	else
		init_val = BuildConstant(g, v);

	AddInit(g, std::string("if ( ! ") + gl + "->HasVal() )");
	AddInit(g, std::string("\t") + gl + "->SetVal(" + init_val + ");");
	}

void CPPCompile::GenFuncVarInits()
	{
	for ( const auto& fv_init : func_vars )
		{
		auto& fv = fv_init.first;
		auto& const_name = fv_init.second;

		auto f = fv->AsFunc();
		const auto& fn = f->Name();
		const auto& ft = f->GetType();

		NoteInitDependency(fv, TypeRep(ft));

		const auto& bodies = f->GetBodies();

		std::string hashes = "{";

		for ( auto b : bodies )
			{
			auto body = b.stmts.get();

			ASSERT(body_names.count(body) > 0);

			auto& body_name = body_names[body];
			ASSERT(body_hashes.count(body_name) > 0);

			NoteInitDependency(fv, body);

			if ( hashes.size() > 1 )
				hashes += ", ";

			hashes += Fmt(body_hashes[body_name]);
			}

		hashes += "}";

		auto init = std::string("lookup_func__CPP(\"") + fn +
			    "\", " + hashes + ", " + GenTypeName(ft) + ")";

		AddInit(fv, const_name, init);
		}
	}

void CPPCompile::GenPreInit(const Type* t)
	{
	std::string pre_init;

	switch ( t->Tag() ) {
	case TYPE_ADDR:
	case TYPE_ANY:
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ERROR:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_PATTERN:
	case TYPE_PORT:
	case TYPE_STRING:
	case TYPE_TIME:
	case TYPE_TIMER:
	case TYPE_VOID:
		pre_init = std::string("base_type(") + TypeTagName(t->Tag()) + ")";
		break;

	case TYPE_ENUM:
		pre_init = std::string("get_enum_type__CPP(\"") +
		           t->GetName() + "\")";
		break;

	case TYPE_SUBNET:
		pre_init = std::string("make_intrusive<SubNetType>()");
		break;

	case TYPE_FILE:
		pre_init = std::string("make_intrusive<FileType>(") +
		           GenTypeName(t->AsFileType()->Yield()) + ")";
		break;

	case TYPE_OPAQUE:
		pre_init = std::string("make_intrusive<OpaqueType>(\"") +
		           t->AsOpaqueType()->Name() + "\")";
		break;

	case TYPE_RECORD:
		{
		std::string name;

		if ( t->GetName() != "" )
			name = std::string("\"") + t->GetName() + std::string("\"");
		else
			name = "nullptr";

		pre_init = std::string("get_record_type__CPP(") + name + ")";
		}
		break;

	case TYPE_LIST:
		pre_init = std::string("make_intrusive<TypeList>()");
		break;

	case TYPE_TYPE:
	case TYPE_VECTOR:
	case TYPE_TABLE:
	case TYPE_FUNC:
		// Nothing to do for these, pre-initialization-wise.
		return;

	default:
		reporter->InternalError("bad type in CPPCompile::GenType");
	}

	pre_inits.emplace_back(GenTypeName(t) + " = " + pre_init + ";");
	}

void CPPCompile::AddInit(const Obj* o, const std::string& init)
	{
	obj_inits[o].emplace_back(init);
	}

void CPPCompile::AddInit(const Obj* o)
	{
	if ( obj_inits.count(o) == 0 )
		{
		std::vector<std::string> empty;
		obj_inits[o] = empty;
		}
	}

void CPPCompile::NoteInitDependency(const Obj* o1, const Obj* o2)
	{
	obj_deps[o1].emplace(o2);
	}

void CPPCompile::CheckInitConsistency(std::unordered_set<const Obj*>& to_do)
	{
	for ( const auto& od : obj_deps )
		{
		const auto& o = od.first;

		if ( to_do.count(o) == 0 )
			{
			fprintf(stderr, "object not in to_do: %s\n",
				obj_desc(o).c_str());
			exit(1);
			}

		for ( const auto& d : od.second )
			{
			if ( to_do.count(d) == 0 )
				{
				fprintf(stderr, "dep object for %s not in to_do: %s\n",
					obj_desc(o).c_str(), obj_desc(d).c_str());
				exit(1);
				}
			}
		}
	}

void CPPCompile::GenDependentInits(std::unordered_set<const Obj*>& to_do)
	{
	// The basic approach is fairly brute force: find elements of
	// to_do that don't have any pending dependencies; generate those;
	// and remove them from the to_do list, freeing up other to_do entries
	// to now not having any pending dependencies.  Iterate until there
	// are no more to-do items.
	while ( to_do.size() > 0 )
		{
		std::unordered_set<const Obj*> done;

		for ( const auto& o : to_do )
			{
			const auto& od = obj_deps.find(o);

			bool has_pending_dep = false;

			if ( od != obj_deps.end() )
				{
				for ( const auto& d : od->second )
					if ( to_do.count(d) > 0 )
						{
						has_pending_dep = true;
						break;
						}
				}

			if ( has_pending_dep )
				continue;

			for ( const auto& i : obj_inits.find(o)->second )
				Emit("%s", i);

			done.insert(o);
			}

		ASSERT(done.size() > 0);

		for ( const auto& o : done )
			{
			ASSERT(to_do.count(o) > 0);
			to_do.erase(o);
			}

		NL();
		}
	}

void CPPCompile::InitializeFieldMappings()
	{
	Emit("int fm_offset;");

	for ( const auto& mapping : field_decls )
		{
		auto rt = mapping.first;
		auto td = mapping.second;
		auto fn = td->id;
		auto rt_name = GenTypeName(rt) + "->AsRecordType()";

		Emit("fm_offset = %s->FieldOffset(\"%s\");", rt_name, fn);
		Emit("if ( fm_offset < 0 )");

		StartBlock();
		Emit("// field does not exist, create it");
		Emit("fm_offset = %s->NumFields();", rt_name);
		Emit("type_decl_list tl;");
		Emit(GenTypeDecl(td));
		Emit("%s->AddFieldsDirectly(tl);", rt_name);
		EndBlock();

		Emit("field_mapping.push_back(fm_offset);");
		}
	}

void CPPCompile::InitializeEnumMappings()
	{
	Emit("int em_offset;");

	for ( const auto& mapping : enum_names )
		{
		auto et = mapping.first;
		const auto& e_name = mapping.second;
		auto et_name = GenTypeName(et) + "->AsEnumType()";

		Emit("em_offset = %s->Lookup(\"%s\");", et_name, e_name);
		Emit("if ( em_offset < 0 )");

		StartBlock();
		Emit("// enum does not exist, create it");
		Emit("em_offset = %s->Names().size();", et_name);
		Emit("if ( %s->Lookup(em_offset) )", et_name);
		Emit("\treporter->InternalError(\"enum inconsistency while initializing compiled scripts\");");
		Emit("%s->AddNameInternal(\"%s\", em_offset);", et_name, e_name);
		EndBlock();

		Emit("enum_mapping.push_back(em_offset);");
		}
	}

void CPPCompile::GenInitHook()
	{
	NL();

	if ( standalone )
		GenStandaloneActivation();

	Emit("int hook_in_init()");

	StartBlock();

	Emit("CPP_init_funcs.push_back(init__CPP);");

	if ( standalone )
		GenLoad();

        Emit("return 0;");
	EndBlock();

	// Trigger the activation of the hook at run-time.
	NL();
	Emit("static int dummy = hook_in_init();\n");
	}

void CPPCompile::GenStandaloneActivation()
	{
	Emit("void standalone_init__CPP()");
	StartBlock();

	// For events and hooks, we need to add each compiled body *unless*
	// it's already there (which could be the case if the standalone
	// code wasn't run standalone but instead with the original scripts).
	// For events, we also register them in order to activate the
	// associated scripts.

	// First, build up a list of per-hook/event handler bodies.
	std::unordered_map<const Func*, std::vector<hash_type>> func_bodies;

	for ( const auto& func : funcs )
		{
		auto f = func.Func();

		if ( f->Flavor() == FUNC_FLAVOR_FUNCTION )
			// No need to explicitly add bodies.
			continue;

		auto fname = BodyName(func);
		auto bname = Canonicalize(fname.c_str()) + "_zf";

		if ( compiled_funcs.count(bname) == 0 )
			// We didn't wind up compiling it.
			continue;

		ASSERT(body_hashes.count(bname) > 0);
		func_bodies[f].push_back(body_hashes[bname]);
		}

	for ( auto& fb : func_bodies )
		{
		auto f = fb.first;
		const auto fn = f->Name();
		const auto& ft = f->GetType();

		std::string hashes;
		for ( auto h : fb.second )
			{
			if ( hashes.size() > 0 )
				hashes += ", ";

			hashes += Fmt(h);
			}

		hashes = "{" + hashes + "}";

		Emit("activate_bodies__CPP(\"%s\", %s, %s);",
		     fn, GenTypeName(ft), hashes);
		}

	EndBlock();
	NL();
	}

void CPPCompile::GenLoad()
	{
	// First, generate a hash unique to this compilation.
	auto t = util::current_time();
	auto th = std::hash<double>{}(t);

	total_hash = MergeHashes(total_hash, th);

	Emit("register_scripts__CPP(%s, standalone_init__CPP);", Fmt(total_hash));

	// Spit out the placeholder script.
	printf("global init_CPP_%llu = load_CPP(%llu);\n",
	       total_hash, total_hash);
	}

} // zeek::detail
