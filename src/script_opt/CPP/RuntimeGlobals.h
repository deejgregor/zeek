// See the file "COPYING" in the main distribution directory for copyright.

// Classes for run-time initialization and management of C++ globals used
// by the generated code.

#include "zeek/Expr.h"
#include "zeek/script_opt/CPP/RuntimeInit.h"

#pragma once

namespace zeek::detail
	{

using BoolValPtr = IntrusivePtr<BoolVal>;
using IntValPtr = IntrusivePtr<IntVal>;
using CountValPtr = IntrusivePtr<CountVal>;
using DoubleValPtr = IntrusivePtr<DoubleVal>;
using TimeValPtr = IntrusivePtr<TimeVal>;
using IntervalValPtr = IntrusivePtr<IntervalVal>;
using FileValPtr = IntrusivePtr<FileVal>;

extern std::vector<BoolValPtr> CPP__Bool__;
extern std::vector<IntValPtr> CPP__Int__;
extern std::vector<CountValPtr> CPP__Count__;
extern std::vector<EnumValPtr> CPP__Enum__;
extern std::vector<DoubleValPtr> CPP__Double__;
extern std::vector<TimeValPtr> CPP__Time__;
extern std::vector<IntervalValPtr> CPP__Interval__;
extern std::vector<StringValPtr> CPP__String__;
extern std::vector<PatternValPtr> CPP__Pattern__;
extern std::vector<AddrValPtr> CPP__Addr__;
extern std::vector<SubNetValPtr> CPP__SubNet__;
extern std::vector<PortValPtr> CPP__Port__;
extern std::vector<ListValPtr> CPP__List__;
extern std::vector<RecordValPtr> CPP__Record__;
extern std::vector<TableValPtr> CPP__Table__;
extern std::vector<VectorValPtr> CPP__Vector__;
extern std::vector<FuncValPtr> CPP__Func__;
extern std::vector<FileValPtr> CPP__File__;

extern std::vector<TypePtr> CPP__Type__;
extern std::vector<AttrPtr> CPP__Attr__;
extern std::vector<AttributesPtr> CPP__Attributes__;
extern std::vector<CallExprPtr> CPP__CallExpr__;

template <class T>
class CPP_Global
	{
public:
	virtual ~CPP_Global() { }

	virtual T PreInit() const { return nullptr; }
	virtual T Generate(std::vector<T>& global_vec, int offset) const
		{ return Generate(global_vec); }
	virtual T Generate(std::vector<T>& global_vec) const
		{ return Generate(); }
	virtual T Generate() const
		{ return nullptr; }
	};

template <class T>
class CPP_Globals
	{
public:
	CPP_Globals(std::vector<T>& _global_vec, std::vector<std::vector<CPP_Global<T>>> _inits)
		: global_vec(_global_vec), inits(std::move(_inits))
		{
		int num_globals = 0;

		for ( const auto& cohort : inits )
			{
			cohort_offsets.push_back(num_globals);
			num_globals += cohort.size();
			}

		global_vec.resize(num_globals);

		DoPreInits();
		}

	void InitializeCohort(int cohort)
		{
		int offset = cohort_offsets[cohort];

		for ( const auto& i : inits[cohort] )
			{
			global_vec[offset] = i.Generate(global_vec, offset);
			++offset;
			}
		}

private:
	void DoPreInits()
		{
		int offset = 0;

		for ( const auto& cohort : inits )
			for ( const auto& i : cohort )
				global_vec[offset++] = i.PreInit();
		}

	std::vector<T>& global_vec;

	// Indexed first by cohort, and then iterated over to get all
	// of the initializers for that cohort.
	std::vector<std::vector<CPP_Global<T>>> inits;

	std::vector<int> cohort_offsets;
	};

template <class T1, typename T2, class T3>
class CPP_BasicConst : public CPP_Global<T1>
	{
public:
	CPP_BasicConst(T2 _v) : v(_v) { }

	T1 Generate() const override
		{ return make_intrusive<T3>(v); }

private:
	T2 v;
	};

class CPP_PortConst : public CPP_Global<PortValPtr>
	{
public:
	CPP_PortConst(int _raw_p)
		: raw_p(_raw_p) { }

	PortValPtr Generate() const override
		{ return make_intrusive<PortVal>(raw_p); }

private:
	uint32_t raw_p;
	};

class CPP_StringConst : public CPP_Global<StringValPtr>
	{
public:
	CPP_StringConst(int _len, const char* _chars)
		: len(_len), chars(_chars) { }

	StringValPtr Generate() const override
		{ return make_intrusive<StringVal>(len, chars); }

private:
	int len;
	const char* chars;
	};

class CPP_PatternConst : public CPP_Global<PatternValPtr>
	{
public:
	CPP_PatternConst(const char* _pattern, int _is_case_insensitive)
		: pattern(_pattern), is_case_insensitive(_is_case_insensitive) { }

	PatternValPtr Generate() const override;

private:
	const char* pattern;
	int is_case_insensitive;
	};

class CPP_EnumConst : public CPP_Global<EnumValPtr>
	{
public:
	CPP_EnumConst(int type, int val)
		: e_type(type), e_val(val) { }

	EnumValPtr Generate() const override
		{ return make_enum__CPP(CPP__Type__[e_type], e_val); }

private:
	int e_type;
	int e_val;
	};

class CPP_AbstractValElem
	{
public:
	CPP_AbstractValElem() {}
	virtual ~CPP_AbstractValElem() {}

	virtual ValPtr Get() const { return nullptr; }
	};

template <class T>
class CPP_ValElem : public CPP_AbstractValElem
	{
public:
	CPP_ValElem(std::vector<T>& _vec, int _offset)
		: vec(_vec), offset(_offset) { }

	ValPtr Get() const override
		{ return offset >= 0 ? vec[offset] : nullptr; }

private:
	std::vector<T>& vec;
	int offset;
	};

class CPP_ListConst : public CPP_Global<ListValPtr>
	{
public:
	CPP_ListConst(std::vector<CPP_AbstractValElem> _vals)
		: vals(std::move(_vals)) { }

	ListValPtr Generate() const override;

private:
	std::vector<CPP_AbstractValElem> vals;
	};

class CPP_VectorConst : public CPP_Global<VectorValPtr>
	{
public:
	CPP_VectorConst(int type, std::vector<CPP_AbstractValElem> vals)
		: v_type(type), v_vals(std::move(vals)) { }

	VectorValPtr Generate() const override;

private:
	int v_type;
	std::vector<CPP_AbstractValElem> v_vals;
	};

class CPP_RecordConst : public CPP_Global<RecordValPtr>
	{
public:
	CPP_RecordConst(int type, std::vector<CPP_AbstractValElem> vals)
		: r_type(type), r_vals(std::move(vals)) { }

	RecordValPtr Generate() const override;

private:
	int r_type;
	std::vector<CPP_AbstractValElem> r_vals;
	};

class CPP_TableConst : public CPP_Global<TableValPtr>
	{
public:
	CPP_TableConst(int type, std::vector<CPP_AbstractValElem> indices, std::vector<CPP_AbstractValElem> vals)
		: t_type(type), t_indices(std::move(indices)), t_vals(std::move(vals)) { }

	TableValPtr Generate() const override;

private:
	int t_type;
	std::vector<CPP_AbstractValElem> t_indices;
	std::vector<CPP_AbstractValElem> t_vals;
	};

class CPP_FuncConst : public CPP_Global<FuncValPtr>
	{
public:
	CPP_FuncConst(const char* _name, int _type, std::vector<p_hash_type> _hashes)
		: name(_name), type(_type), hashes(std::move(_hashes)) { }

	FuncValPtr Generate() const override
		{ return lookup_func__CPP(name, hashes, CPP__Type__[type]); }

private:
	std::string name;
	int type;
	std::vector<p_hash_type> hashes;
	};


class CPP_AbstractAttrExpr
	{
public:
	CPP_AbstractAttrExpr() {}
	virtual ~CPP_AbstractAttrExpr() {}

	virtual ExprPtr Build() const { return nullptr; }
	};

class CPP_ConstAttrExpr : public CPP_AbstractAttrExpr
	{
public:
	CPP_ConstAttrExpr(CPP_AbstractValElem _v) : v(std::move(_v)) {}

	ExprPtr Build() const override
		{ return make_intrusive<ConstExpr>(v.Get()); }

private:
	CPP_AbstractValElem v;
	};

class CPP_NameAttrExpr : public CPP_AbstractAttrExpr
	{
public:
	CPP_NameAttrExpr(IDPtr& _id_addr) : id_addr(_id_addr) {}

	ExprPtr Build() const override
		{ return make_intrusive<NameExpr>(id_addr); }

private:
	IDPtr& id_addr;
	};

class CPP_RecordAttrExpr : public CPP_AbstractAttrExpr
	{
public:
	CPP_RecordAttrExpr(int _type) : type(_type) {}

	ExprPtr Build() const override;

private:
	int type;
	};

class CPP_CallAttrExpr : public CPP_AbstractAttrExpr
	{
public:
	CPP_CallAttrExpr(int _call) : call(_call) {}

	ExprPtr Build() const override { return CPP__CallExpr__[call]; }

private:
	int call;
	};

class CPP_Attr : public CPP_Global<AttrPtr>
	{
public:
	CPP_Attr(AttrTag t, CPP_AbstractAttrExpr _expr)
		: tag(t), expr(std::move(_expr)) { }

	AttrPtr Generate() const override
		{ return make_intrusive<Attr>(tag, expr.Build()); }

private:
	AttrTag tag;
	CPP_AbstractAttrExpr expr;
	};

class CPP_Attrs : public CPP_Global<AttributesPtr>
	{
public:
	CPP_Attrs(std::vector<int> _attrs)
		: attrs(std::move(_attrs)) { }

	AttributesPtr Generate() const override;

private:
	std::vector<int> attrs;
	};


class CPP_AbstractType : public CPP_Global<TypePtr>
	{
public:
	CPP_AbstractType() { }
	CPP_AbstractType(std::string _name) : name(std::move(_name)) { }

	TypePtr Generate(std::vector<TypePtr>& global_vec, int offset) const override
		{
		auto t = DoGenerate(global_vec, offset);
		if ( ! name.empty() )
			register_type__CPP(t, name);
		return t;
		}

protected:
	virtual TypePtr DoGenerate(std::vector<TypePtr>& global_vec, int offset) const
		{ return DoGenerate(global_vec); }
	virtual TypePtr DoGenerate(std::vector<TypePtr>& global_vec) const
		{ return DoGenerate(); }
	virtual TypePtr DoGenerate() const
		{ return nullptr; }

	std::string name;
	};

class CPP_BaseType : public CPP_AbstractType
	{
public:
	CPP_BaseType(TypeTag t)
		: CPP_AbstractType(), tag(t) { }

	TypePtr DoGenerate() const override
		{ return base_type(tag); }

private:
	TypeTag tag;
	};

class CPP_EnumType : public CPP_AbstractType
	{
public:
	CPP_EnumType(std::string _name, std::vector<std::string> _elems, std::vector<int> _vals)
		: CPP_AbstractType(_name), elems(std::move(_elems)), vals(std::move(_vals)) { }

	// TypePtr PreInit() const override { return get_enum_type__CPP(name); }
	TypePtr DoGenerate() const override;

private:
	std::vector<std::string> elems;
	std::vector<int> vals;
	};

class CPP_OpaqueType : public CPP_AbstractType
	{
public:
	CPP_OpaqueType(std::string _name) : CPP_AbstractType(_name) { }

	TypePtr DoGenerate() const override
		{ return make_intrusive<OpaqueType>(name); }
	};

class CPP_TypeType : public CPP_AbstractType
	{
public:
	CPP_TypeType(int _tt_offset)
		: CPP_AbstractType(), tt_offset(_tt_offset) { }

	TypePtr DoGenerate(std::vector<TypePtr>& global_vec) const override
		{ return make_intrusive<TypeType>(global_vec[tt_offset]); }

private:
	int tt_offset;
	};

class CPP_VectorType : public CPP_AbstractType
	{
public:
	CPP_VectorType(int _yt_offset)
		: CPP_AbstractType(), yt_offset(_yt_offset) { }

	TypePtr DoGenerate(std::vector<TypePtr>& global_vec) const override
		{ return make_intrusive<VectorType>(global_vec[yt_offset]); }

private:
	int yt_offset;
	};

class CPP_TypeList : public CPP_AbstractType
	{
public:
	CPP_TypeList(std::vector<int> _types)
		: CPP_AbstractType(), types(std::move(_types)) { }

	TypePtr PreInit() const override { return make_intrusive<TypeList>(); }
	TypePtr DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override
		{
		const auto& tl = cast_intrusive<TypeList>(global_vec[offset]);

		for ( auto t : types )
			tl->Append(global_vec[t]);

		return tl;
		}

private:
	std::vector<int> types;
	};

class CPP_TableType : public CPP_AbstractType
	{
public:
	CPP_TableType(int _indices, int _yield)
		: CPP_AbstractType(), indices(std::move(_indices)), yield(_yield) { }

	TypePtr DoGenerate(std::vector<TypePtr>& global_vec) const override;

private:
	int indices;
	int yield;
	};

class CPP_FuncType : public CPP_AbstractType
	{
public:
	CPP_FuncType(int _params, int _yield, FunctionFlavor _flavor)
		: CPP_AbstractType(), params(std::move(_params)), yield(_yield), flavor(_flavor) { }

	TypePtr DoGenerate(std::vector<TypePtr>& global_vec) const override;

private:
	int params;
	int yield;
	FunctionFlavor flavor;
	};

class CPP_RecordType : public CPP_AbstractType
	{
public:
	CPP_RecordType(std::vector<std::string> _field_names, std::vector<int> _field_types, std::vector<int> _field_attrs)
		: CPP_AbstractType(), field_names(std::move(_field_names)), field_types(_field_types), field_attrs(_field_attrs) { }

	TypePtr PreInit() const override;
	TypePtr DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override;

private:
	std::vector<std::string> field_names;
	std::vector<int> field_types;
	std::vector<int> field_attrs;
	};


class CPP_FieldMapping
	{
public:
	CPP_FieldMapping(int _rec, std::string _field_name, int _field_type, int _field_attrs)
		: rec(_rec), field_name(std::move(_field_name)), field_type(_field_type), field_attrs(_field_attrs)
		{ }

	int ComputeOffset() const;

private:
	int rec;
	std::string field_name;
	int field_type;
	int field_attrs;
	};


class CPP_EnumMapping
	{
public:
	CPP_EnumMapping(int _e_type, std::string _e_name)
		: e_type(_e_type), e_name(std::move(_e_name))
		{ }

	int ComputeOffset() const;

private:
	int e_type;
	std::string e_name;
	};


class CPP_RegisterBody
	{
public:
	CPP_RegisterBody(std::string _func_name, int _priority, p_hash_type _h, std::vector<std::string> _events)
		: func_name(std::move(_func_name)), priority(_priority), h(_h), events(std::move(_events))
		{ }
	virtual ~CPP_RegisterBody() { }

	virtual void Register() const { }

protected:
	std::string func_name;
	int priority;
	p_hash_type h;
	std::vector<std::string> events;
	};

template <class T>
class CPP_RegisterBodyT : public CPP_RegisterBody
	{
public:
	CPP_RegisterBodyT(std::string _func_name, int _priority, p_hash_type _h, std::vector<std::string> _events)
		: CPP_RegisterBody(_func_name, _priority, _h, _events)
		{ }

	void Register() const override
		{
		auto f = make_intrusive<T>(func_name.c_str());
		register_body__CPP(f, priority, h, events);
		}
	};

class CPP_LookupBiF
	{
public:
	CPP_LookupBiF(zeek::Func*& _bif_func, std::string _bif_name)
		: bif_func(_bif_func), bif_name(std::move(_bif_name))
		{ }

	void ResolveBiF() const { bif_func = lookup_bif__CPP(bif_name.c_str()); }

protected:
	zeek::Func*& bif_func;
	std::string bif_name;
	};

class CPP_GlobalInit
	{
public:
	CPP_GlobalInit(IDPtr& _global, const char* _name, int _type, int _attrs, CPP_AbstractValElem _val, bool _exported)
		: global(_global), name(_name), type(_type), attrs(_attrs), val(std::move(_val)), exported(_exported)
		{ }

	void Init() const;

protected:
	IDPtr& global;
	const char* name;
	int type;
	int attrs;
	CPP_AbstractValElem val;
	bool exported;
	};

class CPP_AbstractCallExprInit : CPP_Global<CallExprPtr>
	{
public:
	CPP_AbstractCallExprInit() {}
	};

template <class T>
class CPP_CallExprInit : CPP_AbstractCallExprInit
	{
public:
	CPP_CallExprInit(CallExprPtr& _e_var)
		: e_var(_e_var)
		{ }

	CallExprPtr Generate() const override
		{
		auto wrapper_class = make_intrusive<T>();
		auto func_val = make_intrusive<FuncVal>(wrapper_class);
		auto func_expr = make_intrusive<ConstExpr>(func_val);
		auto empty_args = make_intrusive<ListExpr>();

		e_var = make_intrusive<CallExpr>(func_expr, empty_args);
		return e_var;
		}

protected:
	CallExprPtr& e_var;
	};

class CPP_AbstractLambdaRegistration : CPP_Global<bool>
	{
public:
	bool Generate() const override { return false; }
	};

template <class T>
class CPP_LambdaRegistration : CPP_AbstractLambdaRegistration
	{
public:
	CPP_LambdaRegistration(const char* _name, int _func_type, p_hash_type _h, bool _has_captures)
		: name(_name), func_type(_func_type), h(_h), has_captures(_has_captures)
		{ }

	bool Generate() const override
		{
		auto l = make_intrusive<T>(name);
		auto& ft = CPP__Type__[func_type];
		register_lambda__CPP(l, h, name, ft, has_captures);
		return true;
		}

protected:
	const char* name;
	int func_type;
	p_hash_type h;
	bool has_captures;
	};


	} // zeek::detail