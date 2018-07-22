/*
 * ErrDocEP: Identify error propagation bugs.
 * Adapted from EPEx(https://github.com/yujokang/EPEx)
 */
#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <vector>
using namespace clang;
using namespace ento;
using namespace std;
/* placeholder value for wild-card parameter counts and bounds */
#define DONT_CARE -1
#define ERROR_SPEC_NAME "[error_spec.txt]"
#define TARGET_FUNCTION_ERROR_SPEC_NAME "[target_spec.txt]"
namespace {

struct SymState {
private:
	/* the name of the caller function */
	std::string func_name;
	/* the sequence of fallible functions encountered on the path */
	std::string error_func_names;
	/* the most recent, fallible function in the path */
	std::string lst_error_func_name;
public:
	/*
	 * InFuncName: the name of the caller function
	 * InErrFuncName: the sequence of fallible functions
	 *	encountered on the path
	 * InLstErrName: the most recent, fallible function in the path
	 */
	SymState(std::string InFuncName, std::string InErrFuncNames,
		 std::string InLstErrName) : func_name(InFuncName),
					     error_func_names(InErrFuncNames),
					     lst_error_func_name(InLstErrName)
	{
	}

	std::string getFuncName() const
	{
		return func_name;
	}

	std::string getErrorFuncNames() const
	{
		return error_func_names;
	}

	std::string getLstErrFuncName() const
	{
		return lst_error_func_name;
	}

	bool operator==(const SymState &X) const
	{
		return (func_name == X.func_name) &&
		       (error_func_names == X.error_func_names) &&
		       (lst_error_func_name == X.lst_error_func_name);
	}

	void Profile(llvm::FoldingSetNodeID &ID) const
	{
		ID.AddString(func_name);
		ID.AddString(error_func_names);
		ID.AddString(lst_error_func_name);
	}
};
class CallRef: public llvm::FoldingSetNode {
public:
    CallRef(string name):func_name(name),func_depth(0){}
    CallRef(string name, unsigned depth):func_name(name),func_depth(depth){}
    string func_name;
    unsigned func_depth;
    bool operator==(const CallRef &X) const
	{
		return func_name==X.func_name&&func_depth==X.func_depth;
	}
	bool operator<(const CallRef &X) const
	{
		if(func_name!=X.func_name){
			return func_name < X.func_name;
		}
		else{
			return func_depth < X.func_depth;
		}
	}
    void Profile(llvm::FoldingSetNodeID &ID) const
	{
		ID.AddString(func_name);
		ID.AddInteger(func_depth);		
	}

};
struct PathState {
private:
	/* the name of the caller function */
	std::string func_name;
	std::string target_func;
	unsigned func_depth;
	bool error_path;
	bool path_valid;
	
public:
	vector<string> path;
	/*
	 * InFuncName: the name of the caller function
	
	 */
	PathState(std::string InFuncName, unsigned depth) : func_name(InFuncName),func_depth(depth),
					     error_path(false),path_valid(true)
	{
		target_func = "";
	}

	PathState(std::string InFuncName) : func_name(InFuncName),func_depth(0),
					     error_path(false),path_valid(true)
	{
	}

	PathState(const PathState *ps)
	{
		vector<string> p = ps->path;
		for(size_t i = 0;i<p.size();i++){
			path.push_back(p[i]);
		}
		error_path = ps->isErrorPath();
		func_name = ps->getFuncName();
		func_depth = ps->getDepth();
		path_valid = ps->isValid();
		target_func = ps->getTargetFunc();
	}
	PathState(const PathState& ps)
	{
		vector<string> p = ps.path;
		for(size_t i = 0;i<p.size();i++){
			path.push_back(p[i]);
		}
		error_path = ps.isErrorPath();
		func_name = ps.getFuncName();
		func_depth = ps.getDepth();
		path_valid = ps.isValid();
		target_func = ps.getTargetFunc();
	}

	std::string getFuncName() const
	{
		return func_name;
	}

	std::string getTargetFunc() const
	{
		return target_func;
	}

	void setTargetFunc(std::string name)
	{
		target_func = name;
	}

	unsigned getDepth() const
	{
		return func_depth;
	}

	bool isErrorPath() const
	{
		return error_path;
	}
    void setError(){
    	error_path = true;
    }
    bool isValid() const{
    	return path_valid;
    }
    void setInvalid(){
    	path_valid = false;
    }

	bool operator==(const PathState &X) const
	{
		return (func_name==X.getFuncName()) && (target_func==X.getTargetFunc());
	}

	void Profile(llvm::FoldingSetNodeID &ID) const
	{
		ID.AddString(func_name);
		ID.AddString(target_func);
		ID.AddInteger(func_depth);
		ID.AddBoolean(error_path);
		ID.AddBoolean(path_valid);
		for(size_t i = 0;i<path.size();i++){
			ID.AddString(path[i]);
		}
	}
};

/* the error specification for a function, or all callers */
struct FuncErrSpec {
	/* the name of the function */
	std::string func_name;
	/* the number of parameters in the function signature */
	int nparameters;
	/*
	 * the position of the first bound,
	 * which is usually the lower bound when both are used
	 */
	int err_lbound;
	/* the comparator for the first, or lower bound */
	int err_lbound_op;
	/*
	 * the position of the second bound,
	 * which is usually the upper bound when both are used
	 */
	int err_ubound;
	/* the comparator for the second, or upper bound */
	int err_ubound_op;
	/* one of the supported return types */
	enum ReturnType {
		PTR_TYPE, /* a NULL or non-NULL pointer */
		INT_TYPE, /* ranges of integers */
		BOOL_TYPE /* the C++ bool type */
	} ret_type;
};

/* lookup table for functions' error specifications, mapped by the name */
struct FuncSpecs {
	/* the lookup data structure */
	mutable std::map<std::string, FuncErrSpec> specs_map;
public:
	/*
	 * Fetch the error specification for the given function.
	 * fname:	the name of the function
	 *		whose error specification is wanted
	 * returns	the error specification struct of the desired function
	 *		if it exists,
	 *		NULL otherwise
	 */
	FuncErrSpec *findSpec(StringRef fname) const
	{
		if (specs_map.count(fname) > 0) {
			return (&specs_map[fname]);
		} else {
			return NULL;
		}
	}

	/*
	 * Add the error specification for a function.
	 * name:	the name of the function
	 * np:		the number of parameters in the function
	 * lb:		the position of the first, or lower bound
	 * lob:		the comparator of the first, or lower bound
	 * ub:		the position of the second, or upper bound
	 * uob:		the comparator of the second, or upper bound
	 * ret:		the return value type
	 */
	bool addSpec(std::string name, unsigned int np, int lb, int lop,
		     int ub, int uop, FuncErrSpec::ReturnType ret) const
	{
		FuncErrSpec fes;

		fes.func_name = name;
		fes.nparameters = np;
		fes.err_lbound = lb;
		fes.err_lbound_op = lop;
		fes.err_ubound = ub;
		fes.err_ubound_op = uop;
		fes.ret_type = ret;

		specs_map[name] = fes;

		return true;  
	}
};

/* the error status of a path */
enum IsError {
	NOT_ERROR = -1, /* definitely no error */
	MAYBE_ERROR = 0, /* possibly an error */
	SURE_ERROR = 1 /* definitely an error */
};

/* the RPEx checker */
class ErrDocEP : public Checker<check::PreCall, check::PostCall,
			    check::PreStmt<ReturnStmt>>
{
	struct FuncSpecs fSpecs; /* the error specifications */
	struct FuncSpecs tSpecs; /* the error specifications for target functions*/
	/* the error logging functions */
	mutable std::map<std::string, int> loggers;
	/*
	 * Try to get the exact, integer value of an SVal.
	 * val:		the SVal whose integer we want to extract
	 * ret:		will store the integer value, if it exists
	 * returns	true iff this function stores an exact value in ret
	 */
	bool getConcreteValue(SVal val, int64_t *ret) const;
	/*
	 * Add a logging function.
	 * rest_line:	the part of the line after the logging function marker.
	 *		note that it may be changed to remove newlines
	 */
	void addLogger(char *rest_line);
	/*
	 * Make a single parsing pass, given a new line from the file
	 * buf:		newly-read line from the specification file
	 * returns	the number of error specifications parsed
	 */
	size_t parseOnce(char *buf, int option);
public:
	/*
	 * Load the configuration file,
	 * and divert the output to a randomly-named logging file.
	 */
	ErrDocEP();
	/*
	 * Print a single message line, with this checker's prefix.
	 * str:	the message to print
	 */
	void printMsg(std::string str) const;
	std::string getCaller(CheckerContext &C) const;
	unsigned getStackDepth(CheckerContext &C) const;


	/*
	 * Check if the path has become an error path
	 * after calling a fallible function.
	 */
	void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
	/*
	 * Check for exits and logging.
	 */
	void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
	/*
	 * Check for error propagation.
	 */
	void checkPreStmt(const ReturnStmt *S, CheckerContext &C) const;


	/*
	 * Check if the function returned an error value.
	 * isErrorPathOut:	the result output, which is NOT_ERROR by default
	 * name:		the name of the function whose return value
	 *			needs to be checked
	 * ret:			the return value
	 * ret_type:		the type of the return value
	 * C:			the checker context
	 * old_state:		the old checker state
	 * care_binary:		for binary return types
	 *			(NULL/non-NULL pointers and booleans),
	 *			do we care about having a specification
	 *			with the matching name and type?
	 * n_args:		the number of arguments to the function
	 * returns		the new state, if it changed, or NULL
	 */
	ProgramStateRef isError(enum IsError *isErrorPathOut, StringRef name,
				SVal ret, QualType ret_type, CheckerContext &C,
				ProgramStateRef old_state, bool care_binary,
				int n_args, int option=0) const;

};

} // end anonymous namespace

/* stack of error states of the path */

REGISTER_MAP_WITH_PROGRAMSTATE(PathMap, CallRef, PathState)
REGISTER_LIST_WITH_PROGRAMSTATE(AnalyzedFuncs, SymState)
/*
 * the suffix of the randomly-named output log,
 * so that they can be identified and gathered
 */
#define LOG_SUFFIX		".e.log"
#define LOG_SUFFIX_LEN		(strlen(LOG_SUFFIX) + 1)

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>

#define N_HEX_IN_BYTE		2
#define URANDOM_PATH		"/dev/urandom"

/*
 * Divert stderr to a randomly-named file.
 */

void divertToRandom_EP()
{
	int random_file = open(URANDOM_PATH, O_RDONLY);
	size_t fname_size;
	unsigned random_bytes;
	time_t creation_time;
	char *fname;

	/* Try using urandom. If that fails, use random. */
	if (random_file >= 0) {
		read(random_file, &random_bytes, sizeof(random_bytes));
		close(random_file);
	} else {
		srandom(time(NULL));
		random_bytes = random() % INT_MAX;
	}

	/* Ensure uniqueness by using time, too. */
	creation_time = time(NULL);

	fname_size = (sizeof(random_bytes) + sizeof(creation_time)) *
					     N_HEX_IN_BYTE + 1 +
		     LOG_SUFFIX_LEN;

	fname = (char *) alloca(fname_size);

	snprintf(fname, fname_size, "%08x_%016lx" LOG_SUFFIX, random_bytes,
		 creation_time);

	freopen(fname, "w", stderr);
}

void ErrDocEP::addLogger(char *rest_line)
{
	size_t real_end = strlen(rest_line) - 1;
	size_t effective_end = real_end;

	/* Remove the new line character at the end, if it's there. */
	if (rest_line[real_end] == '\n') {
		rest_line[real_end] = '\0';
		real_end--;
	}

	if (effective_end > 0) {
		loggers[rest_line] = 1;
	}
}

/* the prefix for logger function lines */
#define LOGGER_MARKER	'1'

/* delimiters between entries in the error spec lines */
static const char delimiters[] = ", \t";

/*
 * Parse bound information.
 * saveptr:	the parsing state
 * bound:	the bound position, which is not changed if it is not available
 * boundop:	the comparator, which is not changed if it is not available
 */
static void parseBound(char **saveptr, int *bound, int *boundop)
{
	char *tok;

	/* Parse the bound position. */
	tok = strtok_r(NULL, delimiters, saveptr);
	if (tok != NULL) {
		*bound = atoi(tok);
	}

	/* Parse the comparator. */
	tok = strtok_r(NULL, delimiters, saveptr);
	if (tok != NULL) {
		if (tok[0] == 'G' && tok[1] == 'T') {
			*boundop = BO_GT;
		} else if (tok[0] == 'G' && tok[1] == 'E') {
			*boundop = BO_GE;
		} else if (tok[0] == 'L' && tok[1] == 'T') {
			*boundop = BO_LT;
		} else if (tok[0] == 'L' && tok[1] == 'E') {
			*boundop = BO_LE;
		} else if (tok[0] == 'E' && tok[1] == 'Q') {
			*boundop = BO_EQ;
		} else if (tok[0] == 'N' && tok[1] == 'E') {
			*boundop = BO_NE;
		}
	}
}

size_t ErrDocEP::parseOnce(char *buf, int option=0)
{
	size_t count = 0;
	char *tok = NULL;
	char *func_name = NULL;
	int nargs = DONT_CARE, lbound = DONT_CARE, ubound = DONT_CARE;
	int lboundop = DONT_CARE, uboundop = DONT_CARE;
	FuncErrSpec::ReturnType ret_type = FuncErrSpec::INT_TYPE;
	char *saveptr;

	/* Process lines starting with the logger prefix. */
	if (buf[0] == LOGGER_MARKER) {
		addLogger(buf + 1);
		return 0;
	}

	/* Get the name. */
	tok = strtok_r(buf, delimiters, &saveptr);
	if (tok != NULL) {
		func_name = tok;
	}

	/* Get the number of parameters. */
	tok = strtok_r(NULL, delimiters, &saveptr);
	if (tok != NULL) {
		nargs = atoi(tok);
	}

	/* Get the two bounds. */
	parseBound(&saveptr, &lbound, &lboundop);
	parseBound(&saveptr, &ubound, &uboundop);

	/* Get the function return type. */
	tok = strtok_r(NULL, delimiters, &saveptr);
	if (tok != NULL) {
		switch(tok[0]) {
			case 'I':
			case 'i':
				ret_type = FuncErrSpec::INT_TYPE;
				break;
			case 'B':
			case 'b':
				ret_type = FuncErrSpec::BOOL_TYPE;
				break;
			case 'P':
			case 'p':
				ret_type = FuncErrSpec::PTR_TYPE;
				break;
			default:
				break;
		}
	}

	/* Count the function, if it is valid. */
	if ((func_name) && (func_name[0] != '\n')) {
		bool success = false;
		if (option==0){
			success = fSpecs.addSpec(func_name, nargs, lbound, lboundop,
					      ubound, uboundop, ret_type);
		}
		else if(option==1){
			success = tSpecs.addSpec(func_name, nargs, lbound, lboundop,
					      ubound, uboundop, ret_type);
		}
		assert(success);
		count++;
	}

	return count;
}



ErrDocEP::ErrDocEP()
{
	size_t count = 0;
    FILE *fp = fopen(ERROR_SPEC_NAME, "r");
    char buf[2048];

    /* Find and parse specification. */
    if (fp == NULL) {
       
            printMsg("ERROR: failed to "
                 "open error spec file " ERROR_SPEC_NAME ", "
                 "exiting..");
            exit(1);
        
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        count += parseOnce(buf,0);
    }

    fclose(fp);


    
    llvm::errs() << "Loaded " + std::to_string(count) +
            " error specs from " + ERROR_SPEC_NAME << "\n";

    count = 0;

    FILE *fp2 = fopen(TARGET_FUNCTION_ERROR_SPEC_NAME, "r");
    if (fp2 == NULL) {
        
            printMsg("ERROR: failed to "
                 "open error spec file " TARGET_FUNCTION_ERROR_SPEC_NAME ", "
                 "exiting..");
            exit(1);
        
    }
    else{
        while (fgets(buf, sizeof(buf), fp2) != NULL) {
            count += parseOnce(buf,1);
        }
    }
    fclose(fp2);
    //cout<<first_elements.size()<< "\n";
    //cout<<second_elements.size()<< "\n";
    llvm::errs() << "Loaded " + std::to_string(count) +
            " function pairs from " + TARGET_FUNCTION_ERROR_SPEC_NAME << "\n";


	
	/* Redirect output. */
	divertToRandom_EP();
}

std::string ErrDocEP::getCaller(CheckerContext &C) const
{
	const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
	return DC->getAsFunction()->getNameInfo().getAsString();
}

unsigned ErrDocEP::getStackDepth(CheckerContext &C) const
{
	unsigned stack_depth = 0;

	for (const LocationContext *LCtx = C.getLocationContext(); LCtx;
	     LCtx = LCtx->getParent()) {
		if (LCtx->getKind() ==
		    LocationContext::ContextKind::StackFrame) {
			stack_depth++;
		}
	}

	return stack_depth;
}

void ErrDocEP::checkPostCall(const CallEvent &Call, CheckerContext &C) const
{
	std::string last_err_call = "";
	ProgramStateRef state = C.getState(), new_state, error_state, noerror_state;
	SVal ret = Call.getReturnValue();

	const IdentifierInfo *id_info = Call.getCalleeIdentifier();

	if (!id_info) {
		return;
	}

	const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
	std::string caller = DC->getAsFunction()->getNameInfo().getAsString();

	
	QualType ResultType = DC->getAsFunction()->getReturnType();
	
	/* Make sure to return error for multiple calls to the same function. */
	AnalyzedFuncsTy funcs = state->get<AnalyzedFuncs>();
	if (!funcs.isEmpty()) {
		const SymState sstate = funcs.getHead();
		if (sstate.getLstErrFuncName() != id_info->getName()) {
			return;
		}
		last_err_call = sstate.getErrorFuncNames();
	}


	/*check whether the callee is a target function or a function to be analyzed in the error_spec.txt*/

	/* Get the name of the called function. */
	StringRef FName = id_info->getName();
	int option = 0;
	
	
	if (ResultType->isVoidType()) {
		return;
	}

	
	enum IsError isErrorPath,isErrorPath1;
	std::string loc = "";
	if (const Expr *call_expr = Call.getOriginExpr()) {
		loc = call_expr->getExprLoc()
			       .printToString(C.getSourceManager());
	}

	QualType ret_type = Call.getResultType();

	if(tSpecs.findSpec(FName) != NULL){
    	option = 1;
    }
    else if(fSpecs.findSpec(FName) != NULL) {
    	option = 0;
    }
    else return;



	/* Check if the function's return value makes the path an error path. */

	error_state = isError(&isErrorPath1, FName, ret, ret_type, C, state, true,
			    (int) Call.getNumArgs(),option);
	
	new_state = error_state;
	if (isErrorPath1 >= MAYBE_ERROR) {
		std::string line;
		if (new_state == NULL) {
			new_state = state;
			
		}
		else{
			
		}
		if (last_err_call == "") {
			line = loc + " " + FName.str();
		} else {
			new_state = new_state->remove<AnalyzedFuncs>();
			line = loc + last_err_call;
		}
		
		new_state =
		new_state->add<AnalyzedFuncs>(SymState(caller, line,
						       FName.str()));
		
		//StringRef name = Call.getCalleeIdentifier()->getName();
		unsigned depth = getStackDepth(C);
		string Callername = getCaller(C);
		if(!Callername.empty()){
			const PathState *ps = new_state->get<PathMap>(CallRef(Callername,depth-1));
	    	if(ps!=nullptr){
	    		PathState ps2 = PathState(ps);   	
	    		//if(is_error_spec)ps2.setError();
	    		//if (isErrorPath1 == SURE_ERROR && is_target_function)ps2.setInvalid();
	    		ps2.setError();
	    		ps2.setTargetFunc(FName.str());
	    		new_state = new_state->set<PathMap>(CallRef(Callername,depth-1), ps2);

	    		//C.addTransition(new_state);
	    	}
	
		}
		
	}

	if (new_state != NULL) {
		C.addTransition(new_state);
	}
}

bool ErrDocEP::getConcreteValue(SVal val, int64_t *ret) const
{
	Optional<loc::ConcreteInt> LV = val.getAs<loc::ConcreteInt>();
	Optional<nonloc::ConcreteInt> NV = val.getAs<nonloc::ConcreteInt>();

	if (LV) {
		*ret = LV->getValue().getExtValue();
		return true;
	}

	if (NV) {
		*ret = NV->getValue().getExtValue();
		return true;
	}

	return false;
}

void ErrDocEP::checkPreCall(const CallEvent &Call, CheckerContext &C) const
{
	if (Call.getCalleeIdentifier() == NULL) {
		return;
	}

	StringRef name = Call.getCalleeIdentifier()->getName();
	ProgramStateRef State = C.getState();
	if(State){
		unsigned depth = getStackDepth(C);
	    State = State->set<PathMap>(CallRef(name.str(),depth), PathState(name.str()));
	    C.addTransition(State);
	}
	
}

void ErrDocEP::printMsg(std::string str) const {
	llvm::errs() << "ErrDocEP: " << str << "\n";
}

void ErrDocEP::checkPreStmt(const ReturnStmt *ret_stmt, CheckerContext &C) const
{
	const Expr *ret_expr = ret_stmt->getRetValue();
	ProgramStateRef state = C.getState(), new_state;
	bool need_printing = true;
	std::string loc;
	SVal ret_val;
	QualType ret_type;
	const CallExpr *CE;
	const Decl *calleeDecl;
	const FunctionDecl *function;
	enum IsError isErrorPath;

	const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
	std::string caller = DC->getAsFunction()->getNameInfo().getAsString();

	AnalyzedFuncsTy analyzed_funcs = state->get<AnalyzedFuncs>();
	if (analyzed_funcs.isEmpty()) {
		return;
	}

	const SymState sstate = analyzed_funcs.getHead();
	if (sstate.getFuncName() != caller) {
		return;
	}

	if (!ret_expr) {
		goto cleanup;
	}

	ret_val = C.getState()->getSVal(ret_expr, C.getLocationContext());
	loc = ret_expr->getExprLoc().printToString(C.getSourceManager());

	/* Ignore wrapper functions */
	CE = dyn_cast<CallExpr>(ret_expr->IgnoreParens());
	if (CE && (calleeDecl = CE->getCalleeDecl()) &&
	    (function = calleeDecl->getAsFunction())) {
		std::string name = function->getNameInfo().getAsString();
		if (sstate.getErrorFuncNames().find(" " + name) != 
		    std::string::npos) {
			goto cleanup;
		}
	}

	/*
	 * Check integers according to the global specification,
	 * and for the binary types, the value corresponding to 0
	 * is considered error, even if there is no error specification
	 * for the caller.
	 */
	ret_type = DC->getAsFunction()->getReturnType();
	new_state = isError(&isErrorPath, "__RETURN_VAL__", ret_val, ret_type,
			    C, state, false, DONT_CARE);
	if (new_state != NULL) {
		state = new_state;
	}

	/* Check for NULL pointer derefences. */
	if (ret_type->isPointerType()) {
		DefinedOrUnknownSVal
		location = ret_val.castAs<DefinedOrUnknownSVal>();
		if (!location.getAs<Loc>()) {
			printMsg(loc + " " + caller +
				 " return=NULL_pointer_dereference");
			need_printing = false;
		}
	}

	if(isErrorPath == NOT_ERROR){
		
		if(state){
			unsigned depth = getStackDepth(C);
		    string Callername = getCaller(C);
		    if(!Callername.empty()){
		    	const PathState *ps = state->get<PathMap>(CallRef(Callername,depth-1));
		    	
		    	if(ps!=nullptr){
					if(ps->isErrorPath()){
						printMsg("EP bug: " + loc + " \"" + Callername + "\" returns non error when \""+ ps->getTargetFunc() + "\" fails.");
		    		}
		    	}
		    	
		    }
		    //C.addTransition(state);
		}
	}

cleanup:
	state = state->remove<AnalyzedFuncs>();
	//C.addTransition(state);
}


ProgramStateRef
ErrDocEP::isError(enum IsError *isErrorPathOut, StringRef name, SVal ret,
	      QualType ret_type, CheckerContext &C, ProgramStateRef old_state,
	      bool care_binary, int n_args, int option) const
{
	ProgramStateRef state = old_state;
	ConstraintManager &CM = C.getConstraintManager();
	enum IsError isErrorPath;
	ProgramStateRef error, noerror;
	FuncErrSpec *FES = (option==0?fSpecs.findSpec(name):tSpecs.findSpec(name));
	SVal lbound, ubound, tVal;

	*isErrorPathOut = NOT_ERROR;

	if (FES == NULL) {
		return NULL;
	}

	/* Just to be safe */
	if ((FES->nparameters != DONT_CARE) && (n_args != DONT_CARE) &&
	    (n_args != FES->nparameters)) {
		return NULL;
	}

	/* For integer, use specific error specification. */
	if (ret_type->isIntegerType()) {
		SValBuilder &SVB = C.getSValBuilder();
		Optional<DefinedSVal> TV;

		if (FES->ret_type != FuncErrSpec::INT_TYPE) {
			return NULL;
		}
		if (!ret.getAs<NonLoc>()) {
			return NULL;
		}

		/* Check first bound. */
		if (FES->err_lbound_op != DONT_CARE) {
			lbound = SVB.makeIntVal(FES->err_lbound, ret_type);
			tVal = SVB.evalBinOpNN(state, (BinaryOperator::Opcode)
						      FES->err_lbound_op,
					       ret.castAs<NonLoc>(),
					       lbound.castAs<NonLoc>(),
					       ret_type);

			TV = tVal.getAs<DefinedSVal>();
			std::tie(error, noerror) = CM.assumeDual(state, *TV);
			if (!error && noerror) {
				isErrorPath = NOT_ERROR;
			} else if (error && !noerror) {
				isErrorPath = SURE_ERROR;
			} else {
				/* Force error path. */
				isErrorPath = MAYBE_ERROR;
				state = error;
			}
		}

		/*
		 * Check second bound
		 * if there is still a chance of being an error.
		 */
		if ((isErrorPath >= MAYBE_ERROR) &&
		    (FES->err_ubound_op != DONT_CARE)) {
			ubound = SVB.makeIntVal(FES->err_ubound, ret_type);
			tVal = SVB.evalBinOpNN(state, (BinaryOperator::Opcode)
						      FES->err_ubound_op,
					       ret.castAs<NonLoc>(),
					       ubound.castAs<NonLoc>(),
					       ret_type);
			TV = tVal.getAs<DefinedSVal>();
			std::tie(error, noerror) = CM.assumeDual(state, *TV);
			if (!error && noerror) {
				isErrorPath = NOT_ERROR;
			} else if (error && noerror) {
				isErrorPath = MAYBE_ERROR;
				/*
				 * Bad hack to avoid a Clang bug:
				 * handle the overflow case
				 */
				if (FES->err_ubound < 0) {
					ProgramStateRef sane, insane;
					SVal one;

					one = SVB.makeIntVal(1, ret_type);
					tVal =
					SVB.evalBinOpNN(state, BO_LT,
							ret.castAs<NonLoc>(),
							one.castAs<NonLoc>(),
							ret_type);
					TV = tVal.getAs<DefinedSVal>();
					std::tie(sane, insane) =
					CM.assumeDual(state, *TV);
					if (!sane || insane) {
						isErrorPath = NOT_ERROR;
					}
				}
				if (isErrorPath == MAYBE_ERROR) {
					/* Force the error path. */
					state = error;
				}
			}
			/* No change if second bound must be true. */
		}
	} else {
		/* Check type of error spec only if we need to. */
		if (care_binary) {
			if (ret_type->isBooleanType()) {
				if (FES->ret_type != FuncErrSpec::BOOL_TYPE) {
					return NULL;
				}
			} else if (ret_type->isPointerType()) {
				if (FES->ret_type != FuncErrSpec::PTR_TYPE) {
					return NULL;
				}
			}
		}
		/* Check that we can still handle the type. */
		if (!(ret_type->isBooleanType() || ret_type->isPointerType())) {
			return NULL;
		}
		if (!ret.getAs<DefinedOrUnknownSVal>()) {
			return NULL;
		} else {
			/* 0 (NULL or false) is error. */
			std::tie(noerror, error) =
			state->assume(ret.castAs<DefinedOrUnknownSVal>());
			if (error && !noerror) {
				isErrorPath = SURE_ERROR;
			} else if (!error && noerror) {
				isErrorPath = NOT_ERROR;
			} else {
				isErrorPath = MAYBE_ERROR;
				/* Force the error path. */
				state = error;
			}
		}
	}

	*isErrorPathOut = isErrorPath;
	if (state == old_state) {
		return NULL;
	}
	return state;
}


/*
 * Perform standard Clang checker registration.
 */
void ento::registerErrDocEP(CheckerManager &mgr)
{
	mgr.registerChecker<ErrDocEP>();
}
