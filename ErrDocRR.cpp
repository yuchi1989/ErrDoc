/*
 * The Clang checker implementation of RPEx.
 */
#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <algorithm>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <sstream>
using namespace clang;
using namespace ento;
using namespace std;
/* placeholder value for wild-card parameter counts and bounds */
#define DONT_CARE -1
#define ERROR_SPEC_NAME "/home/tyc/clang/work/example11/rpex/workflow/test/error_spec.txt"
#define FUNCTION_PAIRS_SPEC "/home/tyc/clang/work/example11/rpex/workflow/test/function_pairs_spec.txt"

namespace {


struct StreamState {
	enum Kind { Opened, Closed } K;
	std::string info; // filename:caller:funcname:linenumber:returnsymbol:argu1:argu2:argu3......
	StreamState(Kind InK, StringRef Info) : K(InK), info(Info) { }
	StreamState(Kind InK) : K(InK) {
		info = "";
	}
	bool operator==(const StreamState &X) const {
		return K == X.K && info == X.info;
	}
	void Profile(llvm::FoldingSetNodeID &ID) const {
		ID.AddInteger(K);
		ID.AddString(info);
	}
	std::string getInfo() const {return info;}
	bool isOpened() const { return K == Opened; }
	bool isClosed() const { return K == Closed; }
	static StreamState getOpened() { return StreamState(Opened); }
	static StreamState getClosed() { return StreamState(Closed); }
	static StreamState getOpened(std::string info) { return StreamState(Opened, info); }
	static StreamState getClosed(std::string info) { return StreamState(Closed, info); }
};

class PSymbolRef: public llvm::FoldingSetNode {
public:
	StringRef func_name;
	SymbolRef argsymbol;
	string first_element;
	string second_element;
	PSymbolRef(){}
	PSymbolRef(StringRef left_pair_name, SymbolRef symbol):func_name(left_pair_name), argsymbol(symbol){}
	
	bool operator==(const PSymbolRef &X) const
	{
		return func_name == X.func_name && argsymbol == X.argsymbol;
	}
	bool operator<(const PSymbolRef &X) const
	{
		if(!(argsymbol==X.argsymbol)) return argsymbol<X.argsymbol;
		else return func_name<X.func_name;
	}
    void Profile(llvm::FoldingSetNodeID &ID) const
	{
		ID.AddString(func_name);
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
	}

	std::string getFuncName() const
	{
		return func_name;
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
		return func_name==X.getFuncName();
	}

	void Profile(llvm::FoldingSetNodeID &ID) const
	{
		ID.AddString(func_name);
		ID.AddInteger(func_depth);
		ID.AddBoolean(error_path);
		ID.AddBoolean(path_valid);
		for(size_t i = 0;i<path.size();i++){
			ID.AddString(path[i]);
		}
	}
};

/* the state of the explored path */
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

/* the ErrDocRR checker */
class ErrDocRR : public Checker<check::PreCall, check::PostCall, check::EndFunction,
			    check::PreStmt<ReturnStmt>, check::DeadSymbols >
{
	struct FuncSpecs fSpecs; /* the error specifications */
	struct FuncSpecs tSpecs; /* the error specifications for target functions*/
	vector<string> first_elements;
	vector<string> second_elements;
	vector<unsigned> first_loc;
	vector<unsigned> second_loc;

	/*
	 * Try to get the exact, integer value of an SVal.
	 * val:		the SVal whose integer we want to extract
	 * ret:		will store the integer value, if it exists
	 * returns	true iff this function stores an exact value in ret
	 */
	bool getConcreteValue(SVal val, int64_t *ret) const;

	/*
	 * Make a single parsing pass, given a new line from the file
	 * buf:		newly-read line from the specification file
	 * returns	the number of error specifications parsed
	 */
	size_t parseOnce(char *buf, int option);
	size_t parsePairs(char *buf);
	void trim(string& s);
public:
	/*
	 * Load the configuration file,
	 * and divert the output to a randomly-named logging file.
	 */
	ErrDocRR();
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
	 * Perform sanity check for if there are still any unchecked states
	 * in the caller function.
	 */
	void checkEndFunction(CheckerContext &C) const;

	void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;

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
				int n_args, int option = 0) const;

};

} // end anonymous namespace

/* stack of error states of the path */

REGISTER_MAP_WITH_PROGRAMSTATE(PathMap, CallRef, PathState)
REGISTER_LIST_WITH_PROGRAMSTATE(AnalyzedFuncs, SymState)
REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, PSymbolRef, StreamState)

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

void divertToRandom_RR()
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

size_t ErrDocRR::parseOnce(char *buf, int option=0)
{
	size_t count = 0;
	char *tok = NULL;
	char *func_name = NULL;
	int nargs = DONT_CARE, lbound = DONT_CARE, ubound = DONT_CARE;
	int lboundop = DONT_CARE, uboundop = DONT_CARE;
	FuncErrSpec::ReturnType ret_type = FuncErrSpec::INT_TYPE;
	char *saveptr;

	

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
void ErrDocRR::trim(string& s)
{
	size_t p = s.find_first_not_of(" \t\n");
	s.erase(0, p);

	p = s.find_last_not_of(" \t\n");
	if (string::npos != p)
	s.erase(p+1);
}
size_t ErrDocRR::parsePairs(char *buf){
	char *saveptr;
	char *tok = NULL;
	string first_element_name, second_element_name;
	unsigned loc1;
	unsigned loc2;
	tok = strtok_r(buf, delimiters, &saveptr);
	if (tok != NULL) {
		string temp = string(tok);
		trim(temp);
		first_element_name = temp;
		//first_elements.push_back(temp);
	}
	tok = strtok_r(NULL, delimiters, &saveptr);
	if (tok != NULL) {
		string temp = string(tok);
		trim(temp);
		loc1 = std::stoul(temp);
	}

	tok = strtok_r(NULL, delimiters, &saveptr);
	if (tok != NULL) {
		string temp = string(tok);
		trim(temp);
		second_element_name = temp;
		//second_elements.push_back(temp);
	}
	tok = strtok_r(NULL, delimiters, &saveptr);
	if (tok != NULL) {
		string temp = string(tok);
		trim(temp);
		loc2 = std::stoul(temp);
	}
	/*
	bool processedflag = false;
	for (unsigned i = 0; i< first_elements.size(); i++){
		if (first_elements[i] == first_element_name && second_elements[i] == second_element_name){
			processedflag = true;
			break;
		}
	}*/
	//if(processedflag)return 0;
	first_elements.push_back(first_element_name);
	second_elements.push_back(second_element_name);
	first_loc.push_back(loc1);
	second_loc.push_back(loc2);
	return 1;
}



ErrDocRR::ErrDocRR()
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

    FILE *fp2 = fopen(FUNCTION_PAIRS_SPEC, "r");
    if (fp2 == NULL) {
        
            printMsg("ERROR: failed to "
                 "open error spec file " FUNCTION_PAIRS_SPEC ", "
                 "exiting..");
            exit(1);
        
    }
    else{
        while (fgets(buf, sizeof(buf), fp2) != NULL) {
            count += parsePairs(buf);
        }
    }
    fclose(fp2);
    //cout<<first_elements.size()<< "\n";
    //cout<<second_elements.size()<< "\n";
    llvm::errs() << "Loaded " + std::to_string(count) +
            " function pairs from " + FUNCTION_PAIRS_SPEC << "\n";

    /* Redirect output. */
    divertToRandom_RR();
}

std::string ErrDocRR::getCaller(CheckerContext &C) const
{
	const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
	return DC->getAsFunction()->getNameInfo().getAsString();
}

unsigned ErrDocRR::getStackDepth(CheckerContext &C) const
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

void ErrDocRR::checkPostCall(const CallEvent &Call, CheckerContext &C) const
{
	std::string last_err_call = "";
	ProgramStateRef state = C.getState(), new_state, error_state, noerror_state;
	//SVal ret = Call.getReturnValue();
	if (Call.getCalleeIdentifier() == NULL) {
		return;
	}

	const IdentifierInfo *id_info = Call.getCalleeIdentifier();

	if (!id_info) {
		return;
	}

	const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
	std::string caller = DC->getAsFunction()->getNameInfo().getAsString();
	
	
	
	if(state){
		StringRef name = Call.getCalleeIdentifier()->getName();
		unsigned depth = getStackDepth(C);
		const PathState *ps = state->get<PathMap>(CallRef(name.str(),depth));
		if(ps!=nullptr){			
			if(ps->isErrorPath() && ps->isValid()){
				if(ps->path.size()>0){
					printMsg("Error Path in function " + Call.getCalleeIdentifier()->getName().str());
					const FunctionDecl *func = static_cast<const FunctionDecl*>(Call.getRuntimeDefinition().getDecl());
					if (func){
						clang::FullSourceLoc fullLoc(func->getNameInfo().getBeginLoc(), C.getSourceManager());
	        			std::string fileName = C.getSourceManager().getFilename(fullLoc);
	        			//printMsg("name: " + func->getQualifiedNameAsString());
	        			printMsg("C: " + Call.getCalleeIdentifier()->getName().str());
	        			printMsg("F: " + fileName);
					}
					
					for(size_t i = 0; i<ps->path.size();i++ ){
						printMsg("P: " + ps->path[i]);
					}
				}
			}
			state = state->remove<PathMap>(CallRef(name.str(),depth));		
		}

	}
	std::string filename;
	std::string linenumber;
	
	SourceLocation callloc = Call.getOriginExpr()->getExprLoc();
	if( callloc.isMacroID() ) {
        // Get the start/end expansion locations
        std::pair< SourceLocation, SourceLocation > expansionRange = 
                 C.getSourceManager().getImmediateExpansionRange( callloc );
       
        callloc = expansionRange.first;
    }
	FullSourceLoc FullLocation(callloc, C.getSourceManager());
	if (FullLocation.isValid()){
		filename = C.getSourceManager().getFilename(FullLocation);
		linenumber = std::to_string(FullLocation.getSpellingLineNumber());
	}
	else{
		filename="";
		linenumber="";
	}		
	
	
	StringRef name = Call.getCalleeIdentifier()->getName();
	string Info = filename + ":" + caller + ":" + name.str() + ":" + linenumber;
	SymbolRef symbol = NULL;
	/*function pairs signature identification*/
	if(state){
		bool flag = true;
		for (unsigned i = 0;i<first_elements.size();i++){
			
			if (name.str()!=first_elements[i]){continue;}

			 // Get the symbolic value corresponding to the file handle.
			
			
			if(first_loc[i]==0){
				if(flag){
					SymbolRef ReturnValue = Call.getReturnValue().getAsSymbol();
					
					if(ReturnValue){
						symbol = ReturnValue;
						flag = false;
						
					}
				}
				
				Info = Info + ":" + "0" + ":" + second_elements[i] + ":" + std::to_string(second_loc[i]);
			}
			else if (first_loc[i]>0 &&first_loc[i]<=Call.getNumArgs()){
				if(flag){
					SymbolRef argsymbol = Call.getArgSVal(first_loc[i]-1).getAsSymbol();
					if(argsymbol){
						symbol = argsymbol;
						flag = false;
					}
				}
				Info = Info + ":" + std::to_string(i) + ":" + second_elements[i] + ":" + std::to_string(second_loc[i]);
				
			}

		}	
		if(!flag){state = state->set<StreamMap>(PSymbolRef(name,symbol), StreamState::getOpened(Info));}
		C.addTransition(state);
	}

}

bool ErrDocRR::getConcreteValue(SVal val, int64_t *ret) const
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

//If there is a right-pair function call, then close the corresponding left-pair function call.
void ErrDocRR::checkPreCall(const CallEvent &Call, CheckerContext &C) const
{
	if (Call.getCalleeIdentifier() == NULL) {
		return;
	}
	StringRef name = Call.getCalleeIdentifier()->getName();
	//printMsg("PreP: path, "+name.str());
	ProgramStateRef State = C.getState();
	if(State){		
		for (unsigned i = 0;i<second_elements.size();i++){
			if (name.str()!=second_elements[i])continue;
			unsigned k = Call.getNumArgs();
			if(second_loc[i]<=k){				
				SymbolRef argsymbol = Call.getArgSVal(second_loc[i]-1).getAsSymbol();
				if(argsymbol){
					const StreamState *SS = State->get<StreamMap>(PSymbolRef(first_elements[i],argsymbol));
					if (SS) {
						if(SS->isClosed()){
							const FunctionDecl *func = static_cast<const FunctionDecl*>(Call.getRuntimeDefinition().getDecl());
							if (func){
								clang::FullSourceLoc fullLoc(func->getNameInfo().getBeginLoc(), C.getSourceManager());
								std::string filename = C.getSourceManager().getFilename(fullLoc);
								string callername = getCaller(C);
								string calleename = Call.getCalleeIdentifier()->getName().str();
								printMsg("B: double close: " + callername + ", " + 
											calleename + ", " + filename + ", " + 
											first_elements[i] + ", " + second_elements[i]);
							}
							
						}
					}
					const StreamState *ss = State->get<StreamMap>(PSymbolRef(first_elements[i],argsymbol));
					if(ss){State = State->set<StreamMap>(PSymbolRef(first_elements[i],argsymbol), StreamState::getClosed(ss->getInfo()));}

				}		
			}	
		}
	}

	if(State){
		unsigned depth = getStackDepth(C);
	    State = State->set<PathMap>(CallRef(name.str(),depth), PathState(name.str()));
	    string Callername = getCaller(C);
	    if(!Callername.empty()){
	    	const PathState *ps = State->get<PathMap>(CallRef(Callername,depth-1));
	    	
	    	if(ps!=nullptr){
	    		PathState ps2 = PathState(ps);   	
	    		ps2.path.push_back(name.str());
	    		State = State->set<PathMap>(CallRef(Callername,depth-1), ps2);
	    	}
	    	
	    }
	}
	C.addTransition(State);
	/* Check exit and that its parameter is an error value. */
	if ((name == "exit") || (name == "_Exit") || (name == "_exit")) {
		const clang::Decl *
		caller_decl = C.getCurrentAnalysisDeclContext()->getDecl();
		std::string
		caller = caller_decl->getAsFunction()
				    ->getNameInfo().getAsString();
		ProgramStateRef state = C.getState();
		std::string loc = "";

		if (const Expr *call_expr = Call.getOriginExpr()) {
			loc = call_expr->getExprLoc()
				       .printToString(C.getSourceManager());
		}

		AnalyzedFuncsTy funcs = state->get<AnalyzedFuncs>();
		if (funcs.isEmpty()) {
			return;
		}

		const SymState sstate = funcs.getHead();
		if (sstate.getFuncName() != caller) {
			return;
		}

		int64_t ret;
		std::string return_status;
		if (getConcreteValue(Call.getArgSVal(0), &ret)) {
			if (ret == 0) {
				return_status = "noerror";
			} else {
				return_status = "error";
			}
		} else {
			return_status = "noerror_or_error";
		}

		if(state){
			unsigned depth = getStackDepth(C);
		    //state = state->set<PathMap>(CallRef(name.str(),depth), PathState(name.str()));
		    string Callername = getCaller(C);
		    if(!Callername.empty()){
		    	const PathState *ps = state->get<PathMap>(CallRef(Callername,depth-1));
		    	
		    	if(ps!=nullptr){
		    		PathState ps2 = PathState(ps);   	
		    		ps2.path.push_back(sstate.getErrorFuncNames() + " " + loc+ " " + caller + " Return=" + return_status);
		    		state = state->set<PathMap>(CallRef(Callername,depth-1), ps2);
		    	}
		    	
		    }
		    //C.addTransition(state);
		}

		printMsg(sstate.getErrorFuncNames() + " " + loc+ " " +
			 caller + " Return=" + return_status);

		state = state->remove<AnalyzedFuncs>();
		C.addTransition(state); 
	}
	
}

void ErrDocRR::printMsg(std::string str) const {
	llvm::errs() << "RPEx: " << str << "\n";
}

//Before returning, check each symbol. If the symbol is still open, then report bug.
//Check the return value to record if it returns error or non error.
void ErrDocRR::checkPreStmt(const ReturnStmt *ret_stmt, CheckerContext &C) const
{
	
	const Expr *ret_expr = ret_stmt->getRetValue();
	
	ProgramStateRef state = C.getState(), new_state;

	//Before returning, check each symbol. 
	StreamMapTy TrackedStreams = state->get<StreamMap>();
	for (StreamMapTy::iterator I = TrackedStreams.begin(),
		E = TrackedStreams.end(); I != E; ++I) {
		SymbolRef Sym = I->first.argsymbol;
		//bool IsSymDead = SymReaper.isDead(Sym);
		//if (IsSymDead){
			
			if(I->second.isOpened()){
				//unsigned depth = getStackDepth(C);
    			string Callername = getCaller(C);
				ConstraintManager &CMgr = state->getConstraintManager();
 				ConditionTruthVal OpenFailed = CMgr.isNull(state, Sym);
 				if(OpenFailed.isConstrainedTrue())continue;
				const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
				std::string callername = DC->getAsFunction()->getNameInfo().getAsString();
				const FunctionDecl *func = static_cast<const FunctionDecl*>(DC);
				if (func){
					clang::FullSourceLoc fullLoc(func->getNameInfo().getBeginLoc(), C.getSourceManager());
					std::string filename = C.getSourceManager().getFilename(fullLoc);
					
					printMsg("B: leaked: " + I->first.func_name.str()+ ":" + I->second.getInfo());

				}

			}
			//State = State->remove<StreamMap>(PSymbolRef(I->first.func_name,Sym));
		//}

	}



	//Check the return value to record if it returns error or non error.
	bool need_printing = true;
	std::string loc;
	SVal ret_val;
	QualType ret_type;
	//const CallExpr *CE;
	//const Decl *calleeDecl;
	//const FunctionDecl *function;
	enum IsError isErrorPath;

	const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
	std::string caller = DC->getAsFunction()->getNameInfo().getAsString();


	if (!ret_expr) {
		goto cleanup;
	}

	ret_val = C.getState()->getSVal(ret_expr, C.getLocationContext());
	loc = ret_expr->getExprLoc().printToString(C.getSourceManager());

	
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

	/* Print the error handling status. */
	//need_printing = true;
	if (need_printing) {
		std::string status = "";
		switch (isErrorPath) {
			case NOT_ERROR:
				status = "noerror";
				break;
			case MAYBE_ERROR:
				status = "noerror_or_error";
				break;
			case SURE_ERROR:
				status = "error";
				break;
			default:
				break;
		}


		if(state){
			unsigned depth = getStackDepth(C);

			string Callername = getCaller(C);
			if(!Callername.empty()){
				const PathState *ps = state->get<PathMap>(CallRef(Callername,depth-1));
				
				if(ps!=nullptr){
					PathState ps2 = PathState(ps);
					if (status.length() > 0) {
						ps2.path.push_back(" " + loc+ " " + caller + " Return=" + status);
					}
					state = state->set<PathMap>(CallRef(Callername,depth-1), ps2);
				}
				
			}
		}
		if (status.length() > 0) {
			printMsg("R: " + loc +
				 " " + caller + " Return=" + status);
		}
		need_printing = false;
	}

cleanup:
	state = state->remove<AnalyzedFuncs>();
	C.addTransition(state);
}

void ErrDocRR::checkEndFunction(CheckerContext &C) const
{
	const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
	std::string caller = DC->getAsFunction()->getNameInfo().getAsString();
	ProgramStateRef state = C.getState();

	AnalyzedFuncsTy funcs = state->get<AnalyzedFuncs>();
	if (funcs.isEmpty()) {
		return;
	}

	const SymState sstate = funcs.getHead();
	if (sstate.getFuncName() != caller) {
		return;
	}

	printMsg("!!You should not be here..returning from function: " +
		 caller);
	state = state->remove<AnalyzedFuncs>();
	C.addTransition(state); 
}


ProgramStateRef
ErrDocRR::isError(enum IsError *isErrorPathOut, StringRef name, SVal ret,
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




void ErrDocRR::checkDeadSymbols(SymbolReaper &SymReaper,  CheckerContext &C) const {
	ProgramStateRef State = C.getState();
	StreamMapTy TrackedStreams = State->get<StreamMap>();
	for (StreamMapTy::iterator I = TrackedStreams.begin(),
		E = TrackedStreams.end(); I != E; ++I) {
		SymbolRef Sym = I->first.argsymbol;
		bool IsSymDead = SymReaper.isDead(Sym);
		if (IsSymDead){
			
			if(I->second.isOpened()){
				//unsigned depth = getStackDepth(C);
    			string Callername = getCaller(C);
				ConstraintManager &CMgr = State->getConstraintManager();
 				ConditionTruthVal OpenFailed = CMgr.isNull(State, Sym);
 				
 				// if the dead symbol is NULL, then close this symbol.
 				if(OpenFailed.isConstrainedTrue()){
 					const StreamState *ss = State->get<StreamMap>(I->first);
					if(ss){State = State->set<StreamMap>(I->first, StreamState::getClosed(ss->getInfo()));}
 					continue;
 				}
 				/*
				const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
				std::string callername = DC->getAsFunction()->getNameInfo().getAsString();
				const FunctionDecl *func = static_cast<const FunctionDecl*>(DC);
				if (func){
					clang::FullSourceLoc fullLoc(func->getNameInfo().getBeginLoc(), C.getSourceManager());
					std::string filename = C.getSourceManager().getFilename(fullLoc);
					
					printMsg("B: leaked: " + I->first.func_name.str()+ ":" + I->second.getInfo());

				}*/

			}
			//State = State->remove<StreamMap>(PSymbolRef(I->first.func_name,Sym));
		}

	}
	C.addTransition(State);

}

/*
 * Perform standard Clang checker registration.
 */
void ento::registerErrDocRR(CheckerManager &mgr)
{
	mgr.registerChecker<ErrDocRR>();
}
