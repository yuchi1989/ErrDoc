#include "ClangSACheckers.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/StmtObjC.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/Support/raw_ostream.h"
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <vector>

using namespace clang;
using namespace ento;
using namespace std;
namespace {

/* CallRef structure stores each function call information. */
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

/* PathState structure stores path information for each CallRef */
struct PathState {
private:
  /* the name of the caller function */
  std::string func_name;
  unsigned func_depth;
  bool error_path;
  
public:
  vector<string> path;
  /* InFuncName: the name of the caller function */
  PathState(std::string InFuncName, unsigned depth) : func_name(InFuncName),func_depth(depth),
               error_path(false){
  }

  PathState(std::string InFuncName) : func_name(InFuncName),func_depth(0),
               error_path(false){
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

  bool operator==(const PathState &X) const
  {
    return func_name==X.getFuncName();
  }

  void Profile(llvm::FoldingSetNodeID &ID) const
  {
    ID.AddString(func_name);
    ID.AddInteger(func_depth);
    ID.AddBoolean(error_path);
    for(size_t i = 0;i<path.size();i++){
      ID.AddString(path[i]);
    }
  }
};

class ErrDocAllPath : public Checker< check::PreCall,
                                   check::PostCall > {
public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  std::string getCaller(CheckerContext &C) const;
  unsigned getStackDepth(CheckerContext &C) const;

  void printMsg(std::string str) const;
};

}

/* It registers a map from CallRef to PathState. */
REGISTER_MAP_WITH_PROGRAMSTATE(PathMap, CallRef, PathState)

/* Add a function call to the currernt path */
void ErrDocAllPath::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (Call.getCalleeIdentifier() == NULL) {
    return;
  }
    
  StringRef name = Call.getCalleeIdentifier()->getName();
  ProgramStateRef State = C.getState();
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
      C.addTransition(State);
  }
}

void ErrDocAllPath::printMsg(std::string str) const {
  llvm::errs() << "ErrDoc: " << str << "\n";
}

/* get caller name*/
std::string ErrDocAllPath::getCaller(CheckerContext &C) const
{
  const clang::Decl *DC = C.getCurrentAnalysisDeclContext()->getDecl();
  return DC->getAsFunction()->getNameInfo().getAsString();
}

/* get call stack depth*/
unsigned ErrDocAllPath::getStackDepth(CheckerContext &C) const
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

/*Print a path*/
void ErrDocAllPath::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef state = C.getState();
  if(state){
    StringRef name = Call.getCalleeIdentifier()->getName();
    unsigned depth = getStackDepth(C);
    const PathState *ps = state->get<PathMap>(CallRef(name.str(),depth));
        
    if(ps!=nullptr){
      
      if(ps->path.size()>0){
        
        printMsg("Path in function " + Call.getCalleeIdentifier()->getName().str());
        for(size_t i = 0; i<ps->path.size();i++ ){
          printMsg("P: " + ps->path[i]);
        }
      }   
    }
  }
  


}

void ento::registerErrDocAllPath(CheckerManager &mgr) {
  mgr.registerChecker<ErrDocAllPath>();
}
