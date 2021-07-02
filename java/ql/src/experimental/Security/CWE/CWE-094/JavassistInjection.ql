/**
 * @name TBD
 * @description TBD
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/javassist-injectin
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class JavassistInjection extends TaintTracking::Configuration {
  JavassistInjection() { this = "JavassistInjection" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma, Method m | m = ma.getMethod() |
      m.getDeclaringType().getPackage().getName().indexOf("javassist") = 0 and
      m.hasName(["addCatch", "insertAfter", "insertAt", "insertBefore", "setBody", "make"]) and
      ma.getAnArgument() = sink.asExpr()
    )
  }
  // override predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {}
}

from DataFlow::PathNode source, DataFlow::PathNode sink, JavassistInjection conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Code injectin with Javassist using $@.", source.getNode(),
  "remote input"
