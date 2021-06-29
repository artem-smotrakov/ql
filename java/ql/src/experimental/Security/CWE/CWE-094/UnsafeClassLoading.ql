/**
 * @name TBD
 * @description TBD
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/unsafe-class-loading
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class UnsafeClassLoadingConfig extends TaintTracking::Configuration {
  UnsafeClassLoadingConfig() { this = "UnsafeClassLoadingConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("java.lang", "ClassLoader", "defineClass")
    |
      ma.getArgument(1) = sink.asExpr()
    )
  }
  // override predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {}
}

from DataFlow::PathNode source, DataFlow::PathNode sink, UnsafeClassLoadingConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe class loading using $@.", source.getNode(), "remote input"
