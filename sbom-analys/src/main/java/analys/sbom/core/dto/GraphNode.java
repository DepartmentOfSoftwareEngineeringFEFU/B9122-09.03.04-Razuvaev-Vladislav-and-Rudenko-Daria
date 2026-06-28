package analys.sbom.core.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Set;

@Data
@Builder
public class GraphNode {

  String bomRef;

  String displayName;

  int depth;
  boolean isDirect;

  Set<String> vulnerableCves;

  String maxSeverity;

  boolean vulnerable;

  List<String> childRefs;
}