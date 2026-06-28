package analys.sbom.core.dto;

import lombok.Builder;
import lombok.Data;
import lombok.Value;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Value
@Builder
public class FullAnalysisResponse {

  UUID id;
  String projectName;
  String sbomName;
  Instant createdAt;
  String status;
  Integer totalComponents;
  Integer vulnerableComponents;

  List<ComponentVulnerabilityDto> findings;
}


