package analys.sbom.core.dto;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;
import java.util.UUID;

@Value
@Builder
public class AnalysisResponse {

  UUID id;
  String projectName;
  String sbomName;
  Instant createdAt;
  String status;
}