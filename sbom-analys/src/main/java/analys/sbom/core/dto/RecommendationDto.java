package analys.sbom.core.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RecommendationDto {

  String cveId;

  String priority;

  String primaryAction;

  String steps;

  String estimatedEffort;

  int slaDays;

  String rationale;

  String fixVersion;
}