package analys.sbom.core.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NormalizedComponent {

  private String name;
  private String version;
  private String purl;
  private String ecosystem;
}
