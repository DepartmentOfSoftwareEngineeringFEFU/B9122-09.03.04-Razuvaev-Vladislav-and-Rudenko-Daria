package analys.sbom.core.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "analysis")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalysisEntity {

  @Id
  @GeneratedValue
  private UUID id;

  @Column(name = "project_name")
  private String projectName;

  @Column(name = "sbom_name")
  private String sbomName;

  @Column(name = "created_at")
  private Instant createdAt;

  @Column(name = "status")
  private String status;

  @Column(name = "total_components")
  private Integer totalComponents;

  @Column(name = "vulnerable_components")
  private Integer vulnerableComponents;
}