package analys.sbom.core.repository;

import analys.sbom.core.entity.AnalysisEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AnalysisRepository extends JpaRepository<AnalysisEntity, UUID> {

}