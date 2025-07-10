package com.meteorkim.x509pki;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findByTypeAndIssuerIsNull(CertificateType certificateType);
}
