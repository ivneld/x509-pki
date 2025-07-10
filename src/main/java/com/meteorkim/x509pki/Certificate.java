package com.meteorkim.x509pki;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Certificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String alias;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType type;

    @Column(nullable = false, length = 512)
    private String subjectDn;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id")
    private Certificate issuer; // Self-referencing for chain

    @Lob // Large Object for storing PEM data
    @Column(nullable = false)
    private String pemEncoded;

    public Certificate(String alias, CertificateType type, String subjectDn, Certificate issuer, String pemEncoded) {
        this.alias = alias;
        this.type = type;
        this.subjectDn = subjectDn;
        this.issuer = issuer;
        this.pemEncoded = pemEncoded;
        validate();
    }

    /**
     * 인증서 자체의 유효성을 검증하는 비즈니스 로직
     */
    private void validate() {
        if (isRoot() && type != CertificateType.ROOT_CA) {
            throw new IllegalStateException("A certificate with no issuer must be a ROOT_CA.");
        }
        if (!isRoot() && type == CertificateType.ROOT_CA) {
            throw new IllegalStateException("A ROOT_CA must not have an issuer.");
        }
    }

    public boolean isRoot() {
        return this.issuer == null;
    }

    public boolean isCa() {
        return this.type == CertificateType.ROOT_CA || this.type == CertificateType.SUBORDINATE_CA;
    }

    /**
     * 이 인증서를 발급자로 하여 하위 인증서를 발급하는 로직 (개념 예시)
     * 실제 Bouncy Castle 로직은 CryptoService에 위임하고, 여기서는 도메인 규칙을 검증합니다.
     * @return 새로 생성된 하위 Certificate 객체 (아직 저장되지 않음)
     */
    public Certificate issueSubordinate(
        String childAlias,
        String childSubjectDn,
        CertificatePolicy childPolicy,
        String childPem) {
        if (!this.isCa()) {
            throw new IllegalStateException("Cannot issue a certificate from a non-CA certificate.");
        }
        // pathLenConstraint 검증 등 추가적인 비즈니스 로직이 위치할 수 있음
        return new Certificate(childAlias, childPolicy.getType(), childSubjectDn, this, childPem);
    }
}
