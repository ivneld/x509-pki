package com.meteorkim.x509pki;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

//TODO : 설명 및 다음 단계
//
//
//   * CryptoService: 위 코드에는 실제 암호화 로직(키 생성, 인증서 서명 등)이 빠져있습니다. Bouncy Castle을 사용하는 CryptoService를 별도의 Spring @Service로 만들고, PkiService가 이를
//     호출하여 실제 인증서(X509Certificate)를 생성한 뒤, PEM으로 인코딩하여 Certificate 엔티티에 저장하는 흐름으로 가야 합니다.
//   * PkiService: 사용자의 요청을 받아 도메인 객체와 리포지토리, CryptoService를 조율하는 애플리케이션 서비스 계층이 필요합니다. 예를 들어 pkiService.createInitialCaChain() 메서드는
//     트랜잭션(@Transactional) 안에서 루트 CA와 하위 CA를 순차적으로 생성하고 저장하는 역할을 할 것입니다.
//   * 테스트: 이 구조는 단위 테스트(도메인 객체)와 통합 테스트(서비스 및 리포지토리)를 작성하기에 매우 용이합니다.
//
//
//  이 코드는 제안하신 아키텍처를 구체화한 훌륭한 출발점입니다. 이 구조를 기반으로 실제 암호화 로직과 서비스 계층을 채워나가시면 원하시는 시스템을 완성할 수 있을 것입니다.

@Slf4j
@Component
@Order(2) // 정책 초기화 이후 실행
@RequiredArgsConstructor
public class CaChainInitializer implements CommandLineRunner {

    private final CertificateRepository certificateRepository;
    // private final PkiService pkiService; // 이상적으로는 Service Layer를 통해 작업 위임

    private static final String ROOT_CA_ALIAS = "default-root-ca";
    private static final String SUB_CA_ALIAS = "default-sub-ca";

    @Override
    public void run(String... args) throws Exception {
        // 시스템에 루트 CA가 없는 경우에만 초기 체인 생성
        if (certificateRepository.findByTypeAndIssuerIsNull(CertificateType.ROOT_CA).isEmpty()) {
            log.info("No Root CA found. Initializing default CA chain...");
            // 여기에 pkiService.createInitialCaChain(ROOT_CA_ALIAS, SUB_CA_ALIAS) 와 같은
            // 서비스 메서드를 호출하는 코드가 위치하게 됩니다.
            // 이 예제에서는 개념을 설명하기 위해 직접적인 로직은 생략합니다.
            // 실제 구현에서는 CryptoService를 사용하여 인증서를 생성하고,
            // Certificate 객체를 만들어 Repository에 저장해야 합니다.
            log.info("CA Chain initialization logic would run here.");
        } else {
            log.info("Root CA already exists. Skipping CA chain initialization.");
        }
    }
}
