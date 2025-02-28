package com.crossacid;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Data
@NoArgsConstructor
public class CheckResult {

    // 通用名称
    private String certificateCommonName;

    // 颁发者名称
    private String certificateIssuerName;

    // 是否支持SNI
    private boolean supportSNIDesc;

    // 弱密钥
    private boolean weakCipherSuit = false;

    // 加密算法
    private String certificateEncryptionAlgorithm;

    // 签名算法
    private String certificateSigAlgName;

    // 证书品牌
    private String certificateBrand;

    // 证书类型
    private String certificateType;

    // 开始时间
    private String certificateStartTime;

    // 结束时间
    private String certificateEndTime;

    // 吊销状态
    private String certificateRevokedStatus;

    // 证书组织机构
    private String certificateOrganization;

    // 部门 Organizational unit
    private String certificateOU;

    // 备用名称 Subject Alternative Name
    private List<String> certificateSAN;

    // 支持的SSL协议
    private List<String> supportSSLProtocols = new ArrayList<>();

    // 证书链列表
    private Certificate[] certificateChainList;

    // 符合ATS规范
    private boolean isConformToATS;

    // 符合PCI DSS规范
    private boolean isConformToPCIDSS;

    // 证书是否过期
    private StringBuilder expiredInfo = new StringBuilder();

    /**
     * 输出证书链信息
     * @return 证书链信息
     */
    public String getCertificateChainInfo() {
        StringBuilder chainInfo = new StringBuilder();
        for (int i = 0; i < certificateChainList.length; i++) {
            if (certificateChainList[i] instanceof X509Certificate cert) {
                chainInfo.append("Certificate ").append(i + 1).append(": ").append("\n");
                chainInfo.append("颁发给: ").append(cert.getSubjectX500Principal()).append("\n");
                chainInfo.append("颁发者: ").append(cert.getIssuerX500Principal()).append("\n");
                long leftDays = TimeUnit.DAYS.convert(cert.getNotAfter().getTime() - new Date().getTime(), TimeUnit.MILLISECONDS);
                chainInfo.append("有效期: ")
                        .append(Utils.formatDate(cert.getNotBefore()))
                        .append(" ~ ")
                        .append(Utils.formatDate(cert.getNotAfter()))
                        .append(" 剩余 ")
                        .append(leftDays)
                        .append(" 天 ")
                        .append("\n");
                if (leftDays < 0) {
                    expiredInfo.append("  ").append("证书 ").append(i+1).append(" : ").append("证书过期，不可信").append("\n");
                }
            }
        }
        return chainInfo.toString();
    }

}
