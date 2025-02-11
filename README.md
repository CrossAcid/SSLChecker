# SSLChecker

- 编译
```shell
mvn clean package
```

- 使用
```shell
java -jar target.jar xxx.com,xxx.net -o output_path
```
支持多域名同时检测

- 参数说明

| 参数           | 描述         |
| -------------- | ------------ |
| -o -output     | 输出位置     |
| -s -suggestion | 输出建议     |
| -h -help       | 输出使用帮助 |

- 输出示例

**检测域名: xxx.com**
**证书信息**
    通用名称: xxx.com
    颁发者: xxx
    启用SNI: 是
	弱密钥检测: 否
	加密算法: RSA 2048 bits
	签名算法: SHA256withRSA
	证书品牌: DigiCert
	证书类型: OV SSL
	开始时间: 2024-01-30
	结束时间: 2025-03-02
	吊销状态: 正常
	组织机构: xxx
	部门: xxx
	备用名称: -

**证书链信息:** 
Certificate 1: 
颁发给: 
颁发者: CN=DigiCert Secure Site Pro CN CA G3, O=DigiCert Inc, C=US
有效期: 2024-01-30 ~ 2025-03-02 剩余 18 天 
Certificate 2: 
颁发给: CN=DigiCert Secure Site Pro CN CA G3, O=DigiCert Inc, C=US
颁发者: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
有效期: 2020-03-13 ~ 2030-03-13 剩余 1856 天 
Certificate 3: 
颁发给: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
颁发者: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
有效期: 2006-11-10 ~ 2031-11-10 剩余 2462 天 

**协议与套件:**
  支持协议:
    SSLv3 not support
    TLSv1 support
    TLSv1.1 support
    TLSv1.2 support
    TLSv1.3 not support

  支持的加密套件:
    TLSv1: 
        TLS_RSA_WITH_AES_256_CBC_SHA WEAK
       ...
    TLSv1.1: 
        TLS_RSA_WITH_AES_256_CBC_SHA WEAK
        ...
    TLSv1.2: 
        TLS_RSA_WITH_AES_256_CBC_SHA WEAK
        ...


总结:
  是否符合ATS:true
  是否符合PCI DSS:false
  评级: 60 C

建议:

   - 启用TLSv1导致评分最高为B
   - 启用TLSv1.1导致评分最高为B
   - 启用TLSv1将导致PCI DSS不合规
   - 启用SSL_RSA_WITH_RC4_128_SHA导致评分最高为B(不推荐使用RC4)
   - 启用TLS_ECDHE_RSA_WITH_RC4_128_SHA导致评分最高为B(不推荐使用RC4)
   - ...

