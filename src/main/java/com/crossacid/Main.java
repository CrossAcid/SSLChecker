package com.crossacid;

import org.apache.commons.cli.*;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Security;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {

    // 域名合规性检测
    private static final String DOMAIN_REGEX = "^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$";

    public static void main(String[] args) throws InterruptedException {
        // 记录初始时间
        long startTime = System.currentTimeMillis();

        // 设置命令行参数
        Options options = new Options();
        options.addOption("o", "output", true, "Output file path");
        options.addOption("h", "help", false, "Print help message");
        options.addOption("s", "suggestion", false, "give suggestions");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        String[] domains = new String[0];
        boolean outputFlg = false;
        boolean suggestions = false;
        String outputPath = "";
        int taskCount;

        try {
            // 将参数转化为cmd进行解析
            CommandLine cmd = parser.parse(options, args);

            // 输出工具说明
            if (cmd.hasOption("h") || args.length == 0) {
                formatter.printHelp("java -jar SSLChecker.jar example.com [opts]", options);
                return;
            }

            // 没有提供域名
            if (cmd.getArgList().isEmpty()) {
                throw new ParseException("No domain names provided.");
            }

            // 获取域名
            domains = cmd.getArgList().get(0).split(",");

            // 是否需要输出到文件中
            outputPath = cmd.getOptionValue("o");
            outputFlg = outputPath != null && !outputPath.isEmpty();

            // 是否需要给出建议
            suggestions = cmd.hasOption("s");
        } catch (ParseException e) {
            System.err.println(e.getMessage());
            formatter.printHelp("java -jar SSLChecker.jar example.com [opts]", options);
        }

        // 去重
        Set<String> uniqueDomains = new HashSet<>(Arrays.asList(domains));
        domains = uniqueDomains.toArray(new String[0]);

        // 存储无效域名
        List<String> invalidDomains = new ArrayList<>();

        // 检测域名是否合规
        List<String> validDomains = new ArrayList<>();
        for (String domain : domains) {
            if (isValidDomain(domain)) {
                validDomains.add(domain);
            } else {
                invalidDomains.add(domain);
            }
        }

        // 只保留有效的域名
        domains = validDomains.toArray(new String[0]);
        taskCount = domains.length;

        // 如果有无效的域名，统一抛出异常
        if (!invalidDomains.isEmpty()) {
            System.err.println("Warning: Some domains are invalid and will be skipped: " + invalidDomains);
        }

        if (taskCount == 0) {
            return;
        }

        // 使用ExecutorService来执行并行任务
        ExecutorService executorService = Executors.newFixedThreadPool(taskCount);
        CountDownLatch latch = new CountDownLatch(taskCount);

        // 初始化检测配置
        initConfigurations();

        // 对每个域名进行检测
        for (String domain : domains) {
            // 最终是否需要写入文件
            boolean finalSuggestions = suggestions;
            boolean finalOutputFlg = outputFlg;
            String finalOutputPath = outputPath;
            executorService.execute(() -> {
                try {
                    // 执行检测
                    SSLChecker sslChecker = new SSLChecker();
                    String domainPart;
                    String portPart = "443";
                    int colonIndex = domain.lastIndexOf(':');
                    if (colonIndex != -1) {
                        domainPart = domain.substring(0, colonIndex);
                        portPart = domain.substring(colonIndex + 1);
                    } else {
                        domainPart = domain;
                    }
                    String result = sslChecker.check(domainPart, Integer.parseInt(portPart), finalSuggestions);
                    if (finalOutputFlg) {
                        BufferedWriter finalWriter;
                        try {
                            finalWriter = new BufferedWriter(new FileWriter(finalOutputPath +  "\\" + domainPart + "-" + portPart + ".txt"));
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }

                        try {
                            assert result != null;
                            finalWriter.write(result);
                            finalWriter.newLine();
                            finalWriter.close();
                        } catch (IOException e) {
                            System.err.println("Error writing to file: " + e.getMessage());
                        }
                    } else {
                        int totalLength = 80;
                        int equalSignLength = (totalLength - domainPart.length()) / 2;
                        System.out.println(domainPart + "检测完成");
                        System.out.println("=".repeat(equalSignLength) + domainPart + "=".repeat(equalSignLength));
                        System.out.println(result);
                        System.out.println("=".repeat(totalLength));
                    }
                } finally {
                    latch.countDown();
                }

            });
        }

        // 等待所有任务完成
        latch.await();

        // 记录结束时间和内存占用
        long endTime = System.currentTimeMillis();

        // 计算总运行时间和内存占用
        long totalTime = endTime - startTime;

        System.out.println("总运行时间: " + totalTime + " 毫秒");

        executorService.shutdown();
    }

    /**
     *
     * @description 设置初始检测参数
     */
    private static void initConfigurations() {
        // 由于系统默认禁用SSLv3，TLSv1，TLSv1.1，如果不做设置将无法测试SSLv3，TLSv1，TLSv1.1,TLSv1.3
        System.setProperty("jdk.tls.disabledAlgorithms", "");
        Security.setProperty("jdk.tls.disabledAlgorithms", "");
        System.setProperty("jdk.disabled.namedCurves", "");
        Security.setProperty("jdk.security.legacyAlgorithms", "");
        Security.setProperty("crypto.policy", "unlimited");
        System.setProperty("jdk.sunec.disableNative", "false");
    }

    /**
     *
     * @param domain: 待检测域名
     * @return boolean 是否合法
     * @description 检测域名是否合法
     */
    private static boolean isValidDomain(String domain) {
        if (domain == null || domain.length() > 255) {
            System.err.println("Error domain names provided: " + domain);
            return false;
        }

        // 分离域名和端口号
        String domainPart;
        String portPart = null;
        int colonIndex = domain.lastIndexOf(':');
        if (colonIndex != -1) {
            domainPart = domain.substring(0, colonIndex);
            portPart = domain.substring(colonIndex + 1);
        } else {
            domainPart = domain;
        }

        // 检查每个标签是否符合长度限制
        String[] labels = domainPart.split("\\.");
        for (String label : labels) {
            if (label.length() > 63) {
                System.err.println("Error label provided: " + label);
                return false;
            }
        }

        // 使用正则表达式验证域名部分
        if (!domainPart.matches(DOMAIN_REGEX)) {
            System.err.println("Invalid domain format: " + domainPart);
            return false;
        }

        // 如果有端口号，检查端口号的合法性
        if (portPart != null) {
            try {
                int port = Integer.parseInt(portPart);
                if (port < 1 || port > 65535) {
                    System.err.println("Invalid port number: " + port);
                    return false;
                }
            } catch (NumberFormatException e) {
                System.err.println("Port is not a valid number: " + portPart);
                return false;
            }
        }
        return true;
    }
}