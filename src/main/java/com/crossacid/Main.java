package com.crossacid;

import org.apache.commons.cli.*;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {

    // 域名合规性检测
    private static final String DOMAIN_REGEX = "^(?!-)([A-Za-z0-9-]{1,63})(?<!-)(\\.[A-Za-z0-9-]{1,63})*$";

    public static void main(String[] args) {
        // 设置命令行参数
        Options options = new Options();
        options.addOption("o", "output", true, "Output file path");
        options.addOption("h", "help", false, "Print help message");
        options.addOption("s", "suggestion", false, "give suggestions");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

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
            String[] domains = cmd.getArgList().get(0).split(",");

            // 检测域名是否合规
            for (String domain : domains) {
                if (!isValidDomain(domain)) {
                    throw new ParseException("Error domain provided: " + domain);
                }
            }

            // 是否需要输出到文件中
            String outputPath = cmd.getOptionValue("o");
            boolean outputFlg = outputPath != null && !outputPath.isEmpty();
            // writer =

            // 是否需要给出建议
            boolean suggestions = cmd.hasOption("s");

            // 使用ExecutorService来执行并行任务
            ExecutorService executorService = Executors.newCachedThreadPool();

            // 初始化检测配置
            initConfigurations();

            // 对每个域名进行检测
            for (String domain : domains) {
                // 最终是否需要写入文件
                executorService.submit(() -> {
                    // 执行检测
                    SSLChecker sslChecker = new SSLChecker();
                    String result = sslChecker.run(domain, suggestions);
                    if (outputFlg) {
                        BufferedWriter finalWriter;
                        try {
                            finalWriter = new BufferedWriter(new FileWriter(outputPath +  "\\" +domain + ".txt"));
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
                        System.out.println(result);
                    }
                });
            }
            executorService.shutdown();
        } catch (ParseException e) {
            System.err.println(e.getMessage());
            formatter.printHelp("java -jar SSLChecker.jar example.com [opts]", options);
        }
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

        // 检查每个标签是否符合长度限制
        String[] labels = domain.split("\\.");
        for (String label : labels) {
            if (label.length() > 63) {
                System.err.println("Error label provided: " + label);
                return false;
            }
        }

        // 使用正则表达式验证
        return domain.matches(DOMAIN_REGEX);
    }

}