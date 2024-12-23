package com.crossacid;

import java.text.SimpleDateFormat;
import java.util.Date;

public class CertificateUtils {

    public static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

    public static String formatDate(Date date) {
        return sdf.format(date);
    }
}
