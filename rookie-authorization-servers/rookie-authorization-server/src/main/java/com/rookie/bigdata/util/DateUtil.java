package com.rookie.bigdata.util;

import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.regex.Pattern;

/**
 * @Class DateUtil
 * @Description
 * @Author rookie
 * @Date 2024/3/21 11:28
 * @Version 1.0
 */
public class DateUtil {
    public static final String DEFAULT_FORMAT = "yyyy-MM-dd HH:mm:ss";
    public static final String NOSECONDS_FORMAT = "yyyy-MM-dd HH:mm";
    /**
     * 日期转字符串
     *
     */
    public static String dateToString(Date date, String format){
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(getDateFormat(format));
        String dateStr = simpleDateFormat.format(date);
        return dateStr;
    }

    /**
     * 字符串转日期
     *
     */
    public static Date stringToDate(String dateStr){
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(getDateFormat(dateStr));
        Date date = null;
        try {
            date = simpleDateFormat.parse(dateStr);
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
        return date;
    }

    public static Date stringToDate(String dateStr, int hour) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(getDateFormat(dateStr));
        Date date = null;
        try {
            date = simpleDateFormat.parse(dateStr);
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.HOUR, hour);
        return calendar.getTime();
    }



    /**
     * 常规自动日期格式识别
     * @param str 时间字符串
     * @return Date
     * @author nayunhao
     */
    private static String getDateFormat(String str) {
        boolean year = false;
        Pattern pattern = Pattern.compile("^[-\\+]?[\\d]*$");
        if(pattern.matcher(str.substring(0, 4)).matches()) {
            year = true;
        }
        StringBuilder sb = new StringBuilder();
        int index = 0;
        if(!year) {
            if(str.contains("月") || str.contains("-") || str.contains("/")) {
                if(Character.isDigit(str.charAt(0))) {
                    index = 1;
                }
            }else {
                index = 3;
            }
        }
        boolean date = false;
        for (int i = 0; i < str.length(); i++) {
            char chr = str.charAt(i);
            if(Character.isDigit(chr)) {

            }else{
                date =true;
            }
        }
        if(date) {
            for (int i = 0; i < str.length(); i++) {
                char chr = str.charAt(i);
                if (Character.isDigit(chr)) {
                    if (index == 0) {
                        sb.append("y");
                    }
                    if (index == 1) {
                        sb.append("M");
                    }
                    if (index == 2) {
                        sb.append("d");
                    }
                    if (index == 3) {
                        sb.append("H");
                    }
                    if (index == 4) {
                        sb.append("m");
                    }
                    if (index == 5) {
                        sb.append("s");
                    }
                    if (index == 6) {
                        sb.append("S");
                    }
                } else {
                    if (i > 0) {
                        char lastChar = str.charAt(i - 1);
                        if (Character.isDigit(lastChar)) {
                            index++;
                        }
                    }
                    sb.append(chr);
                }
            }
        }
        else
        {
            if(str.length() == 8){
                return "yyyymmdd";
            }
            if(str.length() == 14)
            {
                return "YYYYMMDDhhmmss";
            }
            if(str.length() == 12)
            {
                return "YYYYMMDDhhmm";
            }
        }
        return sb.toString();
    }

    /**
     * 获取当前年份
     *
     * @return year
     * @author Suojianfei
     * @date 2019/08/21
     */
    public static int getCurrentDateYear() {
        Calendar currentCal = Calendar.getInstance();
        currentCal.setTime(new Date());
        return currentCal.get(Calendar.YEAR);
    }

    /**
     * 获取当前day
     *
     * @return year
     * @author Suojianfei
     * @date 2019/08/21
     */
    public static int getCurrentDay() {
        Calendar currentCal = Calendar.getInstance();
        currentCal.setTime(new Date());
        return currentCal.get(Calendar.DATE);
    }

    /**
     * 判断指定日期是否本年日期
     *
     * @param date 指定的日期
     * @return 判断结果
     * @author Suojianfei
     * @date 2019/08/21
     */
    public static boolean isCurrentYearDate(Date date) {
        if (date != null) {
            Calendar dateCal = Calendar.getInstance();
            dateCal.setTime(date);

            return DateUtil.getCurrentDateYear() == dateCal.get(Calendar.YEAR);
        }
        return false;
    }

    /**
     * 判断指定日期是否去年日期
     *
     * @param date 指定的日期
     * @return 判断结果
     * @author Suojianfei
     * @date 2019/08/21
     */
    public static boolean isLastYearDate(Date date) {
        if (date != null) {
            Calendar dateCal = Calendar.getInstance();
            dateCal.setTime(date);

            return DateUtil.getCurrentDateYear() == dateCal.get(Calendar.YEAR) + 1;
        }
        return false;
    }

    /**
     * 判断指定日期是否在本季度
     *
     * @param date 指定的日期
     * @return 判断结果
     * @author Suojianfei
     * @date 2019/10/23
     */
    public static boolean isCurrentQuarter(Date date) {
        if (date != null && DateUtil.isCurrentYearDate(date)) {
            Calendar nowCal = Calendar.getInstance();
            nowCal.setTime(new Date());

            int startMonth = ((int) nowCal.get(Calendar.MONTH) / 3) * 3;
            int endMonth = ((int) nowCal.get(Calendar.MONTH) / 3) * 3 + 2;

            Calendar dateCal = Calendar.getInstance();
            dateCal.setTime(date);

            return dateCal.get(Calendar.MONTH) >= startMonth && dateCal.get(Calendar.MONTH) <= endMonth;
        }
        return false;
    }

    /**
     * 日期的加减方法
     * 用于在当前的天或者小时或者分钟或者月份的基础上加上或者减去若干小时，分钟，日，月
     * @param currentDay 时间值
     * @param hour 小时数
     * @param iden 标识加（A）减（S）
     * @return 返回加上或者减去的那时间
     * @author carl
     */
    public static Date hourAddAndSub(Date currentDay,int hour,String iden) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(currentDay);
        if("S".equals(iden)){
            calendar.add(Calendar.HOUR_OF_DAY, -hour);
        }else if("A".equals(iden)){
            calendar.add(Calendar.HOUR_OF_DAY, hour);
        }else{
            calendar.add(Calendar.HOUR_OF_DAY, 0);
        }
        Date startDate = calendar.getTime();
        return startDate;
    }

    /**
     * 获取本月的总天数
     * @return
     */
    public static int getTotalDayOfCurrentMouth() {
        Calendar currentCal = Calendar.getInstance();
        return currentCal.getActualMaximum(Calendar.DATE);
    }

    //主要用于定时任务计算时间
    public static java.sql.Date getLimitDate(String dateTime){
        if (StringUtils.isEmpty(dateTime)){
            dateTime="12";
        }
        Integer num = Integer.valueOf(dateTime);
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -num);

        Date date = calendar.getTime();
        java.sql.Date deleteDate = new java.sql.Date(date.getTime());
        return deleteDate;
    }


    public static Date getDate(Date date, int day) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.DAY_OF_MONTH, day);
        return calendar.getTime();
    }

    public static Date getDate(Date date, int year,int day) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.YEAR, year);
        calendar.add(Calendar.DAY_OF_MONTH, day);
        return calendar.getTime();
    }

}
