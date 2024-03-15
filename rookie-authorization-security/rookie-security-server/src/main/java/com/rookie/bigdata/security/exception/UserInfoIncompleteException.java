package com.rookie.bigdata.security.exception;

/**
 * @Classname UserInfoIncompleteException
 * @Description
 * @Author rookie
 * @Date 2023/3/14 15:45
 * @Version 1.0
 */
public class UserInfoIncompleteException extends RuntimeException {

    public UserInfoIncompleteException(String message) {
        super(message);
    }
}
