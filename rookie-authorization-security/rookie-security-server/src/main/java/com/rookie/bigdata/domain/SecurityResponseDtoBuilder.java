package com.rookie.bigdata.domain;

import com.rookie.bigdata.domain.dto.SecurityResponseDto;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * @Classname SecurityResponseDtoBuilder
 * @Description
 * @Author rookie
 * @Date 2023/3/14 16:03
 * @Version 1.0
 */
public final class SecurityResponseDtoBuilder {


    private static final Object EMPTY_DATA = new Object();

    /**
     * SecurityResponseDto#httpStatus
     */
    public HttpStatus httpStatus;

    /**
     * SecurityResponseDto#message
     */
    public String message;

    /**
     * SecurityResponse#timestamp
     */
    public LocalDateTime timestamp;

    /**
     * SecurityResponse#data
     */
    public Object data;

    private SecurityResponseDtoBuilder() {
    }


    public static SecurityResponseDtoBuilder of() {
        return new SecurityResponseDtoBuilder();
    }

    public SecurityResponseDtoBuilder with(Consumer<SecurityResponseDtoBuilder> builderConsumer) {
        builderConsumer.accept(this);
        return this;
    }


    public SecurityResponseDto build() {
        return new SecurityResponseDto(
                Optional.ofNullable(httpStatus).orElse(HttpStatus.OK),
                StringUtils.isBlank(message) ? StringUtils.EMPTY : message,
                Optional.ofNullable(timestamp).orElse(LocalDateTime.now()),
                Optional.ofNullable(data).orElse(EMPTY_DATA)
        );
    }
}
