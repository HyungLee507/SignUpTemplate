package com.ssafy.template.global.exception;

import lombok.Getter;

@Getter
public enum ExceptionCode {

    MEMBER_NOT_FOUND(404, "회원 정보를 찾을 수 없습니다."),
    MEMBER_ALREADY_EXISTS(409, "회원 정보가 이미 존재합니다."),
    TOKEN_NOT_FOUND(401, "토큰이 존재하지 않습니다."),
    INVALID_TOKEN_FORMAT(401, "잘못된 토큰 형식입니다."),
    JWT_TOKEN_EXPIRED(401, "JWT 토큰이 만료되었습니다."),
    JWT_TOKEN_INVALID(401, "유효하지 않은 JWT 토큰입니다."),
    TOKEN_SIGNATURE_INVALID(401, "토큰 서명이 유효하지 않습니다."),
    REFRESH_TOKEN_NOT_FOUND(404, "Refresh 토큰을 찾을 수 없습니다."),
    JWT_TOKEN_GENERATION_FAILED(500, "JWT 토큰 생성에 실패했습니다."),
    REISSUE_ACCESS_TOKEN_AND_CHECK_VALID_ERROR(401, "Access Token 재발급 중 오류가 발생했습니다."),
    REFRESH_TOKEN_EXPIRED(401, "RefreshToken이 만료되었습니다."),
    JWT_TOKEN_REFRESH_FAILED(500, "JWT 토큰 갱신에 실패했습니다."),
    UNKNOWN_PRINCIPAL_TYPE(401, "OAUTH2 TYP2이 다릅니다."),
    UNSUPPORTED_USER_TYPE(401, "제공하지 않는 유저 타입입니다."),
    MEMBER_ID_MISMATCH(401, "토큰과 멤버ID 불일치 합니다"),
    OAUTH2_LOGIN_FAILURE(401, "OAuth2 로그인에 실패했습니다."),
    PRODUCT_NOT_FOUND(404, "상품을 찾을 수 없습니다."),
    UNAUTHORIZED_PRODUCT_ACCESS(403, "상품에 대한 권한이 없습니다."),
    PRODUCT_DELETE_FAILED(500, "상품 삭제에 실패했습니다."),
    NOT_A_SELLER(403, "판매자 권한이 없습니다."),
    FORM_NOT_FOUND(404, "폼 정보를 찾을 수 없습니다."),
    GROUP_BUYING_BOARD_NOT_FOUND(404, "공동구매 게시판을 찾을 수 없습니다."),
    APPLY_NOT_FOUND(404, "신청 정보를 찾을 수 없습니다."),
    MEMBER_NOT_AUTHORIZED(403, "해당 작업에 대해 권한이 없습니다."),
    FORM_REGISTRATION_FAILED(500, "폼 등록 중 문제가 발생했습니다."),
    APPLY_REGISTRATION_FAILED(500, "폼 신청 중 문제가 발생했습니다."),
    INVAILD_FORM_STATUS_NOT_MATCHED_AMOUNT(403, "신청한 상품 개수가 총 개수에 도달하지 못했습니다."),
    INVAILD_FORM_STATUS_NOT_FOUND_RECIPIENT(403, "상품을 수령할 사용자가 없습니다."),
    APPLY_UNDO_FAILED(500, "폼 취소 중 문제가 발생했습니다."),
    FORM_RETREIVE_FAILED(500, "폼 조회를 실패했습니다."),
    RECIPIENT_NOT_FOUND(404, "수령인 정보를 찾을 수 없습니다."),
    SET_RECIPIENT_FAILED(500, "수령인 등록 중 문제가 발생했습니다."),
    INVALID_DAY_OF_WEEK(400, "잘못된 요일 값입니다."),
    DAY_OF_WEEK_NOT_FOUND(404, "요일 값이 없습니다."),
    SET_DAY_OF_WEEK_FAILED(500, "요일 값 변경에 실패했습니다."),
    ORDER_START_FAILED(500, "주문 시작에 실패했습니다."),
    ORDER_RECIPIENT_SETTING_FAILED(500, "수령인 설정 중 문제가 발생했습니다."),
    ADDRESS_NOT_FOUND(401, "주소를 찾을 수 없습니다."),
    SEND_MAIL_FAILED(401, "이메일 발송중 오류가 발생했습니다."),
    ADDRESS_EMPTY(400, "주소가 비어있습니다."),
    ADDRESS_INVALID_FORMAT(400, "잘못된 주소 형식입니다."),
    ADDRESS_ADMINISTRATIVE_UNIT_INVALID(400, "잘못된 행정구역 형식입니다."),
    ADDRESS_BUILDING_NUMBER_INVALID(400, "잘못된 건물번호 형식입니다."),
    ADDRESS_LOT_NUMBER_INVALID(400, "잘못된 지번 형식입니다."),
    ADDRESS_TOO_LONG(400, "주소가 너무 깁니다.");

    private final int status;

    private final String message;

    ExceptionCode(int code, String message) {
        this.status = code;
        this.message = message;
    }

}
