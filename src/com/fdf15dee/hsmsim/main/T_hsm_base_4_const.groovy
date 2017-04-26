package com.fdf15dee.hsmsim.main

import com.a9ae0b01f0ffc.commons.implementation.main.T_common_base_3_utils

class T_hsm_base_4_const extends T_common_base_3_utils {

    public static final Integer HSM_REQ_COMMAND_CODE_LEN = 0x02
    public static final Integer HSM_REQ_PAN_LEN = 0x10
    public static final Integer HSM_REQ_PAN_SHORT_LEN = 0x0C
    public static final Integer HSM_REQ_CVV_LEN = 0x03
    public static final Integer HSM_REQ_SERVICE_CODE_LEN = 0x03
    public static final Integer HSM_REQ_EXPIRY_DATE_LEN = 0x04
    public static final String HSM_REQ_DELIMITER = ";"

    public static final String DIAG_REQ = "NC"
    public static final String DIAG_RSP = "ND"
    public static final String GEN_KEY_CHECK_VALUE_REQ = "BU"
    public static final String GEN_KEY_CHECK_VALUE_RSP = "BV"

    public static final String GEN_CVV_REQ = "CW"
    public static final String GEN_CVV_RSP = "CX"

    public static final String ENC_CLEAR_PIN_LMK_REQ = "BA"
    public static final String ENC_CLEAR_PIN_LMK_RSP = "BB"
    public static final String DEC_ENCRYPTED_PIN_LMK_REQ = "NG"
    public static final String DEC_ENCRYPTED_PIN_LMK_RSP = "NH"

    public static final String GEN_IBM_PIN_OFFSET_REQ = "DE"
    public static final String GEN_IBM_PIN_OFFSET_RSP = "DF"
    public static final String VRF_IBM_PIN_OFFSET_REQ = "EA"
    public static final String VRF_IBM_PIN_OFFSET_RSP = "EB"

    public static final String TRN_PIN_LMK_TO_ZPK_REQ = "JG"
    public static final String TRN_PIN_LMK_TO_ZPK_RSP = "JH"

    public static final String VRF_ARQC_GEN_ARPC_REQ = "KQ"
    public static final String VRF_ARQC_GEN_ARPC_RSP = "KR"


    public static final String FIRMWARE_VER = "0007-E000"

    public static final Integer MSG_HEADER_LENGTH = 0x06
    public static final String MSG_HEADER = "      "

    public static final Integer TCP_START_CHAR = 0x00
    public static final Integer MSG_HEADER_LENGTH_FULL = 0x08

    public static final String KEY_SCHEME_SINGLE = "Z"
    public static final Integer KEY_SCHEME_SINGLE_LEN = 0x08
    public static final String KEY_SCHEME_DOUBLE_ANSI = "X"
    public static final String KEY_SCHEME_DOUBLE_VARIANT = "U"
    public static final Integer KEY_SCHEME_DOUBLE_LEN = 0x10
    public static final String KEY_SCHEME_TRIPLE_ANSI = "Y"
    public static final String KEY_SCHEME_TRIPLE_VARIANT = "T"
    public static final Integer KEY_SCHEME_TRIPLE_LEN = 0x18

    public static final String KEY_SCHEME_LMK = "L"
    public static final Integer KEY_SCHEME_LMK_LEN = 0x10
    public static final String KEY_SCHEME_CLEAR = "C"

    public static final String CRYPTO_INIT_VECTOR_SINGLE = "0000000000000000"
    public static final String CRYPTO_INIT_VECTOR_SINGLE_F = "FFFFFFFFFFFFFFFF"
    public static final String CRYPTO_INIT_VECTOR_DOUBLE = "00000000000000000000000000000000"
    public static final String CRYPTO_INIT_VECTOR_TRIPLE = "000000000000000000000000000000000000000000000000"

    public static final String HSM_RSP_NO_ERROR = "00"
    public static final String HSM_RSP_VRF_FAILED = "01"
    public static final String HSM_RSP_INSUFFICIENT_DATA = "15"

    public static final Integer HSM_LMK_PAIR_00_01 = 0x00
    public static final Integer HSM_LMK_PAIR_02_03 = 0x01
    public static final Integer HSM_LMK_PAIR_04_05 = 0x02
    public static final Integer HSM_LMK_PAIR_06_07 = 0x03
    public static final Integer HSM_LMK_PAIR_08_09 = 0x04
    public static final Integer HSM_LMK_PAIR_10_11 = 0x05
    public static final Integer HSM_LMK_PAIR_12_13 = 0x06
    public static final Integer HSM_LMK_PAIR_14_15 = 0x07
    public static final Integer HSM_LMK_PAIR_16_17 = 0x08
    public static final Integer HSM_LMK_PAIR_18_19 = 0x09
    public static final Integer HSM_LMK_PAIR_20_21 = 0x0A
    public static final Integer HSM_LMK_PAIR_22_23 = 0x0B
    public static final Integer HSM_LMK_PAIR_24_25 = 0x0C
    public static final Integer HSM_LMK_PAIR_26_27 = 0x0D
    public static final Integer HSM_LMK_PAIR_28_29 = 0x0E
    public static final Integer HSM_LMK_PAIR_30_31 = 0x0F
    public static final Integer HSM_LMK_PAIR_32_33 = 0x10
    public static final Integer HSM_LMK_PAIR_34_35 = 0x11
    public static final Integer HSM_LMK_PAIR_36_37 = 0x12
    public static final Integer HSM_LMK_PAIR_38_39 = 0x13

    public static final Integer HSM_LMK_VARIANT_0 = 0x00
    public static final Integer HSM_LMK_VARIANT_1 = 0x01
    public static final Integer HSM_LMK_VARIANT_2 = 0x02
    public static final Integer HSM_LMK_VARIANT_3 = 0x03
    public static final Integer HSM_LMK_VARIANT_4 = 0x04

    public static final Integer HSM_CLEAR_PIN_LENGTH = 0x04
    public static final Integer HSM_ENCRYPTED_PIN_LENGTH = 0x07
    public static final Integer HSM_DECIMALIZATION_TABLE_LENGTH = 0x10
    public static final Integer HSM_PIN_VALIDATION_DATA_LENGTH = 0x0C
    public static final Integer HSM_PIN_BLOCK_LENGTH = 0x10

}
