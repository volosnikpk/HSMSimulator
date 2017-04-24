package com.fdf15dee.hsmsim.crypto.host_commands

import com.fdf15dee.hsmsim.crypto.lmk.T_lmk_storage
import com.fdf15dee.hsmsim.crypto.utils.T_crypto_utils
import com.fdf15dee.hsmsim.crypto.utils.T_key
import com.fdf15dee.hsmsim.main.T_hsm_base_6_util

import javax.xml.bind.DatatypeConverter

public class T_host_command_implementation extends T_hsm_base_6_util {

    public static T_message NC(T_message i_request) {
        T_message l_response = new T_message(i_request.p_message_header_b, (DIAG_RSP + HSM_RSP_NO_ERROR +
                DatatypeConverter.printHexBinary(get_context().p_lmk_storage.get_lmk_check_value()) +
                FIRMWARE_VER).getBytes())
        return l_response
    }

    public static T_message BU(T_message i_request) {
        try {
            String l_key_str = GC_EMPTY_STRING
            Integer l_offset = HSM_REQ_COMMAND_CODE_LEN
            String l_lmk_pair_str = i_request.p_message_s.substring(l_offset, l_offset + 2)
            Integer l_lmk_pair = GC_ZERO
            Integer l_lmk_variant = GC_ZERO
            String l_key_scheme = KEY_SCHEME_SINGLE
            l_offset += 2

            String l_key_length_flag = i_request.p_message_s.substring(l_offset, l_offset + 1)
            l_offset++

            if (T_key.is_key_scheme_present(i_request.p_message_s.substring(l_offset))) {
                l_key_str = T_key.get_full_key(i_request.p_message_s.substring(l_offset))
                l_key_scheme = T_key.get_key_scheme(i_request.p_message_s.substring(l_offset))
            } else {
                switch (l_key_length_flag) {
                    case 0:
                        l_key_str = T_key.get_full_key_no_scheme(i_request.p_message_s.substring(l_offset), KEY_SCHEME_SINGLE)
                        l_key_scheme = KEY_SCHEME_SINGLE
                        break
                    case 1:
                        l_key_str = T_key.get_full_key_no_scheme(i_request.p_message_s.substring(l_offset), KEY_SCHEME_DOUBLE_ANSI)
                        l_key_scheme = KEY_SCHEME_DOUBLE_ANSI
                        break
                    case 2:
                        l_key_str = T_key.get_full_key_no_scheme(i_request.p_message_s.substring(l_offset), KEY_SCHEME_TRIPLE_ANSI)
                        l_key_scheme = KEY_SCHEME_TRIPLE_ANSI
                        break
                }
            }
            l_offset = l_offset + l_key_str.length()
            l_key_str = T_key.remove_key_type(l_key_str)

            if (["FF", "10", "42"].contains(l_lmk_pair_str) == GC_FALSE) {
                l_lmk_pair = T_lmk_storage.get_lmk_pair_mapped(l_lmk_pair_str)

            } else {
                switch (l_lmk_pair_str) {
                    case "10": l_lmk_variant = 1; l_lmk_pair = HSM_LMK_PAIR_04_05; break
                    case "42": l_lmk_variant = 4; l_lmk_pair = HSM_LMK_PAIR_14_15; break
                    default:
                        if (i_request.p_message_s.substring(l_offset, l_offset + 1) == HSM_REQ_DELIMITER) {
                            l_offset++
                            l_lmk_variant = Integer.parseInt(i_request.p_message_s.substring(l_offset, l_offset + 1))
                            l_lmk_pair = T_lmk_storage.get_lmk_pair_mapped(i_request.p_message_s.substring(l_offset + 1, l_offset + 3))
                        } else
                            throw new Exception("LMK key type is absent after delimiter")
                }
            }
            T_key l_key = get_context().p_des.decrypt_key_under_lmk(DatatypeConverter.parseHexBinary(l_key_str), l_key_scheme, l_lmk_pair, l_lmk_variant)

            byte[] block = DatatypeConverter.parseHexBinary(CRYPTO_INIT_VECTOR_SINGLE)
            byte[] l_res = get_context().p_des.encrypt_tdes(block, l_key)
            return new T_message(i_request, (GEN_KEY_CHECK_VALUE_RSP + HSM_RSP_NO_ERROR + DatatypeConverter.printHexBinary(l_res)).getBytes())
        } catch (Exception e) {
            System.out.println(e.getMessage())
            return new T_message(i_request, (GEN_KEY_CHECK_VALUE_RSP + HSM_RSP_INSUFFICIENT_DATA).getBytes())

        }
    }

    public static T_message CW(T_message i_request) {
        String l_cvv = GC_EMPTY_STRING
        try {
            Integer l_offset = HSM_REQ_COMMAND_CODE_LEN
            String l_cvk_str = T_key.get_full_key(i_request.p_message_s.substring(l_offset))

            T_key l_cvk = get_context().p_des.decrypt_key_under_lmk(
                    DatatypeConverter.parseHexBinary(T_key.remove_key_type(l_cvk_str)),
                    T_key.get_key_scheme(l_cvk_str),
                    HSM_LMK_PAIR_14_15,
                    HSM_LMK_VARIANT_4)

            l_offset += l_cvk.p_length * 2
            l_offset += l_cvk.p_scheme.length()

            String l_pan = i_request.p_message_s.substring(l_offset, l_offset + HSM_REQ_PAN_LEN)
            l_offset += HSM_REQ_PAN_LEN
            l_offset += 1

            String l_expiry_date = i_request.p_message_s.substring(l_offset, l_offset + HSM_REQ_EXPIRY_DATE_LEN)
            l_offset += HSM_REQ_EXPIRY_DATE_LEN

            String l_service_code = i_request.p_message_s.substring(l_offset, l_offset + HSM_REQ_SERVICE_CODE_LEN)

            /* Command parsed, now do some crypto */
            byte[] block = DatatypeConverter.parseHexBinary((l_pan + l_expiry_date + l_service_code).padRight(32, "0"))
            byte[] block_a = Arrays.copyOfRange(block, 0, 8)
            byte[] block_b = Arrays.copyOfRange(block, 8, 16)

            T_key l_cvk_a = new T_key(l_cvk.p_a, KEY_SCHEME_SINGLE)

            byte[] l_res = get_context().p_des.encrypt_tdes(block_a, l_cvk_a)
            l_res = T_crypto_utils.xor(l_res, block_b)
            l_res = get_context().p_des.encrypt_tdes(l_res, l_cvk)

            Integer i = GC_ZERO
            String l_res_str = DatatypeConverter.printHexBinary(l_res)
            while (l_cvv.length() < 3) {
                if (((Character) l_res_str.charAt(i)).isDigit()) {
                    l_cvv += l_res_str.charAt(i)
                }
                i++
            }

        } catch (Exception e) {
            System.out.println(e.getMessage())
            return new T_message(i_request, (GEN_CVV_RSP + HSM_RSP_INSUFFICIENT_DATA).getBytes())
        }
        return new T_message(i_request, (GEN_CVV_RSP + HSM_RSP_NO_ERROR + l_cvv).getBytes())
    }

    public static T_message BA(T_message i_request) {
        String l_pin = GC_EMPTY_STRING
        try {
            Integer l_offset = HSM_REQ_COMMAND_CODE_LEN
            l_pin = i_request.p_message_s.substring(l_offset, l_offset + HSM_CLEAR_PIN_LENGTH)
            l_pin = T_key.encrypt_clear_pin_under_lmk(l_pin)
        } catch (Exception e) {
            System.out.println(e.getMessage())
            return new T_message(i_request, (ENC_CLEAR_PIN_LMK_RSP + HSM_RSP_INSUFFICIENT_DATA).getBytes())
        }
        return new T_message(i_request, (ENC_CLEAR_PIN_LMK_RSP + HSM_RSP_NO_ERROR + l_pin).getBytes())
    }

    public T_message NG(T_message i_request) {
        String l_pin = GC_EMPTY_STRING

        try {
            Integer l_offset = HSM_REQ_COMMAND_CODE_LEN
            String l_account_number = i_request.p_message_s.substring(l_offset, l_offset + HSM_REQ_PAN_SHORT_LEN)
            l_offset += HSM_REQ_PAN_SHORT_LEN
            l_pin = i_request.p_message_s.substring(l_offset, l_offset + HSM_ENCRYPTED_PIN_LENGTH)
            l_pin = T_key.decrypt_encrypted_pin_under_lmk(l_pin)
            l_pin = l_pin.padRight(HSM_ENCRYPTED_PIN_LENGTH, 'F')
        } catch (Exception e) {
            System.out.println(e.getMessage())
            return new T_message(i_request, (DEC_ENCRYPTED_PIN_LMK_RSP + HSM_RSP_INSUFFICIENT_DATA).getBytes())
        }
        return new T_message(i_request, (DEC_ENCRYPTED_PIN_LMK_RSP + HSM_RSP_NO_ERROR + l_pin).getBytes())
    }

    public T_message DE(T_message i_request) {
        String l_pin_offset = GC_EMPTY_STRING

        try {
            Integer l_offset = HSM_REQ_COMMAND_CODE_LEN
            String l_pvk_str = T_key.get_full_key(i_request.p_message_s.substring(l_offset))

            T_key l_pvk = get_context().p_des.decrypt_key_under_lmk(
                    DatatypeConverter.parseHexBinary(T_key.remove_key_type(l_pvk_str)),
                    T_key.get_key_scheme(l_pvk_str),
                    HSM_LMK_PAIR_14_15,
                    HSM_LMK_VARIANT_0)

            l_offset += l_pvk.p_length * 2
            l_offset += l_pvk.p_scheme.length()

            String l_encrypted_pin = i_request.p_message_s.substring(l_offset, l_offset + HSM_ENCRYPTED_PIN_LENGTH)
            l_offset += HSM_ENCRYPTED_PIN_LENGTH

            String l_pin_length = i_request.p_message_s.substring(l_offset, l_offset + 2)
            l_offset += 2

            String l_pan = i_request.p_message_s.substring(l_offset, l_offset + HSM_REQ_PAN_SHORT_LEN)
            l_offset += HSM_REQ_PAN_SHORT_LEN

            String l_decimalization_table = i_request.p_message_s.substring(l_offset, l_offset + HSM_DECIMALIZATION_TABLE_LENGTH)
            l_offset += HSM_DECIMALIZATION_TABLE_LENGTH

            String l_pin_validation_data = i_request.p_message_s.substring(l_offset, l_offset + HSM_PIN_VALIDATION_DATA_LENGTH)

            /* Command parsed, now do some crypto */
            String l_clear_pin = T_key.decrypt_encrypted_pin_under_lmk(l_encrypted_pin)

            String l_pin_validation_data_full = l_pin_validation_data.substring(0, l_pin_validation_data.indexOf("N"))
            l_pin_validation_data_full = l_pin_validation_data_full + l_pan.substring(l_pan.length() - 5, l_pan.length())
            l_pin_validation_data_full = l_pin_validation_data_full + l_pin_validation_data.substring(l_pin_validation_data.indexOf("N") + 1)

            byte[] l_encrypted_pan = get_context().p_des.encrypt_tdes(DatatypeConverter.parseHexBinary(l_pin_validation_data_full), l_pvk)

            String l_decimalized_pan = T_key.decimalize(DatatypeConverter.printHexBinary(l_encrypted_pan), l_decimalization_table)
            String l_natural_pin = l_decimalized_pan.substring(0, l_pin_length.toInteger())
            l_pin_offset = T_crypto_utils.sub_modulo_10(l_natural_pin, l_clear_pin)

        } catch (Exception e) {
            System.out.println(e.getMessage())
            return new T_message(i_request, (GEN_IBM_PIN_OFFSET_RSP + HSM_RSP_INSUFFICIENT_DATA).getBytes())
        }

        return new T_message(i_request, (GEN_IBM_PIN_OFFSET_RSP + HSM_RSP_NO_ERROR + l_pin_offset.padRight(HSM_REQ_PAN_SHORT_LEN, 'F')).getBytes())
    }

    public static T_message EA(T_message i_request) {
        try {
            Integer l_offset = HSM_REQ_COMMAND_CODE_LEN
            String l_zpk_str = T_key.get_full_key(i_request.p_message_s.substring(l_offset))

            T_key l_zpk = get_context().p_des.decrypt_key_under_lmk(
                    DatatypeConverter.parseHexBinary(T_key.remove_key_type(l_zpk_str)),
                    T_key.get_key_scheme(l_zpk_str),
                    HSM_LMK_PAIR_06_07,
                    HSM_LMK_VARIANT_0)

            l_offset += l_zpk.p_length * 2
            l_offset += l_zpk.p_scheme.length()

            String l_pvk_str = T_key.get_full_key(i_request.p_message_s.substring(l_offset))

            T_key l_pvk = get_context().p_des.decrypt_key_under_lmk(
                    DatatypeConverter.parseHexBinary(T_key.remove_key_type(l_pvk_str)),
                    T_key.get_key_scheme(l_pvk_str),
                    HSM_LMK_PAIR_14_15,
                    HSM_LMK_VARIANT_0)

            l_offset += l_pvk.p_length * 2
            l_offset += l_pvk.p_scheme.length()

            String l_max_pin_length = i_request.p_message_s.substring(l_offset, l_offset + 2)
            l_offset += 2

            String l_pin_block_under_zpk = i_request.p_message_s.substring(l_offset, l_offset + HSM_PIN_BLOCK_LENGTH)
            l_offset += HSM_PIN_BLOCK_LENGTH

            String l_pin_block_format_in = i_request.p_message_s.substring(l_offset, l_offset + 2)
            l_offset += 2

            String l_min_pin_length = i_request.p_message_s.substring(l_offset, l_offset + 2)
            l_offset += 2

            String l_pan = i_request.p_message_s.substring(l_offset, l_offset + HSM_REQ_PAN_SHORT_LEN)
            l_offset += HSM_REQ_PAN_SHORT_LEN

            String l_decimalization_table = i_request.p_message_s.substring(l_offset, l_offset + HSM_DECIMALIZATION_TABLE_LENGTH)
            l_offset += HSM_DECIMALIZATION_TABLE_LENGTH

            String l_pin_validation_data = i_request.p_message_s.substring(l_offset, l_offset + HSM_PIN_VALIDATION_DATA_LENGTH)
            l_offset += HSM_PIN_VALIDATION_DATA_LENGTH

            String l_pin_offset = i_request.p_message_s.substring(l_offset, l_offset + HSM_PIN_VALIDATION_DATA_LENGTH)

            /* Command parsed, now do some crypto */
            String l_clear_pin_block = DatatypeConverter.printHexBinary(get_context().p_des.decrypt_tdes(DatatypeConverter.parseHexBinary(l_pin_block_under_zpk), l_zpk))
            String l_clear_pin = T_crypto_utils.get_clear_pin_from_pin_block(l_pin_block_format_in, l_clear_pin_block, l_pan)

            String l_pin_validation_data_full = l_pin_validation_data.substring(0, l_pin_validation_data.indexOf("N"))
            l_pin_validation_data_full = l_pin_validation_data_full + l_pan.substring(l_pan.length() - 5, l_pan.length())
            l_pin_validation_data_full = l_pin_validation_data_full + l_pin_validation_data.substring(l_pin_validation_data.indexOf("N") + 1)
            byte[] l_encrypted_pan = get_context().p_des.encrypt_tdes(DatatypeConverter.parseHexBinary(l_pin_validation_data_full), l_pvk)

            String l_decimalized_pan = T_key.decimalize(DatatypeConverter.printHexBinary(l_encrypted_pan), l_decimalization_table)
            String l_natural_pin = l_decimalized_pan.substring(0, l_min_pin_length.toInteger())
            String l_derived_pin = T_crypto_utils.sub_modulo_10(l_natural_pin, l_clear_pin)

            l_pin_offset = l_pin_offset.substring(0, l_derived_pin.length())

            if (l_pin_offset != l_derived_pin) {
                return new T_message(i_request, (VRF_IBM_PIN_OFFSET_RSP + HSM_RSP_VRF_FAILED).getBytes())
            }

        } catch (Exception e) {
            System.out.println(e.getMessage())
            return new T_message(i_request, (VRF_IBM_PIN_OFFSET_RSP + HSM_RSP_INSUFFICIENT_DATA).getBytes())
        }

        return new T_message(i_request, (VRF_IBM_PIN_OFFSET_RSP + HSM_RSP_NO_ERROR).getBytes())
    }

    public static T_message JG(T_message i_request) {
        String l_pin_block = GC_EMPTY_STRING

        try {
            Integer l_offset = HSM_REQ_COMMAND_CODE_LEN
            String l_zpk_str = T_key.get_full_key(i_request.p_message_s.substring(l_offset))

            T_key l_zpk = get_context().p_des.decrypt_key_under_lmk(
                    DatatypeConverter.parseHexBinary(T_key.remove_key_type(l_zpk_str)),
                    T_key.get_key_scheme(l_zpk_str),
                    HSM_LMK_PAIR_06_07,
                    HSM_LMK_VARIANT_0)

            l_offset += l_zpk.p_length * 2
            l_offset += l_zpk.p_scheme.length()

            String l_pin_block_format_out = i_request.p_message_s.substring(l_offset, l_offset + 2)
            l_offset += 2

            String l_pan = i_request.p_message_s.substring(l_offset, l_offset + HSM_REQ_PAN_SHORT_LEN)
            l_offset += HSM_REQ_PAN_SHORT_LEN

            String l_encrypted_pin = i_request.p_message_s.substring(l_offset, l_offset + HSM_ENCRYPTED_PIN_LENGTH)

            /* Command parsed, now do some crypto */
            String l_clear_pin = T_key.decrypt_encrypted_pin_under_lmk(l_encrypted_pin)

            String l_clear_pin_block = T_crypto_utils.construct_clear_pin_block(l_pin_block_format_out, l_clear_pin, l_pan)

            byte[] l_encrypted_pin_block = get_context().p_des.encrypt_tdes(DatatypeConverter.parseHexBinary(l_clear_pin_block), l_zpk)

            l_pin_block = DatatypeConverter.printHexBinary(l_encrypted_pin_block)

        } catch (Exception e) {
            System.out.println(e.getMessage())
            return new T_message(i_request, (TRN_PIN_LMK_TO_ZPK_RSP + HSM_RSP_INSUFFICIENT_DATA).getBytes())
        }

        return new T_message(i_request, (TRN_PIN_LMK_TO_ZPK_RSP + HSM_RSP_NO_ERROR + l_pin_block).getBytes())
    }

    public static T_message KQ(T_message i_request) {
        String l_pin_block = GC_EMPTY_STRING

        try {
            Integer l_offset = HSM_REQ_COMMAND_CODE_LEN

            String l_mode = i_request.p_message_s.substring(l_offset, l_offset + 1)
            l_offset++

            String l_scheme_id = i_request.p_message_s.substring(l_offset, l_offset + 1)
            l_offset++

            String l_mdkac_str = T_key.get_full_key(i_request.p_message_s.substring(l_offset))

            T_key l_mdkac = get_context().p_des.decrypt_key_under_lmk(
                    DatatypeConverter.parseHexBinary(T_key.remove_key_type(l_mdkac_str)),
                    T_key.get_key_scheme(l_mdkac_str),
                    HSM_LMK_PAIR_28_29,
                    HSM_LMK_VARIANT_1)

            l_offset += l_mdkac.p_length * 2
            l_offset += l_mdkac.p_scheme.length()

            byte[] l_pan = Arrays.copyOfRange(i_request.p_message_b, l_offset, l_offset + 8)
            l_offset += 8

            byte[] l_atc = Arrays.copyOfRange(i_request.p_message_b, l_offset, l_offset + 2)
            l_offset += 2

            byte[] l_un = Arrays.copyOfRange(i_request.p_message_b, l_offset, l_offset + 4)
            l_offset += 4

            String l_trxn_data_length = i_request.p_message_s.substring(l_offset, l_offset + 2)
            l_offset += 2

            byte[] l_trxn_data = Arrays.copyOfRange(i_request.p_message_b, l_offset, l_offset + Integer.parseInt(l_trxn_data_length, 16))
            l_offset += Integer.parseInt(l_trxn_data_length, 16)

            if (i_request.p_message_s.substring(l_offset, l_offset + 1) != ';') throw new Exception("Incorrect data supplied")
            l_offset++

            byte[] l_arqc = Arrays.copyOfRange(i_request.p_message_b, l_offset, l_offset + 8)
            l_offset += 8

            String l_arc = new String(Arrays.copyOfRange(i_request.p_message_b, l_offset, l_offset + 2))

            /* Derive session key */
            byte[] l_session_key_a = get_context().p_des.encrypt_tdes(l_pan, l_mdkac)
            byte[] l_session_key_b = T_crypto_utils.xor(l_pan, DatatypeConverter.parseHexBinary(CRYPTO_INIT_VECTOR_SINGLE_F))
            l_session_key_b = get_context().p_des.encrypt_tdes(l_session_key_b, l_mdkac)

            T_key l_session_key = new T_key(T_crypto_utils.concat(l_session_key_a, l_session_key_b), KEY_SCHEME_DOUBLE_VARIANT)


        } catch (Exception e) {
            System.out.println(e.getMessage())
            return new T_message(i_request, (VRF_ARQC_GEN_ARPC_RSP + HSM_RSP_INSUFFICIENT_DATA).getBytes())
        }

        return new T_message(i_request, (VRF_ARQC_GEN_ARPC_RSP + HSM_RSP_NO_ERROR).getBytes())
    }

}

