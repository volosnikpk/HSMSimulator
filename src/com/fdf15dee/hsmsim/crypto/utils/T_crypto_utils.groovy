package com.fdf15dee.hsmsim.crypto.utils

import com.fdf15dee.hsmsim.main.T_hsm_base_6_util

import javax.xml.bind.DatatypeConverter

class T_crypto_utils extends T_hsm_base_6_util {

    public static byte[] xor(byte[] i_x1, byte[] i_x2) {
        byte[] l_res
        if (i_x1.length > i_x2.length)
            l_res = i_x1
        else
            l_res = i_x2

        for (Integer i = 0; i < l_res.length - Math.abs(i_x1.length - i_x2.length); i++) {
            l_res[i] = i_x1[i] ^ i_x2[i]
        }
        return l_res
    }

    public static byte[] concat(byte[] i_x1, byte[] i_x2) {
        byte[] l_res = new byte[i_x1.length + i_x2.length]
        System.arraycopy(i_x1, 0, l_res, 0, i_x1.length)
        System.arraycopy(i_x2, 0, l_res, i_x1.length, i_x2.length)
        return l_res
    }

    public static byte[] concat(byte[] i_x1, byte[] i_x2, byte[] i_x3) {
        byte[] l_res = new byte[i_x1.length + i_x2.length + i_x3.length]
        System.arraycopy(i_x1, 0, l_res, 0, i_x1.length)
        System.arraycopy(i_x2, 0, l_res, i_x1.length, i_x2.length)
        System.arraycopy(i_x3, 0, l_res, i_x1.length + i_x2.length, i_x3.length)
        return l_res
    }

    public static String construct_clear_pin_block(String i_pin_block_format, String i_clear_pin, String i_pan) {
        switch (i_pin_block_format) {
            case "01":
                String l_part1 = ("0" + i_clear_pin.length() + i_clear_pin).padRight(HSM_PIN_BLOCK_LENGTH, 'F')
                String l_part2 = i_pan.padLeft(HSM_PIN_BLOCK_LENGTH, '0')
                byte[] l_part1_byte = DatatypeConverter.parseHexBinary(l_part1)
                byte[] l_part2_byte = DatatypeConverter.parseHexBinary(l_part2)
                return DatatypeConverter.printHexBinary(xor(l_part1_byte, l_part2_byte))
                break
            default:
                return CRYPTO_INIT_VECTOR_SINGLE
        }
    }

    public static String get_clear_pin_from_pin_block(String i_pin_block_format, String i_clear_pin_block, String i_pan) {
        switch (i_pin_block_format) {
            case "01":
                String l_part1 = i_pan.padLeft(HSM_PIN_BLOCK_LENGTH, '0')
                byte[] l_part1_byte = DatatypeConverter.parseHexBinary(l_part1)
                byte[] l_part2_byte = DatatypeConverter.parseHexBinary(i_clear_pin_block)
                String l_decrypted = DatatypeConverter.printHexBinary(xor(l_part1_byte, l_part2_byte))
                Integer l_pin_length = l_decrypted.substring(1, 2).toInteger()
                return l_decrypted.substring(2, 2 + l_pin_length)
                break
            default:
                return GC_EMPTY_STRING
        }
    }

    public static String sub_modulo_10(String i_data1, String i_data2) {
        String l_result = GC_EMPTY_STRING

        for (Integer i = 0; i < i_data1.length(); i++) {
            Integer l_char_code = i_data1.substring(i, i + 1).toInteger() - i_data2.substring(i, i + 1).toInteger()
            if (l_char_code < 0) {
                l_char_code += 10
                l_result = l_result + l_char_code.toString()
            } else {
                l_result = l_result + l_char_code.toString()
            }
        }
        return l_result
    }

    public static String add_modulo_10(String i_data1, String i_data2) {
        String l_result = GC_EMPTY_STRING

        for (Integer i = 0; i < i_data1.length(); i++) {
            Integer l_char_code = i_data1.substring(i, i + 1).toInteger() + i_data2.substring(i, i + 1).toInteger()
            if (l_char_code > 10)
                l_char_code = l_char_code % 10
            l_result = l_result + l_char_code.toString()
        }
        return l_result
    }


}
