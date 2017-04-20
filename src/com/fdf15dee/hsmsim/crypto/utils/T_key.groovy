package com.fdf15dee.hsmsim.crypto.utils

import com.fdf15dee.hsmsim.main.T_hsm_base_6_util

import javax.xml.bind.DatatypeConverter

class T_key extends T_hsm_base_6_util {

    public String p_scheme
    public Integer p_length

    public byte[] p_a
    public byte[] p_b
    public byte[] p_c

    T_key(byte[] i_key, String i_scheme) {
        p_length = i_key.length
        if (i_scheme == GC_EMPTY_STRING)
            p_scheme = KEY_SCHEME_SINGLE
        else
            p_scheme = i_scheme
        if (i_key.length == KEY_SCHEME_SINGLE_LEN) {
            p_a = Arrays.copyOfRange(i_key, 0, 8)
            p_b = p_a
            p_c = p_a
        } else if (i_key.length == KEY_SCHEME_DOUBLE_LEN) {
            p_a = Arrays.copyOfRange(i_key, 0, 8)
            p_b = Arrays.copyOfRange(i_key, 8, 16)
            p_c = p_a
        } else if (i_key.length == KEY_SCHEME_TRIPLE_LEN) {
            p_a = Arrays.copyOfRange(i_key, 0, 8)
            p_b = Arrays.copyOfRange(i_key, 8, 16)
            p_c = Arrays.copyOfRange(i_key, 16, 25)
        }
    }

    T_key(String i_key) {
        p_scheme = get_key_scheme(i_key)
        Integer l_offset = is_key_scheme_present(i_key) ? 1 : 0
        if (p_scheme == KEY_SCHEME_SINGLE ||
                i_key.length() == KEY_SCHEME_SINGLE_LEN * 2) {
            p_a = DatatypeConverter.parseHexBinary(i_key.substring(l_offset, KEY_SCHEME_SINGLE_LEN * 2 + l_offset))
            p_b = p_a
            p_c = p_a
            p_length = KEY_SCHEME_SINGLE_LEN
        } else if (p_scheme == KEY_SCHEME_DOUBLE_ANSI ||
                p_scheme == KEY_SCHEME_DOUBLE_VARIANT ||
                i_key.length() == KEY_SCHEME_DOUBLE_LEN * 2) {
            p_a = DatatypeConverter.parseHexBinary(i_key.substring(l_offset, KEY_SCHEME_SINGLE_LEN * 2 + l_offset))
            p_b = DatatypeConverter.parseHexBinary(i_key.substring(KEY_SCHEME_SINGLE_LEN * 2 + l_offset, KEY_SCHEME_DOUBLE_LEN * 2 + l_offset))
            p_c = p_a
            p_length = KEY_SCHEME_DOUBLE_LEN
        } else if (p_scheme == KEY_SCHEME_TRIPLE_ANSI ||
                p_scheme == KEY_SCHEME_TRIPLE_VARIANT ||
                i_key.length() == KEY_SCHEME_TRIPLE_LEN * 2) {
            p_a = DatatypeConverter.parseHexBinary(i_key.substring(l_offset, KEY_SCHEME_SINGLE_LEN * 2 + l_offset))
            p_b = DatatypeConverter.parseHexBinary(i_key.substring(KEY_SCHEME_SINGLE_LEN * 2 + l_offset, KEY_SCHEME_DOUBLE_LEN * 2 + l_offset))
            p_c = DatatypeConverter.parseHexBinary(i_key.substring(KEY_SCHEME_DOUBLE_LEN * 2 + l_offset, KEY_SCHEME_TRIPLE_LEN * 2 + l_offset))
            p_length = KEY_SCHEME_TRIPLE_LEN
        }
    }

    public String toString() {
        return p_scheme + (DatatypeConverter.printHexBinary(p_a) +
                DatatypeConverter.printHexBinary(p_b) +
                DatatypeConverter.printHexBinary(p_c)).substring(0, p_length * 2)
    }

    public static Boolean is_key_scheme_present(String i_key) {
        switch (i_key.substring(0, 1)) {
            case KEY_SCHEME_SINGLE:
            case KEY_SCHEME_DOUBLE_ANSI:
            case KEY_SCHEME_DOUBLE_VARIANT:
            case KEY_SCHEME_TRIPLE_ANSI:
            case KEY_SCHEME_TRIPLE_VARIANT:
                return GC_TRUE
            default:
                return GC_FALSE
        }
    }

    public static String get_key_scheme(String i_key) {
        if (is_key_scheme_present(i_key))
            return i_key.substring(0, 1)
        else
            return KEY_SCHEME_SINGLE
    }

    public static Integer get_key_scheme_length(String i_key_scheme) {
        switch (i_key_scheme.substring(0, 1)) {
            case KEY_SCHEME_SINGLE:
                return KEY_SCHEME_SINGLE_LEN
            case KEY_SCHEME_DOUBLE_ANSI:
            case KEY_SCHEME_DOUBLE_VARIANT:
                return KEY_SCHEME_DOUBLE_LEN
            case KEY_SCHEME_TRIPLE_ANSI:
            case KEY_SCHEME_TRIPLE_VARIANT:
                return KEY_SCHEME_TRIPLE_LEN
            default:
                return KEY_SCHEME_SINGLE_LEN
        }
    }

    public static String remove_key_type(String i_key) {
        switch (i_key.substring(0, 1)) {
            case KEY_SCHEME_SINGLE:
            case KEY_SCHEME_DOUBLE_ANSI:
            case KEY_SCHEME_DOUBLE_VARIANT:
            case KEY_SCHEME_TRIPLE_ANSI:
            case KEY_SCHEME_TRIPLE_VARIANT:
                return i_key.substring(1, get_key_scheme_length(i_key) * 2 + 1)
            default:
                return i_key.substring(0, KEY_SCHEME_SINGLE_LEN * 2)
        }
    }

    public static String get_full_key(String i_key) {
        switch (i_key.substring(0, 1)) {
            case KEY_SCHEME_SINGLE:
            case KEY_SCHEME_DOUBLE_ANSI:
            case KEY_SCHEME_DOUBLE_VARIANT:
            case KEY_SCHEME_TRIPLE_ANSI:
            case KEY_SCHEME_TRIPLE_VARIANT:
                return i_key.substring(0, get_key_scheme_length(i_key) * 2 + 1)
            default:
                return i_key.substring(0, KEY_SCHEME_SINGLE_LEN * 2)
        }
    }

    public static String get_full_key_no_scheme(String i_key, String i_key_scheme) {
        switch (i_key_scheme) {
            case KEY_SCHEME_SINGLE:
                return i_key.substring(0, KEY_SCHEME_SINGLE_LEN * 2)
            case KEY_SCHEME_DOUBLE_ANSI:
            case KEY_SCHEME_DOUBLE_VARIANT:
                return i_key.substring(0, KEY_SCHEME_DOUBLE_LEN * 2)
            case KEY_SCHEME_TRIPLE_ANSI:
            case KEY_SCHEME_TRIPLE_VARIANT:
                return i_key.substring(0, KEY_SCHEME_TRIPLE_LEN * 2)
            default:
                return i_key.substring(0, KEY_SCHEME_SINGLE_LEN * 2)
        }
    }

    public static String encrypt_clear_pin_under_lmk(String i_clear_pin) {
        return i_clear_pin.padRight(HSM_ENCRYPTED_PIN_LENGTH, '0')
    }

    public static String decrypt_encrypted_pin_under_lmk(String i_encrypted_pin) {
        return i_encrypted_pin.substring(0, HSM_CLEAR_PIN_LENGTH)
    }

    public static String decimalize(String i_data, String i_decimalization_table) {
        String l_map = "0123456789ABCDEF"
        String l_result = GC_EMPTY_STRING

        for (Integer i = 0; i < i_data.length(); i++) {
            String l_char = i_data.substring(i, i + 1)
            if ("0123456789".contains(l_char)) {
                l_result = l_result + l_char
            } else {
                Integer l_hex_index = l_map.indexOf(l_char)
                l_result = l_result + i_decimalization_table.substring(l_hex_index, l_hex_index + 1)
            }
        }
        return l_result
    }


}
