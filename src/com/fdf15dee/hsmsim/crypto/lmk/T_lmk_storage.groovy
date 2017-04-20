package com.fdf15dee.hsmsim.crypto.lmk

import com.fdf15dee.hsmsim.crypto.utils.T_crypto_utils
import com.fdf15dee.hsmsim.main.T_hsm_base_6_util

import javax.xml.bind.DatatypeConverter

class T_lmk_storage extends T_hsm_base_6_util{

    byte[][] p_lmk
    byte[] p_lmk_variant
    byte[] p_lmk_variant_double
    byte[] p_lmk_variant_triple

    T_lmk_storage(){
        p_lmk_variant = DatatypeConverter.parseHexBinary("A65A6ADE2B50749CFA")
        p_lmk_variant_double = DatatypeConverter.parseHexBinary("A65A")
        p_lmk_variant_triple = DatatypeConverter.parseHexBinary("6ADE2B")
        p_lmk = new byte[20][16]
        p_lmk[0] = DatatypeConverter.parseHexBinary("01010101010101017902CD1FD36EF8BA")
        p_lmk[1] = DatatypeConverter.parseHexBinary("20202020202020203131313131313131")
        p_lmk[2] = DatatypeConverter.parseHexBinary("40404040404040405151515151515151")
        p_lmk[3] = DatatypeConverter.parseHexBinary("61616161616161617070707070707070")
        p_lmk[4] = DatatypeConverter.parseHexBinary("80808080808080809191919191919191")
        p_lmk[5] = DatatypeConverter.parseHexBinary("A1A1A1A1A1A1A1A1B0B0B0B0B0B0B0B0")
        p_lmk[6] = DatatypeConverter.parseHexBinary("C1C1010101010101D0D0010101010101")
        p_lmk[7] = DatatypeConverter.parseHexBinary("E0E0010101010101F1F1010101010101")
        p_lmk[8] = DatatypeConverter.parseHexBinary("1C587F1C13924FEF0101010101010101")
        p_lmk[9] = DatatypeConverter.parseHexBinary("01010101010101010101010101010101")
        p_lmk[10] = DatatypeConverter.parseHexBinary("02020202020202020404040404040404")
        p_lmk[11] = DatatypeConverter.parseHexBinary("07070707070707071010101010101010")
        p_lmk[12] = DatatypeConverter.parseHexBinary("13131313131313131515151515151515")
        p_lmk[13] = DatatypeConverter.parseHexBinary("16161616161616161919191919191919")
        p_lmk[14] = DatatypeConverter.parseHexBinary("1A1A1A1A1A1A1A1A1C1C1C1C1C1C1C1C")
        p_lmk[15] = DatatypeConverter.parseHexBinary("23232323232323232525252525252525")
        p_lmk[16] = DatatypeConverter.parseHexBinary("26262626262626262929292929292929")
        p_lmk[17] = DatatypeConverter.parseHexBinary("2A2A2A2A2A2A2A2A2C2C2C2C2C2C2C2C")
        p_lmk[18] = DatatypeConverter.parseHexBinary("2F2F2F2F2F2F2F2F3131313131313131")
        p_lmk[19] = DatatypeConverter.parseHexBinary("01010101010101010101010101010101")
    }

     public byte[] get_lmk_pair(Integer i_pair){
        return p_lmk[i_pair]
    }

    public byte[] get_lmk_pair_variant(Integer i_pair, Integer i_variant){
        if (i_variant == 0)
            return p_lmk[i_pair]
        byte[] l_variant = new byte[16]
        l_variant[0] = p_lmk_variant[i_variant-1]
        return T_crypto_utils.xor(get_lmk_pair(i_pair), l_variant)
    }

    public byte[] get_lmk_check_value(){
        byte[] l_lmk_check_value = get_lmk_pair(0)
        for (Integer i=1; i < p_lmk.length; i++) {
            l_lmk_check_value = T_crypto_utils.xor(l_lmk_check_value, get_lmk_pair(i))
        }
        l_lmk_check_value = T_crypto_utils.xor(Arrays.copyOfRange(l_lmk_check_value, 0, 8), Arrays.copyOfRange(l_lmk_check_value, 8, 16))
        return Arrays.copyOfRange(l_lmk_check_value, 0, 8)
    }

    public byte[] get_variant(Integer i_variant, Integer i_key_size){
        byte[] l_variant = new byte[i_key_size]
        l_variant[0] = p_lmk_variant[i_variant]
        return l_variant
    }

    public byte[] get_variant_double(Integer i_variant, Integer i_key_size){
        byte[] l_variant = new byte[i_key_size]
        l_variant[0] = p_lmk_variant_double[i_variant]
        return l_variant
    }

    public byte[] get_variant_triple(Integer i_variant, Integer i_key_size){
        byte[] l_variant = new byte[i_key_size]
        l_variant[0] = p_lmk_variant_triple[i_variant]
        return l_variant
    }

    static public Integer get_lmk_pair_mapped(String i_lmk_pair_code){
        switch (i_lmk_pair_code){
            case "00": return HSM_LMK_PAIR_04_05
            case "01": return HSM_LMK_PAIR_06_07
            case "02": return HSM_LMK_PAIR_14_15
            case "03": return HSM_LMK_PAIR_16_17
            case "04": return HSM_LMK_PAIR_18_19
            case "05": return HSM_LMK_PAIR_20_21
            case "06": return HSM_LMK_PAIR_22_23
            case "07": return HSM_LMK_PAIR_24_25
            case "08": return HSM_LMK_PAIR_26_27
            case "09": return HSM_LMK_PAIR_28_29
            case "0A": return HSM_LMK_PAIR_30_31
            case "0B": return HSM_LMK_PAIR_32_33
            default: return HSM_LMK_PAIR_04_05
        }
    }

}
