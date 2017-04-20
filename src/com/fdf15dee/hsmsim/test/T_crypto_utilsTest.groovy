package com.fdf15dee.hsmsim.test

import com.fdf15dee.hsmsim.crypto.utils.T_crypto_utils
import com.fdf15dee.hsmsim.main.T_hsm_base_4_const
import org.junit.Test

import javax.xml.bind.DatatypeConverter

class T_crypto_utilsTest extends GroovyTestCase {
    void testXor() {
        byte[] x1 = DatatypeConverter.parseHexBinary("FFFFFFFFFFFFFFFFFF000FFE")
        byte[] x2 = DatatypeConverter.parseHexBinary("0012300004790000EEEEBBBBBBBBBB")
        System.out.println(DatatypeConverter.printHexBinary(T_crypto_utils.xor(x1, x2)))
    }

    @Test
    void test001(){
        String l_pin_validation_data = "0000000N0000"
        String l_pan = "437102061592"


        String l_res = l_pin_validation_data.substring(0, l_pin_validation_data.indexOf("N"))
        l_res = l_res + l_pan.substring(l_pan.length() - 5, l_pan.length())
        l_res = l_res + l_pin_validation_data.substring(l_pin_validation_data.indexOf("N")+1)

        System.out.print(l_res)

    }

    @Test
    void test002(){
        String i_data = "012ABC789DE0ABCD"
        String i_decimalization_table = "0123456789012345"
        String l_result = T_hsm_base_4_const.GC_EMPTY_STRING
        String l_map = "0123456789ABCDEF"

            for (Integer i = 0; i < i_data.length(); i++) {
                String l_char = i_data.substring(i, i + 1)
                if ("0123456789".contains(l_char)) {
                    l_result = l_result + l_char
                } else {
                    Integer l_hex_index = l_map.indexOf(l_char)
                    l_result = l_result + i_decimalization_table.substring(l_hex_index, l_hex_index + 1)
                }
            }

        System.out.print(l_result)

    }

    @Test
    void test003(){
        String l_pin = T_crypto_utils.get_clear_pin_from_pin_block("01", "0412778EFDF9EA6D","437102061592")
        System.out.println(l_pin)
    }

    @Test
    void test004(){
        String l_pin = T_crypto_utils.add_modulo_10("0123456789012345","3456789012345678")
        System.out.println(l_pin)
    }
}
