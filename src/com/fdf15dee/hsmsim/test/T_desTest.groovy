package com.fdf15dee.hsmsim.test

import com.fdf15dee.hsmsim.crypto.utils.T_des
import com.fdf15dee.hsmsim.crypto.utils.T_key
import com.fdf15dee.hsmsim.main.T_hsm_base_4_const
import com.fdf15dee.hsmsim.main.T_hsm_base_5_context
import com.fdf15dee.hsmsim.main.T_hsm_base_6_util
import org.junit.Test

import javax.xml.bind.DatatypeConverter

class T_desTest extends GroovyTestCase {

    @Test
    void testEncrypt() {
        T_des t = new T_des()

        byte[] keya = DatatypeConverter.parseHexBinary("0707070707070707")
        byte[] keyb = DatatypeConverter.parseHexBinary("0808080808080808")
        byte[] keyc = DatatypeConverter.parseHexBinary("0707070707070707")

        byte[] data = DatatypeConverter.parseHexBinary("0000000000000000")

        byte[] res = t.encrypt(data,keya)
        res = t.decrypt(res,keyb)
        res = t.encrypt(res,keyc)

        System.out.println(DatatypeConverter.printHexBinary(res))
    }

    @Test
    void testClass_001(){
        T_key k = new T_key("070707070707070707070707070707070707070707070707")
        byte[] data = DatatypeConverter.parseHexBinary("0000000000000000")

        System.out.println(DatatypeConverter.printHexBinary(T_des.encrypt_tdes_single(data,k)))
    }

    @Test
    void testClass_002(){
        T_key k = new T_key("070707070707070707070707070707070707070707070707")
        byte[] data = DatatypeConverter.parseHexBinary("E818736E6EA987DB")

        System.out.println(DatatypeConverter.printHexBinary(T_des.decrypt_tdes_single(data,k)))
    }

    @Test
    void testClass_003(){

        T_key k = new T_key("U07070707070707070707070707070707")
        T_des d = new T_des()
        byte[] data = DatatypeConverter.parseHexBinary("E818736E6EA987DB6FF3F1E36F11B0CA")

        System.out.println(DatatypeConverter.printHexBinary(d.decrypt_tdes(data, k)))
    }

    @Test
    void testClass_004(){
        T_hsm_base_5_context c = new T_hsm_base_5_context()
        c.init_custom("./conf/commons.conf")
        //T_key k = new T_key("U07070707070707070707070707070707")
        //T_des des = new T_des()
        //byte[] data = DatatypeConverter.parseHexBinary("5178C9D3D1052B15BF6AEC458B4A4564")
        byte[] data = DatatypeConverter.parseHexBinary("0123456789ABCDEFFEDCBA9876543210")

        System.out.println(T_hsm_base_6_util.x().p_des.encrypt_key_under_lmk(data, "U", T_hsm_base_4_const.HSM_LMK_PAIR_14_15, 4).toString())
    }

}
