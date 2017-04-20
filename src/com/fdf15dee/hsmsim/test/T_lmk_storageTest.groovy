package com.fdf15dee.hsmsim.test

import com.fdf15dee.hsmsim.crypto.lmk.T_lmk_storage
import com.fdf15dee.hsmsim.crypto.utils.T_des
import com.fdf15dee.hsmsim.crypto.utils.T_key
import com.fdf15dee.hsmsim.main.T_hsm_base_4_const
import com.fdf15dee.hsmsim.main.T_hsm_base_6_util
import org.junit.Test

import javax.xml.bind.DatatypeConverter

class T_lmk_storageTest extends GroovyTestCase{

    void testGet_lmk_check_value() {
        T_lmk_storage z = new T_lmk_storage()

        z.get_lmk_check_value()
    }

    @Test
    void test001(){
        T_hsm_base_6_util z = new T_hsm_base_6_util()
        Thread.currentThread().setName("HSM_MAIN_THREAD")
        String l_conf_file_name = "./src/com/fdf15dee/hsmsim/conf/commons.conf"
        z.init_custom(l_conf_file_name)
        T_des l_des = new T_des();
        T_key l_key = l_des.decrypt_key_under_lmk(DatatypeConverter.parseHexBinary("063A0E7C0F2124E56192A4510F395ED7"), "U", T_hsm_base_4_const.HSM_LMK_PAIR_06_07, 0)

        System.out.println(l_key.toString())
    }

}
