package com.fdf15dee.hsmsim.test

import com.fdf15dee.hsmsim.crypto.host_commands.T_host_command_pb
import org.junit.Test

class T_hsm_test {
    static final String PC_CONFIG_FILE_NAME =  "./src/com/fdf15dee/hsmsim/conf/black_box/logger_commons.conf"

    @Test
    void test_001() {
       // T_hsm_base_6_util.x().init_custom(PC_CONFIG_FILE_NAME)
        //T_hsm_base_5_context.get_context().init_custom(PC_CONFIG_FILE_NAME)

        T_host_command_pb l_host_command_parser = new T_host_command_pb()

        String cmd = "NC";
        l_host_command_parser.p_method_map.get(cmd).invoke("00082020202020204E43");

    }

    @Test
    void test_002() {
        printf("%02X", 256);

    }

}
