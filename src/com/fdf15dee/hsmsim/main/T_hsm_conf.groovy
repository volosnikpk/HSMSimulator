package com.fdf15dee.hsmsim.main

import com.a9ae0b01f0ffc.commons.implementation.config.T_common_conf

class T_hsm_conf extends T_common_conf {

    String GC_BLACK_BOX_CONFIG
    String GC_HSM_THREAD_CONFIG

    T_hsm_conf(String i_config_file_name) {
        super(i_config_file_name)
        GC_BLACK_BOX_CONFIG = GC_CONST_CONF.GC_BLACK_BOX_CONFIG(GC_BLACK_BOX_CONFIG)
        GC_HSM_THREAD_CONFIG = GC_CONST_CONF.GC_HSM_THREAD_CONFIG(GC_HSM_THREAD_CONFIG)
    }

}
