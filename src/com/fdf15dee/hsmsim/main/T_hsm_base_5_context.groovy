package com.fdf15dee.hsmsim.main

import com.a9ae0b01f0ffc.black_box.main.T_logging_base_5_context
import com.a9ae0b01f0ffc.commons.implementation.main.T_common_base_2_context
import com.fdf15dee.hsmsim.crypto.lmk.T_lmk_storage
import com.fdf15dee.hsmsim.crypto.utils.T_des

class T_hsm_base_5_context extends T_hsm_base_4_const{

    protected static ThreadLocal<T_hsm_base_5_context> p_context_thread_local = new ThreadLocal<T_hsm_base_5_context>()
    T_hsm_conf p_commons = GC_NULL_OBJ_REF as T_hsm_conf
    public T_lmk_storage p_lmk_storage = GC_NULL_OBJ_REF as T_lmk_storage
    public T_des p_des = GC_NULL_OBJ_REF as T_des

    static void init_custom(String i_conf_file_name) {
        get_context().p_commons = new T_hsm_conf(i_conf_file_name)
        T_logging_base_5_context.init_custom(c().GC_BLACK_BOX_CONFIG)
        get_context().p_lmk_storage = new T_lmk_storage()
        get_context().p_des = new T_des()
    }

    static T_hsm_base_5_context get_context() {
        if (is_null(p_context_thread_local.get())) {
            p_context_thread_local.set(new T_hsm_base_5_context())
        }
        return p_context_thread_local.get()
    }

    static T_hsm_conf c() {
        return get_context().p_commons
    }

}
