package com.fdf15dee.hsmsim.main

import com.fdf15dee.hsmsim.network.T_hsm_thread_listen
import groovy.util.slurpersupport.GPathResult

class T_hsm_base_7_main extends T_hsm_base_6_util {

    private static void spawn_thread(GPathResult i_thread_xml, String i_conf_name) {
        T_hsm_thread_listen l_hsm_thread = new T_hsm_thread_listen(Integer.parseInt(i_thread_xml.@thread_id.text()), Integer.parseInt(i_thread_xml.@thread_ip_port.text()), i_thread_xml.@thread_owner.text(), i_conf_name)
        l_hsm_thread.start()
    }

    static void main(String... i_args) {
        Thread.currentThread().setName("HSM_MAIN_THREAD")
        String l_conf_file_name = "./src/com/fdf15dee/hsmsim/conf/commons.conf"
        init_custom(l_conf_file_name)
        l().log_info(s.Main_configration_file_name_Z1, l_conf_file_name)
        l().log_info(s.Main_thread_started_to_work)
        GPathResult p_conf = (GPathResult) new XmlSlurper().parse(c().GC_HSM_THREAD_CONFIG)
        for (l_thread_xml in p_conf.children()) {
            spawn_thread(l_thread_xml as GPathResult, l_conf_file_name)
        }
    }

}
