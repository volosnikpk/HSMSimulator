package com.fdf15dee.hsmsim.network

import com.a9ae0b01f0ffc.black_box.annotations.I_fix_variable_scopes

import static com.a9ae0b01f0ffc.commons.implementation.main.T_common_base_1_const.*
import static com.fdf15dee.hsmsim.main.T_hsm_base_5_context.init_custom
import static com.fdf15dee.hsmsim.main.T_hsm_base_6_util.l

@I_fix_variable_scopes
public class T_hsm_thread_listen extends Thread {

    Integer p_thread_id = GC_ZERO
    Integer p_thread_ip_port = GC_ZERO
    String p_thread_owner = GC_EMPTY_STRING
    String p_conf_name = GC_EMPTY_STRING

    T_hsm_thread_listen(Integer i_thread_id, Integer i_thread_ip_port, String i_thread_owner, String i_conf_name) {
        init(i_thread_id, i_thread_ip_port, i_thread_owner, i_conf_name)
    }

    void init(Integer i_thread_id, Integer i_thread_ip_port, String i_thread_owner, String i_conf_name) {
        p_thread_id = i_thread_id
        p_thread_ip_port = i_thread_ip_port
        p_thread_owner = i_thread_owner
        p_conf_name = i_conf_name
    }

    //@I_black_box
    void run_with_logging() {
        ServerSocket l_server_socket = new ServerSocket(p_thread_ip_port)

        while (GC_TRUE) {
            Socket l_service_socket = l_server_socket.accept()
            l().log_info(s.Connected)
            T_hsm_thread_handle l_hsm_thread_handle = new T_hsm_thread_handle(l_service_socket, p_thread_id, p_conf_name)
            l_hsm_thread_handle.start()
            //new Thread(new T_hsm_thread_handle(l_service_socket, p_thread_id, p_conf_name)).start()
        }
    }

    @Override
    public void run() {
        setName("HSM_THREAD_LISTEN" + String.format("%02d", p_thread_id))
        init_custom(p_conf_name)
        run_with_logging()
    }

}
