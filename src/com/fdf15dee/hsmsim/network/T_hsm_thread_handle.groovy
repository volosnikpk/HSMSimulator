package com.fdf15dee.hsmsim.network

import com.fdf15dee.hsmsim.crypto.host_commands.T_host_command_implementation
import com.fdf15dee.hsmsim.crypto.host_commands.T_host_command_pb
import com.fdf15dee.hsmsim.crypto.host_commands.T_message
import com.fdf15dee.hsmsim.crypto.utils.T_crypto_utils
import com.fdf15dee.hsmsim.main.T_hsm_base_6_util

import javax.xml.bind.DatatypeConverter

import static com.a9ae0b01f0ffc.commons.implementation.main.T_common_base_1_const.*
import static com.fdf15dee.hsmsim.main.T_hsm_base_5_context.init_custom
import static com.fdf15dee.hsmsim.main.T_hsm_base_6_util.l

public class T_hsm_thread_handle extends Thread {

    T_host_command_pb p_host_command_parser = new T_host_command_pb()

    Socket p_service_socket
    Integer p_thread_id = GC_ZERO
    String p_conf_name = GC_EMPTY_STRING

    T_hsm_thread_handle(Socket i_service_socket, Integer i_thread_id, String i_conf_name) {
        init(i_service_socket, i_thread_id, i_conf_name)
    }

    void init(Socket i_service_socket, Integer i_thread_id, String i_conf_name) {
        p_service_socket = i_service_socket
        p_thread_id = i_thread_id
        p_conf_name = i_conf_name
    }

    @Override
    public void run() {
        setName("HSM_THREAD_HANDLE" + String.format("%02d", p_thread_id))
        String tid_str = "TID_" + String.format("%02X", p_thread_id) + " "
        init_custom(p_conf_name)

        T_host_command_implementation hci = new T_host_command_implementation()
        l().log_info(s.Thread_Z1_accepted_connection_from_host_Z2, p_thread_id, p_service_socket.getInetAddress().getHostName())

        InputStream l_buffer_in = p_service_socket.getInputStream()
        OutputStream l_buffer_out = p_service_socket.getOutputStream()

        try {
            while (GC_TRUE) {
                byte[] l_start_char = new byte[1]
                l_buffer_in.read(l_start_char, 0, 1)
                if (l_start_char[0] == 0x00)
                    l_buffer_in.read(l_start_char, 0, 1)

                Integer l_host_command_length = Integer.parseInt(DatatypeConverter.printHexBinary(l_start_char[0]), 16)

                byte[] l_request_received = new byte[l_host_command_length + 2]
                l_request_received[1] = l_host_command_length
                l_buffer_in.read(l_request_received, 2, l_host_command_length)

                T_message l_message = new T_message(l_request_received)

                l().log_info(s.Request_received)

                System.out.println(tid_str + "RCV BIN [" + new String(l_message.p_message_header_b) + new String(l_message.p_message_b) + "]")
                System.out.println(tid_str + "RCV HEX [" + l_message.p_message_header_s + l_message.p_message_s + "]")

                System.out.println(tid_str + "HC REQ length [" + String.format("%02X", l_message.p_message_b.length) + "]")
                System.out.println(tid_str + "HC REQ code   [" + T_host_command_pb.get_host_command_code(l_message) + "]")
                System.out.println(tid_str + "HC REQ data   [" + T_host_command_pb.get_host_command_data(l_message) + "]")

                System.out.println(tid_str + "Entered " + T_host_command_pb.get_host_command_code(l_message) + " command handler")

                T_message l_host_command_response = (T_message)p_host_command_parser.p_method_map.get(T_host_command_pb.get_host_command_code(l_message)).invoke(hci, l_message)
                System.out.println(tid_str + "Exited " + T_host_command_pb.get_host_command_code(l_message) + " command handler")

                System.out.println(tid_str + "HC RSP length [" + String.format("%02X", l_host_command_response.p_message_b.length) + "]")
                System.out.println(tid_str + "HC RSP code   [" + T_host_command_pb.get_host_command_code(l_host_command_response) + "]")
                System.out.println(tid_str + "HC RSP data   [" + T_host_command_pb.get_host_command_data(l_host_command_response) + "]")

                T_message l_host_command_response_sent = T_host_command_pb.prepare_response_final(l_host_command_response)
                System.out.println(tid_str + "SND BIN [" + new String(l_host_command_response_sent.p_message_header_b) + new String(l_host_command_response_sent.p_message_b) + "]")
                System.out.println(tid_str + "SND HEX [" + DatatypeConverter.printHexBinary(T_crypto_utils.concat(l_host_command_response_sent.p_message_header_b, l_host_command_response_sent.p_message_b)) + "]")
                l_buffer_out.write(T_crypto_utils.concat(l_host_command_response_sent.p_message_header_b, l_host_command_response_sent.p_message_b))
                l_buffer_out.flush()
                l().log_info(s.Response_sent)
            }
        } catch (Exception e) {
            System.out.println(e.getMessage())
        }
        finally {
            try {
                l_buffer_in.close()
                //l_buffer_out.close()
                p_service_socket.close()
                System.out.println("TID" + p_thread_id + " closed connection.")
            } catch (IOException ioe) {
                ioe.printStackTrace()
            }
        }

    }

}
