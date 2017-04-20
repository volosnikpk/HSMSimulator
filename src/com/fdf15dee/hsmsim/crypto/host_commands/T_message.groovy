package com.fdf15dee.hsmsim.crypto.host_commands

import com.fdf15dee.hsmsim.main.T_hsm_base_6_util

import javax.xml.bind.DatatypeConverter

class T_message extends T_hsm_base_6_util {
    public byte[] p_message_b
    public String p_message_s
    public byte[] p_message_header_b
    public String p_message_header_s

    T_message(byte[] i_message) {
        p_message_b = Arrays.copyOfRange(i_message, MSG_HEADER_LENGTH_FULL, i_message.length)
        p_message_header_b = Arrays.copyOfRange(i_message, 0, MSG_HEADER_LENGTH_FULL)
        p_message_s = new String(p_message_b)
        p_message_header_s = new String(p_message_header_b)
    }

    T_message(byte[] i_message_header, byte[] i_message_body) {
        if (i_message_header == GC_NULL_OBJ_REF) {
            p_message_header_s == "        "
            p_message_header_b = p_message_header_s.getBytes()
        } else {
            p_message_b = i_message_body
            p_message_header_b = i_message_header
            p_message_s = new String(p_message_b)
            p_message_header_s = new String(p_message_header_b)
        }
    }

    T_message(T_message i_request, byte[] i_response_body) {
        p_message_b = i_response_body
        p_message_header_b = i_request.p_message_header_b
        p_message_s = new String(p_message_b)
        p_message_header_s = new String(p_message_header_b)
    }

}
