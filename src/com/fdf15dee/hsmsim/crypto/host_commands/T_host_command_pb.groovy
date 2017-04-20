package com.fdf15dee.hsmsim.crypto.host_commands

import com.fdf15dee.hsmsim.main.T_hsm_base_6_util

import java.lang.reflect.Method

public class T_host_command_pb extends T_hsm_base_6_util {

    public Map<String, Method> p_method_map = new HashMap<String, Method>()

    T_host_command_pb() {
        p_method_map.put(DIAG_REQ, T_host_command_implementation.class.getMethod(DIAG_REQ, T_message.class))
        p_method_map.put(GEN_KEY_CHECK_VALUE_REQ, T_host_command_implementation.class.getMethod(GEN_KEY_CHECK_VALUE_REQ, T_message.class))
        p_method_map.put(GEN_CVV_REQ, T_host_command_implementation.class.getMethod(GEN_CVV_REQ, T_message.class))
        p_method_map.put(ENC_CLEAR_PIN_LMK_REQ, T_host_command_implementation.class.getMethod(ENC_CLEAR_PIN_LMK_REQ, T_message.class))
        p_method_map.put(DEC_ENCRYPTED_PIN_LMK_REQ, T_host_command_implementation.class.getMethod(DEC_ENCRYPTED_PIN_LMK_REQ, T_message.class))
        p_method_map.put(GEN_IBM_PIN_OFFSET_REQ, T_host_command_implementation.class.getMethod(GEN_IBM_PIN_OFFSET_REQ, T_message.class))
        p_method_map.put(VRF_IBM_PIN_OFFSET_REQ, T_host_command_implementation.class.getMethod(VRF_IBM_PIN_OFFSET_REQ, T_message.class))
        p_method_map.put(TRN_PIN_LMK_TO_ZPK_REQ, T_host_command_implementation.class.getMethod(TRN_PIN_LMK_TO_ZPK_REQ, T_message.class))
        p_method_map.put(VRF_ARQC_GEN_ARPC_REQ, T_host_command_implementation.class.getMethod(VRF_ARQC_GEN_ARPC_REQ, T_message.class))
    }

    public static String get_host_command_code(T_message i_message) {
        if (i_message == GC_NULL_OBJ_REF)
            return GC_EMPTY_STRING
        return new String(Arrays.copyOfRange(i_message.p_message_b, 0, 2))
    }

    public static String get_host_command_data(T_message i_message) {
        if (i_message == GC_NULL_OBJ_REF)
            return i_message
        return new String(Arrays.copyOfRange(i_message.p_message_b, 2, i_message.p_message_b.length))
    }

    public static T_message prepare_response_final(T_message i_message) {
        T_message l_response = new T_message(i_message.p_message_header_b, i_message.p_message_b)
        l_response.p_message_header_b[1] = (byte)(l_response.p_message_b.length + MSG_HEADER_LENGTH)
        return l_response
    }

}
