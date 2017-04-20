package com.fdf15dee.hsmsim.crypto.utils

import com.fdf15dee.hsmsim.main.T_hsm_base_6_util

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class T_des extends T_hsm_base_6_util {

    public Cipher p_cipher

    T_des(){
        p_cipher = Cipher.getInstance("DES/ECB/NoPadding")
    }

    public byte[] encrypt(byte[] i_data, byte[] i_key){
        p_cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(i_key, "DES"))
        return p_cipher.doFinal(i_data)
    }

    public byte[] decrypt(byte[] i_data, byte[] i_key){
        p_cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(i_key, "DES"));
        return p_cipher.doFinal(i_data)
    }

    public byte[] encrypt_tdes_single(byte[] i_data, T_key i_key){
        byte[] res = encrypt(i_data, i_key.p_a)
        res = decrypt(res, i_key.p_b)
        res = encrypt(res, i_key.p_c)
        return res
    }

    public byte[] decrypt_tdes_single(byte[] i_data, T_key i_key){
        byte[] res = decrypt(i_data, i_key.p_c)
        res = encrypt(res, i_key.p_b)
        res = decrypt(res, i_key.p_a)
        return res
    }

    public byte[] encrypt_tdes(byte[] i_data, T_key i_key){
        if (i_data.length == 8)
            return encrypt_tdes_single(i_data, i_key)
        else if (i_data.length == 16)
            return encrypt_tdes_single(Arrays.copyOfRange(i_data, 0, 8), i_key) +
                   encrypt_tdes_single(Arrays.copyOfRange(i_data, 8, 16), i_key)
        else if (i_data.length == 24)
            return encrypt_tdes_single(Arrays.copyOfRange(i_data, 0, 8), i_key) +
                   encrypt_tdes_single(Arrays.copyOfRange(i_data, 8, 16), i_key) +
                   encrypt_tdes_single(Arrays.copyOfRange(i_data, 16, 24), i_key)
        else
            return i_data

    }

    public byte[] decrypt_tdes(byte[] i_data, T_key i_key){
        if (i_data.length == 8)
            return decrypt_tdes_single(i_data, i_key)
        else if (i_data.length == 16)
            return decrypt_tdes_single(Arrays.copyOfRange(i_data, 0, 8), i_key) +
                   decrypt_tdes_single(Arrays.copyOfRange(i_data, 8, 16), i_key)
        else if (i_data.length == 24)
            return decrypt_tdes_single(Arrays.copyOfRange(i_data, 0, 8), i_key) +
                   decrypt_tdes_single(Arrays.copyOfRange(i_data, 8, 16), i_key) +
                   decrypt_tdes_single(Arrays.copyOfRange(i_data, 16, 24), i_key)
        else
            return i_data
    }

    public byte[] encrypt_tdes_lmk_variant(byte[] i_data, T_key i_key){
        byte[] l_p_bkp = i_key.p_b
        byte[] l_res_a
        byte[] l_res_b
        byte[] l_res_c
        if (i_data.length == 16){
            i_key.p_b = T_crypto_utils.xor(i_key.p_b, get_context().p_lmk_storage.get_variant_double(0, 8))
            l_res_a = encrypt_tdes(Arrays.copyOfRange(i_data, 0, 8), i_key)
            i_key.p_b = T_crypto_utils.xor(l_p_bkp, get_context().p_lmk_storage.get_variant_double(1, 8))
            l_res_b = encrypt_tdes(Arrays.copyOfRange(i_data, 8, 16), i_key)
            return T_crypto_utils.concat(l_res_a, l_res_b)
        } else if (i_data.length == 24) {
            i_key.p_b = T_crypto_utils.xor(i_key.p_b, get_context().p_lmk_storage.get_variant_double(0, 8))
            l_res_a = encrypt_tdes(Arrays.copyOfRange(i_data, 0, 8), i_key)
            i_key.p_b = T_crypto_utils.xor(l_p_bkp, get_context().p_lmk_storage.get_variant_double(1, 8))
            l_res_b = encrypt_tdes(Arrays.copyOfRange(i_data, 8, 16), i_key)
            i_key.p_b = T_crypto_utils.xor(l_p_bkp, get_context().p_lmk_storage.get_variant_double(2, 8))
            l_res_c = encrypt_tdes(Arrays.copyOfRange(i_data, 16, 24), i_key)
            return T_crypto_utils.concat(l_res_a, l_res_b, l_res_c)
        } else
            return i_data

    }

    public byte[] decrypt_tdes_lmk_variant(byte[] i_data, T_key i_key){
        byte[] l_p_bkp = i_key.p_b
        byte[] l_res_a
        byte[] l_res_b
        byte[] l_res_c
        if (i_data.length == 16){
            i_key.p_b = T_crypto_utils.xor(i_key.p_b, get_context().p_lmk_storage.get_variant_double(0, 8))
            l_res_a = decrypt_tdes(Arrays.copyOfRange(i_data, 0, 8), i_key)
            i_key.p_b = T_crypto_utils.xor(l_p_bkp, get_context().p_lmk_storage.get_variant_double(1, 8))
            l_res_b = decrypt_tdes(Arrays.copyOfRange(i_data, 8, 16), i_key)
            return T_crypto_utils.concat(l_res_a, l_res_b)
        } else if (i_data.length == 24){
            i_key.p_b = T_crypto_utils.xor(i_key.p_b, get_context().p_lmk_storage.get_variant_double(0, 8))
            l_res_a = decrypt_tdes(Arrays.copyOfRange(i_data, 0, 8), i_key)
            i_key.p_b = T_crypto_utils.xor(l_p_bkp, get_context().p_lmk_storage.get_variant_double(1, 8))
            l_res_b = decrypt_tdes(Arrays.copyOfRange(i_data, 8, 16), i_key)
            i_key.p_b = T_crypto_utils.xor(l_p_bkp, get_context().p_lmk_storage.get_variant_double(2, 8))
            l_res_c = decrypt_tdes(Arrays.copyOfRange(i_data, 16, 24), i_key)
            return T_crypto_utils.concat(l_res_a, l_res_b, l_res_c)
        } else
            return i_data

    }

    public T_key encrypt_key_under_lmk(byte[] i_key, String i_scheme, Integer i_lmk_pair, Integer i_variant){
        T_key l_lmk = new T_key(get_context().p_lmk_storage.get_lmk_pair_variant(i_lmk_pair, i_variant), KEY_SCHEME_LMK)
        if (i_scheme == KEY_SCHEME_SINGLE ||
                i_scheme == KEY_SCHEME_DOUBLE_ANSI ||
                i_scheme == KEY_SCHEME_TRIPLE_ANSI) {
            return new T_key(encrypt_tdes(i_key, l_lmk), i_scheme)
        } else if (i_scheme == KEY_SCHEME_DOUBLE_VARIANT ||
                 i_scheme == KEY_SCHEME_TRIPLE_VARIANT) {
            return new T_key(encrypt_tdes_lmk_variant(i_key, l_lmk), i_scheme)
        } else
            return new T_key(i_key, i_scheme)
    }

    public T_key decrypt_key_under_lmk(byte[] i_key, String i_scheme, Integer i_lmk_pair, Integer i_variant){
        T_key l_lmk = new T_key(get_context().p_lmk_storage.get_lmk_pair_variant(i_lmk_pair, i_variant), KEY_SCHEME_LMK)
        if (i_scheme == KEY_SCHEME_SINGLE ||
                i_scheme == KEY_SCHEME_DOUBLE_ANSI ||
                i_scheme == KEY_SCHEME_TRIPLE_ANSI) {
            return new T_key(decrypt_tdes(i_key, l_lmk), i_scheme)
        }
        else if (i_scheme == KEY_SCHEME_DOUBLE_VARIANT ||
                i_scheme == KEY_SCHEME_TRIPLE_VARIANT) {
            return new T_key(decrypt_tdes_lmk_variant(i_key, l_lmk), i_scheme)
        } else
            return new T_key(i_key, i_scheme)
    }

}
