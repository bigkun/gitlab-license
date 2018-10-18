<?php

class License
{

    const GITLAB_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Hxv3MkkZbMrKtIs6np9
ccP4OwGBkNhIvhPjcQP48hbbascv5RqsOquQGrYSD2ZrE/kbkRdkIcoHEeTZLif+
bDKFZFI7o5x0H92o9/GSvxHJhQ8mkmvwxD7lssGShwZEm8WG+U7BZqUV/gGmCDqe
9W8H8Fq2B0ck8IXjbQ4Zz+JlyV/NHZTZcs69plFiLKh4N6GYVftOVwSomh0bbypP
OB9WnLC7RC9a2LRrhtf8sqa2rRFmtyMMfgFFzLMzS+w+1K4+QLnWP1gKQVzaFnzk
pnwKPrqbGFYbRztIVEWbs8jPYlLkGb8ME4C84YVtQgbQcbyisU/VW3wUGkhT+J0k
xwIDAQAB
-----END PUBLIC KEY-----';


    const YOUR_PUBLIC_KEY = '----';

    const YOUR_PRIVATE_KEY = '----';

    /**
     * @param string $license
     * @return string
     */
    public static function decrypt(string $license)
    {

        $json_data = base64_decode($license);

        $encryption_data = json_decode($json_data, true);

        $encrypted_data = base64_decode($encryption_data["data"]);

        $encrypted_key = base64_decode($encryption_data["key"]);

        $aes_iv = base64_decode($encryption_data["iv"]);

        openssl_public_decrypt($encrypted_key, $aes_key, openssl_pkey_get_public(self::GITLAB_PUBLIC_KEY));

        $data = openssl_decrypt(
            $encrypted_data,
            'aes-128-cbc',
            $aes_key,
            OPENSSL_RAW_DATA,
            $aes_iv
        );

        return $data;
    }


    /**
     * @param array $license
     * @return string
     */
    public static function encrypt(array $license)
    {

        $encryption_data = json_encode($license);

        $hex_iv = self::hexToStr('CA5328D7739776848CECA367A7716B13');

        $key = self::hexToStr('27C0D46688610BBD66497D10D20A94DB');

        $data = openssl_encrypt(
            $encryption_data,
            'aes-128-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $hex_iv
        );

        openssl_private_encrypt($key, $encrypted, openssl_pkey_get_private(self::YOUR_PRIVATE_KEY));

        return base64_encode(json_encode([
            "data" => base64_encode($data),
            'key' => base64_encode($encrypted),
            'iv' => base64_encode($hex_iv)
        ]));

    }


    static function hexToStr(string $hex)
    {
        $string = '';
        for ($i = 0; $i < strlen($hex) - 1; $i += 2) {
            $string .= chr(hexdec($hex[$i] . $hex[$i + 1]));
        }
        return $string;
    }

}