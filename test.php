<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

$key='shdM#9odQa/**5wng0dX+';

require_once 'crypto.php';

$plaintext='abcd';

//---------------------------------------------

$ciphertext=encrypt($plaintext, $key);

file_put_contents('ciphertext.enc', $ciphertext);

//---------------------------------------------

$ciphertext=file_get_contents('ciphertext.enc');

$plaintext=decrypt($ciphertext, $key);

if($plaintext===False) echo 'Decryption error!';
else echo 'Plaintext: ', $plaintext;

//---------------------------------------------

?>