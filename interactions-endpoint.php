<?php
    define("CLIENT_PUBLIC_KEY", "❓❓❓");

    include("❓❓❓/vendor/autoload.php");

    error_reporting(E_ALL);
    ini_set("log_errors", 1);
    ini_set("error_log", "errors.log");

    use phpseclib3\Crypt\EC;

    $Request = json_decode(file_get_contents('php://input'), true);
    error_log("Request: ".json_encode($Request));

    function IsRequestValid(){
        $signature = $_SERVER['HTTP_X_SIGNATURE_ED25519'];
        $timestamp = $_SERVER['HTTP_X_SIGNATURE_TIMESTAMP'];
        $rawBody = file_get_contents('php://input');

        $public = EC::loadFormat('libsodium', hex2bin(CLIENT_PUBLIC_KEY));
        return $public->verify($timestamp.$rawBody, hex2bin($signature)) == TRUE;
    }

    if(IsRequestValid()){
        error_log("VALID REQUEST");
        header('Content-Type: application/json; charset=utf-8');
        $Output = array();

        $type = (int)$Request["type"];
        switch($type){
            case 1:
                $Output = array("type" => 1);
                break;
        } 

        error_log("OUTPUT: ".json_encode($Output));
        echo json_encode($Output);
    }else{
        error_log("INVALID REQUEST");
        http_response_code(401);
        echo "Invalid Request!";
    }

?>
