<?php

namespace Package\User;

use \Package\CCMS\Response;
use \Package\CCMS\Request;
use \Package\Database;
use \Package\User;
use \PDO;

class AccountManager
{
    public static function registerNewToken($uid, $ip)
    {
        // Kill other tokens from this uid
        $stmt = Database::Instance()->prepare("UPDATE tokens SET forcekill=1 WHERE uid=:uid;");
        $stmt->bindParam(":uid", $uid);
        $stmt->execute();
        AccountManager::removeBadTokens();
        
        $token = "";
        $tokenIsAvailable = false;
        
        while (!$tokenIsAvailable) {
            $token = bin2hex(openssl_random_pseudo_bytes(16));
            
            $stmt = Database::Instance()->prepare("SELECT * FROM tokens WHERE tid=:tid;");
            $stmt->bindParam(":tid", $token);
            $stmt->execute();$stmt->setFetchMode(PDO::FETCH_ASSOC);
            
            $tokenIsAvailable = count($stmt->fetchAll()) == 0;
        }
        
        $now = date("Y-m-d", time());
        $end = date("Y-m-d", time()+3600*24*30); // 30-day expiry
        
        $stmt = Database::Instance()->prepare("INSERT INTO tokens VALUES (:uid, :tid, :ip, :start, :expire, 0);");
        $stmt->bindParam(":uid", $uid);
        $stmt->bindParam(":tid", $token);
        $stmt->bindParam(":ip", $ip);
        $stmt->bindParam(":start", $now);
        $stmt->bindParam(":expire", $end);
        $stmt->execute();
        
        return $token;
    }
    
    public static function removeBadTokens()
    {
        $now = date("Y-m-d", time());
        $stmt = Database::Instance()->prepare("DELETE FROM tokens WHERE expire<=:now OR forcekill!=0;");
        $stmt->bindParam(":now", $now);
        $stmt->execute();
    }
    
    public static function validateToken($token, $ip)
    {
        AccountManager::removeBadTokens();
        
        $stmt = Database::Instance()->prepare("SELECT * FROM tokens WHERE tid=:tid AND source_ip=:ip;");
        $stmt->bindParam(":tid", $token);
        $stmt->bindParam(":ip", $ip);
        $stmt->execute();$stmt->setFetchMode(PDO::FETCH_ASSOC);
        
        return count($stmt->fetchAll()) == 1;
    }
    
    public static function hookNewToken(Request $request)
    {
        if (!isset($_POST["email"]) or !isset($_POST["password"])) {
            return new Response("FALSE");
        }
        $user = User::userFromEmail($_POST["email"]);
        
        if (!$user->authenticate($_POST["password"])) {
            return new Response("FALSE");
        }
        
        return new Response(AccountManager::registerNewToken($user->uid, $_SERVER["REMOTE_ADDR"]));
    }
}
