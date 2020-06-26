<?php
$basepath = '/var/www/html/';
$realBase = realpath($basepath);
$item = '....//....//....//....//....//....//....//....//etc/passwd';
$userpath = $basepath . $item;
$realUserPath = realpath($userpath);

if ($realUserPath === false || strpos($realUserPath, $realBase) !== 0) {
    echo $basepath;
} else {
    echo $realUserPath;
    //Good path!
}



?>