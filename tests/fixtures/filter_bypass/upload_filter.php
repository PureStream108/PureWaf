<?php
$data = $_GET['data'] ?? '';
if (preg_match("/'| |_|php|;|~|\\^|\\+|eval|{|}/i", $data)) {
    die('blocked');
}
file_put_contents(__DIR__ . '/index.php', $data);
?>
