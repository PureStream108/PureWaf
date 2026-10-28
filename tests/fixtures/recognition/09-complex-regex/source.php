<?php
if (isset($_GET['f']) && !preg_match('/flag|file|php|data|zip|phar|(proc|dev|bin|usr|var).{15,}/i', $_GET['f'])) {
    include $_GET['f'];
}
