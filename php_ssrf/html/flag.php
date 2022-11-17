<?php
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') die("Only for localhost user.");
?>

<?php
echo "FLAG:", getenv('FLAG');