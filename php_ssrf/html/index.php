<form action="/index.php">
    <input class="input" type="text" name="url" value="<?= $_GET['url'] ?? '' ?>" placeholder="https://example.com">
</form>
<br>

<a href="/flag.php"> Flag Here</a>

<?php if (isset($_GET['url'])) : ?>
    <?php
    $ch = curl_init($url = $_GET['url']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $html = curl_exec($ch);
    ?>
    
    <pre><?= htmlentities($html) ?></pre>
    <?php curl_close($ch); ?>
<?php endif; ?>