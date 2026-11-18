<?php
/*
 * Copyright 2026 The QuarkPress Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Writes wordpress-7.1.3-hashes.txt: password hashes made by running WordPress's own functions, each with
 * WordPress's answers recorded. Run from the wp-password module:
 *
 *   php src/test/php/make-fixtures.php <wordpress-dir> > src/test/resources/wordpress-7.1.3-hashes.txt
 *
 * <wordpress-dir> is an unpacked WordPress release (the directory holding wp-includes/). Its files are loaded
 * from there at run time and are never copied into this repository. Needs PHP 8.4 with hash, sodium and
 * tokenizer. Salts are random, so two runs differ only in the hash column.
 */

declare(strict_types=1);

if (PHP_VERSION_ID < 80400 || PHP_VERSION_ID >= 80500) {
    fwrite(STDERR, 'make-fixtures needs PHP 8.4, found ' . PHP_VERSION . "\n");
    exit(3);
}
if (2 !== $argc) {
    fwrite(STDERR, "usage: php make-fixtures.php <wordpress-dir>\n");
    exit(2);
}
if (!defined('PASSWORD_ARGON2ID')) {
    fwrite(STDERR, "make-fixtures needs PHP built with Argon2 (PASSWORD_ARGON2ID)\n");
    exit(4);
}

define('ABSPATH', rtrim($argv[1], '/') . '/');
define('WPINC', 'wp-includes');
define('QP_WP', ABSPATH . WPINC . '/');

// The few environment functions WordPress code expects from a full install.
function __($text, $domain = 'default')
{
    return $text;
}

function _doing_it_wrong($function_name, $message, $version)
{
    fwrite(STDERR, 'WordPress notice: ' . $function_name . ': ' . $message . "\n");
    exit(5);
}

function get_option($option, $default_value = false)
{
    return 'blog_charset' === $option ? 'UTF-8' : $default_value;
}

/**
 * Loads selected top-level functions from a PHP file that cannot be included as a whole: the file is tokenized,
 * each requested function's source is cut out by brace matching, and only those snippets are evaluated.
 */
function qp_load_functions(string $file, array $names): void
{
    $isOpen = static fn (array|string $token): bool => '{' === $token
        || (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true));
    if (!function_exists('token_get_all')) {
        throw new RuntimeException('the tokenizer extension is required');
    }
    $source = file_get_contents($file);
    if (false === $source) {
        throw new RuntimeException('cannot read ' . $file);
    }
    $tokens = token_get_all($source);
    $count = count($tokens);
    $wanted = array_fill_keys($names, true);
    $loaded = [];
    $depth = 0;
    for ($i = 0; $i < $count; $i++) {
        $token = $tokens[$i];
        if ($isOpen($token)) {
            $depth++;
            continue;
        }
        if ('}' === $token) {
            $depth--;
            continue;
        }
        if (0 !== $depth || !is_array($token) || T_FUNCTION !== $token[0]) {
            continue;
        }
        $j = $i + 1;
        while ($j < $count && is_array($tokens[$j]) && T_WHITESPACE === $tokens[$j][0]) {
            $j++;
        }
        if ($j >= $count || !is_array($tokens[$j]) || T_STRING !== $tokens[$j][0] || !isset($wanted[$tokens[$j][1]])) {
            continue;
        }
        $code = '';
        $level = 0;
        for ($k = $i; $k < $count; $k++) {
            $piece = $tokens[$k];
            $code .= is_array($piece) ? $piece[1] : $piece;
            if ($isOpen($piece)) {
                $level++;
            } elseif ('}' === $piece && 0 === --$level) {
                break;
            }
        }
        eval($code);
        $loaded[$tokens[$j][1]] = true;
        $i = $k;
    }
    $missing = array_diff($names, array_keys($loaded));
    if ([] !== $missing) {
        throw new RuntimeException('not found in ' . $file . ': ' . implode(', ', $missing));
    }
}

require QP_WP . 'version.php';
require QP_WP . 'plugin.php';
qp_load_functions(QP_WP . 'functions.php', ['wp_fast_hash', 'wp_verify_fast_hash']);
require QP_WP . 'pluggable.php';
require QP_WP . 'class-phpass.php';

/** A bcrypt salt of 22 characters, taken from a fresh password_hash() so it uses bcrypt's own alphabet. */
function qp_bcrypt_salt(): string
{
    return substr(password_hash('salt', PASSWORD_BCRYPT, ['cost' => 4]), 7, 22);
}

/** A salt for crypt()'s $1$, $5$ and $6$ forms: 8 characters of [./0-9A-Za-z]. */
function qp_crypt_salt(): string
{
    $alphabet = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    $salt = '';
    foreach (str_split(random_bytes(8)) as $byte) {
        $salt .= $alphabet[ord($byte) & 63];
    }
    return $salt;
}

/** crypt(), failing loudly instead of returning a failure marker. */
function qp_crypt(string $password, string $setting): string
{
    $hash = crypt($password, $setting);
    if (strlen($hash) < 13 || !str_starts_with($hash, substr($setting, 0, 3))) {
        throw new RuntimeException('crypt() refused the setting ' . $setting);
    }
    return $hash;
}

$passwords = [
    'ascii' => 'correct horse',
    'utf8' => "p\u{E4}ssw\u{F6}rd \u{1F511}",
    'quote' => "O'Brien",
    'long100' => str_repeat('0123456789', 10),
];
// WordPress's screens and REST API hash the slashed password (addslashes), so O'Brien is stored as O\'Brien.
$stored = static fn (string $key, string $password): string => 'quote' === $key ? addslashes($password) : $password;
$phpass = new PasswordHash(8, true);

/** @var list<array{string, string, string, string}> $rows id, form, password, hash */
$rows = [];
$add = static function (string $id, string $form, string $password, string $hash) use (&$rows): void {
    $rows[] = [$id, $form, $password, $hash];
};

foreach ($passwords as $key => $password) {
    $add('wp-' . $key, 'wp', $password, wp_hash_password($stored($key, $password)));
}
foreach ($passwords as $key => $password) {
    $add('phpass-' . $key, 'phpass', $password, $phpass->HashPassword($stored($key, $password)));
}
foreach ($passwords as $key => $password) {
    $add('md5-' . $key, 'md5', $password, md5($stored($key, $password)));
}
foreach ($passwords as $key => $password) {
    $add('bcrypt-' . $key, 'bcrypt', $password, password_hash($stored($key, $password), PASSWORD_BCRYPT, ['cost' => 10]));
}
$add('bcrypt2a-ascii', 'bcrypt', $passwords['ascii'], qp_crypt($passwords['ascii'], '$2a$10$' . qp_bcrypt_salt()));
$add('bcrypt2b-ascii', 'bcrypt', $passwords['ascii'], qp_crypt($passwords['ascii'], '$2b$10$' . qp_bcrypt_salt()));

// The reverse of the screen form: O'Brien hashed unslashed, as a path that does not slash would write it.
$add('wp-quote-unslashed', 'wp', $passwords['quote'], wp_hash_password($passwords['quote']));
$add('phpass-quote-unslashed', 'phpass', $passwords['quote'], $phpass->HashPassword($passwords['quote']));
$add('md5-quote-unslashed', 'md5', $passwords['quote'], md5($passwords['quote']));
$add('bcrypt-quote-unslashed', 'bcrypt', $passwords['quote'],
    password_hash($passwords['quote'], PASSWORD_BCRYPT, ['cost' => 10]));

// A stored hash of 32 bytes that is not hex: wp_check_password compares it with the MD5 and fails.
$add('md5-nonhex32', 'md5', $passwords['ascii'], str_repeat('z', 32));

// A wrong password against each accepted form.
foreach (['wp', 'phpass', 'md5', 'bcrypt', 'bcrypt2a', 'bcrypt2b'] as $prefix) {
    foreach ($rows as [$id, $form, , $hash]) {
        if ($id === $prefix . '-ascii') {
            $add($prefix . '-wrong', $form, 'correct horse battery', $hash);
        }
    }
}

// wp_hash_password trims the password before hashing; wp_check_password does not trim.
$trimmed = wp_hash_password(' pw ');
$add('wp-trim-spaced', 'wp', ' pw ', $trimmed);
$add('wp-trim-bare', 'wp', 'pw', $trimmed);

// Plain bcrypt reads only the first 72 bytes; the $wp$ pre-hash covers every byte.
$truncated = substr($passwords['long100'], 0, 72) . 'abcdefghijklmnopqrstuvwxyz01';
foreach (['wp', 'bcrypt'] as $prefix) {
    foreach ($rows as [$id, $form, , $hash]) {
        if ($id === $prefix . '-long100') {
            $add($prefix . '-long100-after72', $form, $truncated, $hash);
        }
    }
}

// wp_check_password compares a stored hash of 32 bytes or fewer with the MD5 before it limits the length.
$long4097 = str_repeat('a', 4097);
$add('md5-long4097', 'md5', $long4097, md5($long4097));

// Forms WordPress never writes; its answer is recorded all the same.
$add('refused-2x', 'bcrypt-2x', $passwords['ascii'], qp_crypt($passwords['ascii'], '$2x$10$' . qp_bcrypt_salt()));
$add('refused-1', 'md5-crypt', $passwords['ascii'], qp_crypt($passwords['ascii'], '$1$' . qp_crypt_salt() . '$'));
$add('refused-5', 'sha256-crypt', $passwords['ascii'], qp_crypt($passwords['ascii'], '$5$' . qp_crypt_salt() . '$'));
$add('refused-6', 'sha512-crypt', $passwords['ascii'], qp_crypt($passwords['ascii'], '$6$' . qp_crypt_salt() . '$'));
$add('refused-argon2id', 'argon2id', $passwords['ascii'], password_hash($passwords['ascii'], PASSWORD_ARGON2ID));
$phpbbSetting = '$H$' . substr($phpass->HashPassword($passwords['ascii']), 3, 9);
$add('refused-phpbb', 'phpbb', $passwords['ascii'], $phpass->crypt_private($passwords['ascii'], $phpbbSetting));
$add('refused-generic', 'generic', $passwords['ascii'], wp_fast_hash($passwords['ascii']));
// Work above QuarkPress's bounds. WordPress computes these; QuarkPress refuses them without computing.
// bcrypt cost 17 is the lowest above QuarkPress's bound of 16 (cost 31 would take WordPress about a day per check).
$add('refused-bcrypt-cost17', 'bcrypt', $passwords['ascii'],
    password_hash($passwords['ascii'], PASSWORD_BCRYPT, ['cost' => 17]));
// phpass count J (2^20 rounds) is the lowest above QuarkPress's bound of I; S (2^30) is the highest phpass allows.
foreach (['J', 'S'] as $count) {
    $setting = '$P$' . $count . substr($phpass->HashPassword($passwords['ascii']), 4, 8);
    $add('refused-phpass-count' . $count, 'phpass', $passwords['ascii'],
        $phpass->crypt_private($passwords['ascii'], $setting));
}
$add('refused-empty', 'empty', $passwords['ascii'], '');
$add('refused-star', 'star', $passwords['ascii'], '*');

$bool = static fn (bool $value): string => $value ? 'true' : 'false';
$field = static fn (string $value): string => '' === $value ? '<empty>' : $value;

echo '# WordPress ', $wp_version, ' password hashes, produced by running WordPress; regenerate with',
    " `php src/test/php/make-fixtures.php <dir>`.\n";
echo '# PHP ', PHP_VERSION, ', date ', gmdate('Y-m-d'), ', SHA-256 of wp-includes/pluggable.php ',
    hash_file('sha256', QP_WP . 'pluggable.php'), ', of wp-includes/class-phpass.php ',
    hash_file('sha256', QP_WP . 'class-phpass.php'), ".\n";
echo "# Made by: wp_hash_password with no filter (wp), PasswordHash(8, true)->HashPassword (phpass), md5() (md5),\n";
echo "#   password_hash(PASSWORD_BCRYPT, cost 10 or 17) or crypt() with a \$2a\$/\$2b\$ setting (bcrypt), crypt()\n";
echo "#   (bcrypt-2x, md5-crypt, sha256-crypt, sha512-crypt), password_hash(PASSWORD_ARGON2ID) (argon2id),\n";
echo "#   PasswordHash::crypt_private with a \$H\$ setting (phpbb) or a \$P\$J/\$P\$S setting (phpass counts),\n";
echo "#   wp_fast_hash (generic). In the *-quote rows O'Brien is hashed as addslashes(\"O'Brien\"), the form WordPress's\n";
echo "#   screens and REST API pass to the hash functions; the *-quote-unslashed rows hash it as is.\n";
echo "# Columns, separated by one space:\n";
echo "#   id form password-hex hash wp_check_password(pw) wp_check_password(addslashes(pw)) wp_password_needs_rehash(hash)\n";
echo "#   password-hex is the password's bytes in hex; <empty> stands for the empty string.\n";
echo "# Known differences: QuarkPress refuses these forms although WordPress's wp_check_password accepts them:\n";
echo "#   W1 (lib-wp-password D1): refused-2x.\n";
echo "#   W2 (lib-wp-password D2): refused-1, refused-5, refused-6, refused-argon2id.\n";
echo "#   W3 (lib-wp-password D3): refused-bcrypt-cost17.\n";
echo "#   W4 (lib-wp-password D8): refused-phpass-countJ, refused-phpass-countS.\n";

foreach ($rows as [$id, $form, $password, $hash]) {
    $check = wp_check_password($password, $hash);
    $slashed = addslashes($password);
    $checkSlashed = $slashed === $password ? $check : wp_check_password($slashed, $hash);
    echo implode(' ', [
        $id,
        $form,
        $field(bin2hex($password)),
        $field($hash),
        $bool($check),
        $bool($checkSlashed),
        $bool(wp_password_needs_rehash($hash)),
    ]), "\n";
}
