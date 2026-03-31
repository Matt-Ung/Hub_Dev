"""
Helper: try_decode_blob.py
Usage: place a raw blob binary file (e.g. blob_0x140004010.bin) next to this script and run:
    python3 try_decode_blob.py blob_0x140004010.bin

It will attempt:
 - base64 detection/decoding
 - repeating-key XOR guessing (keysizes 1..8) with the key guessed per-column by maximizing printable fraction
 - single-byte XOR bruteforce
 - print best printable candidates

This is a small, non-exhaustive helper for analyst triage.
"""
import sys
import base64
import math

BASE64_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


def printable_fraction(b):
    if not b:
        return 0.0
    good = 0
    for x in b:
        if 0x20 <= x <= 0x7e or x in (0x09, 0x0a, 0x0d):
            good += 1
    return good / float(len(b))


def try_base64(b):
    score = sum(1 for x in b if x in BASE64_CHARS) / float(len(b))
    print('base64-char-score:', score)
    if score > 0.7:
        try:
            dec = base64.b64decode(b, validate=True)
            print('base64 decode successful, printable_frac=', printable_fraction(dec))
            print(dec[:200])
        except Exception as e:
            print('base64 decode failed:', e)


def guess_repeating_xor(b, max_key=8):
    best_overall = None
    for k in range(1, min(max_key, len(b)) + 1):
        key = []
        for pos in range(k):
            col = b[pos::k]
            best_byte = None
            best_frac = -1
            for cand in range(256):
                x = bytes([c ^ cand for c in col])
                frac = printable_fraction(x)
                if frac > best_frac:
                    best_frac = frac
                    best_byte = cand
            key.append(best_byte)
        # apply key
        dec = bytes([b[i] ^ key[i % k] for i in range(len(b))])
        frac = printable_fraction(dec)
        if best_overall is None or frac > best_overall[0]:
            best_overall = (frac, k, bytes(key), dec[:200])
    return best_overall


def single_byte_xor(b):
    best = None
    for cand in range(256):
        dec = bytes([x ^ cand for x in b])
        frac = printable_fraction(dec)
        if best is None or frac > best[0]:
            best = (frac, cand, dec[:200])
    return best


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: try_decode_blob.py blob.bin')
        sys.exit(1)
    path = sys.argv[1]
    with open(path, 'rb') as f:
        b = f.read()
    print('len:', len(b))
    print('\n-- base64 test --')
    try_base64(b)
    print('\n-- single-byte xor best --')
    s = single_byte_xor(b[:256])
    print(s[0], s[1], s[2])
    print('\n-- repeating-key xor guess --')
    r = guess_repeating_xor(b)
    print('best_repeat_frac:', r[0], 'keylen:', r[1], 'key:', r[2])
    print(r[3])
