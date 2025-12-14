#!/usr/bin/env python3

from __future__ import annotations

import re
import socket
import sys
import time
from dataclasses import dataclass

from Crypto.Util.number import isPrime


HOST = "yukari.seccon.games"
PORT = 15809

BASES = tuple(range(2, 100, 2))


def v2(n: int) -> int:
    c = 0
    while n & 1 == 0:
        n >>= 1
        c += 1
    return c


def v2_order(a: int, p: int) -> int:
    s = v2(p - 1)
    m = (p - 1) >> s
    x = pow(a % p, m, p)
    if x == 1:
        return 0
    j = 0
    while x != 1:
        x = pow(x, 2, p)
        j += 1
        if j > s:
            raise RuntimeError("unexpected v2_order overflow")
    return j


def fingerprint_js(p: int) -> tuple[int, tuple[int, ...]]:
    s = v2(p - 1)
    js = tuple(v2_order(a, p) for a in BASES)
    return s, js


def matches_fingerprint(q: int, s_p: int, js_p: tuple[int, ...]) -> bool:
    if v2(q - 1) != s_p:
        return False
    for a, j in zip(BASES, js_p, strict=True):
        if v2_order(a, q) != j:
            return False
    return True


@dataclass(frozen=True)
class PariCtx:
    s: int
    nf: object
    bnf: object
    class_no: int
    m_col: object


@dataclass(frozen=True)
class PariEnv:
    pari: object
    Bodd: int
    ctxs: dict[int, PariCtx]


def build_pari_env(max_s: int) -> PariEnv:
    try:
        from cypari2 import Pari
    except Exception as e:  # pragma: no cover
        raise SystemExit(
            "cypari2 import failed. Run with:\n"
            "  PYTHONPATH=/tmp/yukuri_venv/lib/python3.12/site-packages python3 solve.py\n"
        ) from e

    pari = Pari()
    pari.allocatemem(1_200_000_000)
    pari("default(realprecision, 200)")

    primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    Bodd = 1
    for r in primes:
        Bodd *= r

    ctxs: dict[int, PariCtx] = {}

    # s=1 handled without PARI.
    for s in range(2, max_s + 1):
        n = 1 << s
        pari(f"pol_{s} = polcyclo({n});")
        pari(f"nf_{s} = nfinit(pol_{s});")
        pari(f"bnf_{s} = bnfinit(pol_{s}, 1);")
        class_no = int(pari(f"bnf_{s}.no"))
        m_col = pari(f"nfalgtobasis(nf_{s}, {Bodd}*(1 - Mod(x, pol_{s}))^3)")
        ctxs[s] = PariCtx(
            s=s,
            nf=pari(f"nf_{s}"),
            bnf=pari(f"bnf_{s}"),
            class_no=class_no,
            m_col=m_col,
        )

    return PariEnv(pari=pari, Bodd=Bodd, ctxs=ctxs)


def find_q_for_p(p: int, env: PariEnv, max_s: int) -> int:
    s_p, js_p = fingerprint_js(p)
    if s_p > max_s:
        raise ValueError(f"v2(p-1)={s_p} exceeds max_s={max_s}")

    # s=1: integer progression.
    if s_p == 1:
        step = 8 * env.Bodd
        for t in range(1, 200_000):
            q = p + step * t
            if q == p:
                continue
            if q.bit_length() < 1024:
                continue
            if not isPrime(q):
                continue
            if matches_fingerprint(q, s_p, js_p):
                return q
        raise RuntimeError("failed to find q for s=1")

    ctx = env.ctxs[s_p]
    pari = env.pari

    ideals = pari("idealprimedec")(ctx.nf, p)
    for P in ideals:
        if ctx.class_no == 1:
            alpha = pari("bnfisprincipal")(ctx.bnf, P)[1]
        else:
            Pk = pari("idealpow")(ctx.nf, P, ctx.class_no)
            alpha = pari("bnfisprincipal")(ctx.bnf, Pk)[1]

        for k in range(1, 50_000):
            cand = alpha + ctx.m_col * k
            q = int(abs(pari("nfeltnorm")(ctx.nf, cand)))
            if q == p:
                continue
            if q.bit_length() < 1024:
                continue
            if not isPrime(q):
                continue
            if matches_fingerprint(q, s_p, js_p):
                return q

    raise RuntimeError(f"failed to find q for v2(p-1)={s_p}")


def solve_once(max_s: int, env: PariEnv) -> tuple[bool, bytes]:
    sock = socket.create_connection((HOST, PORT), timeout=20)
    sock.settimeout(20)
    buf = b""
    try:
        while True:
            while b"q: " not in buf and b"key setup successful" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    return True, buf
                buf += chunk

            if b"key setup successful" in buf:
                return False, buf

            m = re.search(rb"p = ([0-9]+)", buf)
            if not m:
                return False, buf
            p = int(m.group(1))

            s_p = v2(p - 1)
            if s_p > max_s:
                return False, buf

            q = find_q_for_p(p, env, max_s=max_s)
            sock.sendall(str(q).encode() + b"\n")

            idx = buf.index(b"q: ") + 3
            buf = buf[idx:]
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main() -> None:
    max_s = 6
    env = build_pari_env(max_s=max_s)

    for attempt in range(1, 50):
        ok, out = solve_once(max_s=max_s, env=env)
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        if ok and b"SECCON" in out:
            return
        time.sleep(0.2)

    raise SystemExit("gave up after many retries")


if __name__ == "__main__":
    main()