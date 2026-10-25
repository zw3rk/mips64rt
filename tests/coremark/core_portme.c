/* CoreMark MIPS64 N64 port implementation for mips64rt (Phase 7 H3).
 *
 * Bare ee_printf (no stdio), microsecond timer over
 * clock_gettime(CLOCK_MONOTONIC), heap via malloc/free, byte output via
 * the write(2) syscall to stdout. No filesystem use.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _POSIX_C_SOURCE 200809L

#include <math.h>
#include <stdlib.h>
#include <unistd.h>

#include "coremark.h"

ee_u32 default_num_contexts = 1;

/* ------------------------------------------------------------------ */
/* Heap (MEM_METHOD == MEM_MALLOC).                                    */
/* ------------------------------------------------------------------ */
void *
portable_malloc(ee_size_t size)
{
    return malloc(size);
}

void
portable_free(void *p)
{
    free(p);
}

/* ------------------------------------------------------------------ */
/* Timer (USE_CLOCK == 0 path would use clock(); we use the raw        */
/* clock_gettime pair directly for microsecond resolution).            */
/* ------------------------------------------------------------------ */
#define H3_TICKS_PER_SEC 1000000ULL

static struct timespec h3_start_time;
static struct timespec h3_stop_time;

void
start_time(void)
{
    (void)clock_gettime(CLOCK_MONOTONIC, &h3_start_time);
}

void
stop_time(void)
{
    (void)clock_gettime(CLOCK_MONOTONIC, &h3_stop_time);
}

CORE_TICKS
get_time(void)
{
    long long ds = (long long)h3_stop_time.tv_sec - (long long)h3_start_time.tv_sec;
    long long dn = (long long)h3_stop_time.tv_nsec - (long long)h3_start_time.tv_nsec;
    long long us = ds * 1000000LL + dn / 1000LL;
    if (us < 0)
        us = 0;
    return (CORE_TICKS)us;
}

secs_ret
time_in_secs(CORE_TICKS ticks)
{
    return (secs_ret)ticks / (secs_ret)H3_TICKS_PER_SEC;
}

/* ------------------------------------------------------------------ */
/* Bare formatted output. Supports flags '-', '+', ' ', '0', '#';      */
/* width and precision (including '*'); length modifiers h, hh, l,     */
/* ll, z, t; conversions d, i, u, o, x, X, c, s, p, f, F, e, E,        */
/* g, G, %. Floats print via integer arithmetic (no stdio).            */
/* ------------------------------------------------------------------ */
#define H3_OUT_BUF 1024

static void
h3_putc(char c)
{
    (void)write(STDOUT_FILENO, &c, 1);
}

static char *
h3_uint_to_str(char *p, unsigned long long v, unsigned base, int upper)
{
    char  tmp[24];
    int   n   = 0;
    const char *dig = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (v == 0)
        tmp[n++] = '0';
    while (v != 0)
    {
        tmp[n++] = dig[v % base];
        v /= base;
    }
    while (n > 0)
        *p++ = tmp[--n];
    return p;
}

static int
h3_pow10_int(int prec, unsigned long long *out)
{
    unsigned long long m = 1ULL;
    int                i;
    if (prec < 0)
        prec = 6;
    if (prec > 18)
        prec = 18;
    for (i = 0; i < prec; i++)
        m *= 10ULL;
    *out = m;
    return prec;
}

/* Format a finite double in %f style: [-]int[.frac]. */
static char *
h3_format_f(char *p, double v, int prec)
{
    unsigned long long mult, scaled, ip, fp;
    int                i;
    if (v < 0.0)
    {
        *p++ = '-';
        v    = -v;
    }
    prec   = h3_pow10_int(prec, &mult);
    scaled = (unsigned long long)(v * (double)mult + 0.5);
    ip     = scaled / mult;
    fp     = scaled % mult;
    p      = h3_uint_to_str(p, ip, 10, 0);
    if (prec > 0)
    {
        char rev[20];
        int  k = 0;
        *p++   = '.';
        while (fp != 0)
        {
            rev[k++] = (char)('0' + fp % 10ULL);
            fp /= 10ULL;
        }
        for (i = 0; i < prec - k; i++)
            *p++ = '0';
        while (k > 0)
            *p++ = rev[--k];
    }
    return p;
}

/* Format a finite double in %e style: [-]d[.frac]e[+-]xx. */
static char *
h3_format_e(char *p, double v, int prec, int upper)
{
    int   exp = 0;
    double av;
    if (v < 0.0)
    {
        *p++ = '-';
        v    = -v;
    }
    av = v;
    if (av != 0.0)
    {
        while (av >= 10.0)
        {
            av /= 10.0;
            exp++;
        }
        while (av < 1.0)
        {
            av *= 10.0;
            exp--;
        }
    }
    p = h3_format_f(p, av, prec);
    *p++ = (char)(upper ? 'E' : 'e');
    if (exp < 0)
    {
        *p++ = '-';
        exp  = -exp;
    }
    else
    {
        *p++ = '+';
    }
    if (exp >= 100)
        p = h3_uint_to_str(p, (unsigned long long)exp, 10, 0);
    else
    {
        *p++ = (char)('0' + exp / 10);
        *p++ = (char)('0' + exp % 10);
    }
    return p;
}

static char *
h3_format_float(char *p, double v, int prec, char conv)
{
    int exp10 = 0;
    double av;
    if (prec < 0)
        prec = 6;
    if (isnan(v))
    {
        *p++ = 'n';
        *p++ = 'a';
        *p++ = 'n';
        return p;
    }
    if (isinf(v))
    {
        if (v < 0.0)
            *p++ = '-';
        *p++ = 'i';
        *p++ = 'n';
        *p++ = 'f';
        return p;
    }
    if (conv == 'f' || conv == 'F')
        return h3_format_f(p, v, prec);
    if (conv == 'e' || conv == 'E')
        return h3_format_e(p, v, prec, conv == 'E');
    /* g/G: fixed when 1e-4 <= |v| < 10^prec, scientific otherwise. */
    av = v < 0.0 ? -v : v;
    if (av != 0.0)
    {
        double t = av;
        while (t >= 10.0)
        {
            t /= 10.0;
            exp10++;
        }
        while (t < 1.0)
        {
            t *= 10.0;
            exp10--;
        }
    }
    {
        char *start = p, *dot = 0, *end, *e;
        if (av == 0.0 || (exp10 >= -4 && exp10 < prec))
            p = h3_format_f(p, v, prec > exp10 + 1 ? prec - exp10 - 1 : 0);
        else
            p = h3_format_e(p, v, prec - 1, conv == 'G');
        /* %g/%G: strip trailing zeros (and a bare '.') from the mantissa. */
        end = p;
        for (e = start; e < end; e++)
        {
            if (*e == '.')
                dot = e;
            if (*e == 'e' || *e == 'E')
                break;
        }
        if (dot != 0)
        {
            char *m = (e < end) ? e : end;
            while (m > dot + 1 && m[-1] == '0')
                m--;
            if (m == dot + 1)
                m = dot;
            if (m != e)
            {
                char *q = m;
                while (e < end)
                    *q++ = *e++;
                p = q;
            }
        }
        return p;
    }
}

int
ee_vsprintf(char *buf, const char *fmt, va_list args)
{
    char *out = buf;
    while (*fmt != '\0')
    {
        int  left = 0, plus = 0, space = 0, zero = 0, alt = 0;
        int  width = 0, prec = -1, wstar = 0, pstar = 0;
        int  len = 0; /* 0 none, 1 h, 2 hh, 3 l, 4 ll, 5 z, 6 t */
        char conv;
        if (*fmt != '%')
        {
            *out++ = *fmt++;
            continue;
        }
        fmt++;
        if (*fmt == '%')
        {
            *out++ = '%';
            fmt++;
            continue;
        }
        while (*fmt == '-' || *fmt == '+' || *fmt == ' ' || *fmt == '0'
               || *fmt == '#')
        {
            if (*fmt == '-')
                left = 1;
            if (*fmt == '+')
                plus = 1;
            if (*fmt == ' ')
                space = 1;
            if (*fmt == '0')
                zero = 1;
            if (*fmt == '#')
                alt = 1;
            fmt++;
        }
        if (*fmt == '*')
        {
            wstar = 1;
            fmt++;
        }
        else
        {
            while (*fmt >= '0' && *fmt <= '9')
            {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }
        }
        if (*fmt == '.')
        {
            fmt++;
            if (*fmt == '*')
            {
                pstar = 1;
                fmt++;
            }
            else
            {
                prec = 0;
                while (*fmt >= '0' && *fmt <= '9')
                {
                    prec = prec * 10 + (*fmt - '0');
                    fmt++;
                }
            }
        }
        if (*fmt == 'h')
        {
            fmt++;
            len = 1;
            if (*fmt == 'h')
            {
                fmt++;
                len = 2;
            }
        }
        else if (*fmt == 'l')
        {
            fmt++;
            len = 3;
            if (*fmt == 'l')
            {
                fmt++;
                len = 4;
            }
        }
        else if (*fmt == 'z')
        {
            fmt++;
            len = 5;
        }
        else if (*fmt == 't')
        {
            fmt++;
            len = 6;
        }
        conv = *fmt;
        if (conv == '\0')
            break;
        fmt++;
        if (wstar)
        {
            width = va_arg(args, int);
            if (width < 0)
            {
                width = -width;
                left  = 1;
            }
        }
        if (pstar)
        {
            prec = va_arg(args, int);
            if (prec < 0)
                prec = -1;
        }
        if (conv == 'd' || conv == 'i' || conv == 'u' || conv == 'o'
            || conv == 'x' || conv == 'X')
        {
            unsigned long long uv;
            long long          sv    = 0;
            int                is_signed = (conv == 'd' || conv == 'i');
            unsigned           base  = 10;
            int                upper = (conv == 'X');
            char               numbuf[24];
            char              *np = numbuf;
            int                nlen, pad, i;
            if (conv == 'o')
                base = 8;
            if (conv == 'x' || conv == 'X')
                base = 16;
            if (is_signed)
            {
                if (len == 4)
                    sv = va_arg(args, long long);
                else if (len == 3)
                    sv = va_arg(args, long);
                else
                    sv = va_arg(args, int);
                uv = sv < 0 ? (unsigned long long)(-sv) : (unsigned long long)sv;
            }
            else
            {
                if (len == 4)
                    uv = va_arg(args, unsigned long long);
                else if (len == 3)
                    uv = va_arg(args, unsigned long);
                else
                    uv = va_arg(args, unsigned int);
            }
            if (uv == 0 && prec == 0)
                nlen = 0;
            else
            {
                np   = h3_uint_to_str(numbuf, uv, base, upper);
                nlen = (int)(np - numbuf);
            }
            {
                char  sign = 0;
                int   prelen = 0;
                if (is_signed)
                {
                    if (sv < 0)
                        sign = '-';
                    else if (plus)
                        sign = '+';
                    else if (space)
                        sign = ' ';
                }
                if (alt && uv != 0)
                {
                    if (base == 16)
                        prelen = 2;
                    else if (base == 8)
                        prelen = 1;
                }
                if (sign != 0)
                    prelen++;
                pad = width - prelen - (nlen > prec ? nlen : prec);
                if (!left && !zero)
                    for (i = 0; i < pad; i++)
                        *out++ = ' ';
                if (sign != 0)
                    *out++ = sign;
                if (alt && uv != 0)
                {
                    if (base == 16)
                    {
                        *out++ = '0';
                        *out++ = (char)(upper ? 'X' : 'x');
                    }
                    else if (base == 8)
                    {
                        *out++ = '0';
                    }
                }
                if (!left && zero && prec < 0)
                    for (i = 0; i < pad; i++)
                        *out++ = '0';
                else
                    for (i = 0; i < prec - nlen; i++)
                        *out++ = '0';
                for (i = 0; i < nlen; i++)
                    *out++ = numbuf[i];
                if (left)
                    for (i = 0; i < pad; i++)
                        *out++ = ' ';
            }
        }
        else if (conv == 'c')
        {
            int ch = va_arg(args, int);
            int i;
            if (!left)
                for (i = 1; i < width; i++)
                    *out++ = ' ';
            *out++ = (char)ch;
            if (left)
                for (i = 1; i < width; i++)
                    *out++ = ' ';
        }
        else if (conv == 's')
        {
            const char *s = va_arg(args, const char *);
            int         slen = 0, i;
            if (s == 0)
                s = "(null)";
            while (s[slen] != '\0' && (prec < 0 || slen < prec))
                slen++;
            if (!left)
                for (i = slen; i < width; i++)
                    *out++ = ' ';
            for (i = 0; i < slen; i++)
                *out++ = s[i];
            if (left)
                for (i = slen; i < width; i++)
                    *out++ = ' ';
        }
        else if (conv == 'p')
        {
            void *ptr = va_arg(args, void *);
            char  numbuf[24];
            char *np;
            int   nlen, i;
            np   = h3_uint_to_str(numbuf, (unsigned long long)(uintptr_t)ptr,
                                  16, 0);
            nlen = (int)(np - numbuf);
            if (!left)
                for (i = nlen + 2; i < width; i++)
                    *out++ = ' ';
            *out++ = '0';
            *out++ = 'x';
            for (i = 0; i < nlen; i++)
                *out++ = numbuf[i];
            if (left)
                for (i = nlen + 2; i < width; i++)
                    *out++ = ' ';
        }
        else if (conv == 'f' || conv == 'F' || conv == 'e' || conv == 'E'
                 || conv == 'g' || conv == 'G')
        {
            double val = va_arg(args, double);
            char   fbuf[96];
            char  *fp = h3_format_float(fbuf, val, prec, conv);
            int    flen = (int)(fp - fbuf);
            int    i;
            if (!left)
                for (i = flen; i < width; i++)
                    *out++ = ' ';
            for (i = 0; i < flen; i++)
                *out++ = fbuf[i];
            if (left)
                for (i = flen; i < width; i++)
                    *out++ = ' ';
        }
        else
        {
            *out++ = '%';
            *out++ = conv;
        }
    }
    *out = '\0';
    return (int)(out - buf);
}

int
ee_printf(const char *fmt, ...)
{
    char    buf[H3_OUT_BUF];
    va_list args;
    int n, i = 0;
    va_start(args, fmt);
    n = ee_vsprintf(buf, fmt, args);
    va_end(args);
    /* One write() per call: no stdio, no filesystem beyond stdout. */
    while (i < n)
    {
        long w = write(STDOUT_FILENO, buf + i, (unsigned long)(n - i));
        if (w <= 0)
            break;
        i += (int)w;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Target init/fini.                                                  */
/* ------------------------------------------------------------------ */
void
portable_init(core_portable *p, int *argc, char *argv[])
{
    (void)argc;
    (void)argv;
    if (sizeof(ee_ptr_int) != sizeof(ee_u8 *))
        ee_printf("ERROR! ee_ptr_int must hold a pointer (N64 needs 64b)!\n");
    if (sizeof(ee_u32) != 4)
        ee_printf("ERROR! Please define ee_u32 to a 32b unsigned type!\n");
    p->portable_id = 1;
}

void
portable_fini(core_portable *p)
{
    p->portable_id = 0;
}
