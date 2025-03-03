/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <https://unlicense.org>
 */

/* ----------------------------------------------------------------------- */
/* RFC 4648 Base16, Base32 and Base64                                      */
/*             rfc4648.c -- syllogistic xcoding implementation             */
/* Ver. 1.00                    28SEP2024                   CrateOfThunder */
/* ----------------------------------------------------------------------- */

/*
 * gcc -x c -ansi -Wall -Wextra -Wpedantic -Werror -Os -s
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef unsigned char uch;

/*
 * Alphabets
 *  Base32
 *  Base32 Hex
 *  Base64 MIME
 */
static const char b32az[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                  b32x0[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV",
                  b64az[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "0123456789+/";
uch rb[32768], /* raw data buffer */
    eb[32768], /* encoded data buffer */
    lut[256];  /* look-up table */
static size_t i, j, n;

static void
init_lut(range, radstr)
  const int range;
  const uch *radstr;
{
  int i;

  memset(lut, 0, 256);

  for (i = 0; i < range; i++) lut[radstr[i]] = (uch)i;

  return;
}

static uch
set(index, offset, count, A, B, radstr)
  size_t index;
  size_t offset;
  size_t count;
  uch A;
  uch B;
  const char *radstr;
{
  return ((index + offset < count) ? radstr[A | B] : '=');
}

static void
rfc4648_b16enc(ifile, ofile, radstr)
  FILE *ifile;
  FILE *ofile;
const char *radstr;
{
#define HI4 ((rb[i] & 0xF0) >> 4)
#define LO4 ((rb[i] & 0x0F))

  while ((n = fread(rb, 1, 16384, ifile)) > 0) {
    for (i = 0, j = 0; i < n; i++, j += 2) {
      eb[j + 0] = radstr[HI4];
      eb[j + 1] = radstr[LO4];
    }

    fwrite(eb, 1, j, ofile);
  }

  fflush(ofile);
  return;
}

static void
rfc4648_b16dec(ifile, ofile, radstr)
  FILE *ifile;
  FILE *ofile;
  const char *radstr;
{
  init_lut(16, radstr);

#define BYTE1NYBBLE ((eb[j + 0] & 0x0F) << 4)
#define BYTE2NYBBLE (eb[j + 1] & 0x0F)

  while ((n = fread(eb, 1, 32768, ifile)) > 0) {
    for (i = 0; i < n; i++)
      eb[i] = lut[eb[i]];

    n = i;

    for (i = 0, j = 0; j < n; j += 2, i++)
      rb[i] = BYTE1NYBBLE | BYTE2NYBBLE;

    fwrite(rb, 1, i, ofile);
  }

  fflush(ofile);
  return;
}

static void
rfc4648_b32enc(ifile, ofile, radstr)
  FILE *ifile;
  FILE *ofile;
  const char *radstr;
{
#define HI5BYTE1 (rb[i] >> 3)
#define LO3BYTE1 ((rb[i] & 7) << 2)
#define HI2BYTE2 ((i + 1 < n) ? (rb[i + 1] >> 6) : 0)
#define HI5BYTE2 ((rb[i + 1] >> 1) & 31)
#define LO1BYTE2 ((rb[i + 1] & 1) << 4)
#define HI4BYTE3 ((i + 2 < n) ? (rb[i + 2] >> 4) : 0)
#define LO4BYTE3 ((rb[i + 2] & 15) << 1)
#define HI1BYTE4 ((i + 3 < n) ? (rb[i + 3] >> 7) : 0)
#define HI5BYTE4 ((rb[i + 3] >> 2) & 31)
#define LO2BYTE4 ((rb[i + 3] & 3) << 3)
#define HI3BYTE5 ((i + 4 < n) ? (rb[i + 4] >> 5) : 0)
#define LO5BYTE5 (rb[i + 4] & 31)

  while ((n = fread(rb, 1, 32765, ifile)) > 0) {
    for (i = 0, j = 0; i < n; i += 5, j += 8) {
      eb[j + 0] = set(i, 0, n, HI5BYTE1,        0, radstr);
      eb[j + 1] = set(i, 0, n, LO3BYTE1, HI2BYTE2, radstr);
      eb[j + 2] = set(i, 1, n, HI5BYTE2,        0, radstr);
      eb[j + 3] = set(i, 1, n, LO1BYTE2, HI4BYTE3, radstr);
      eb[j + 4] = set(i, 2, n, LO4BYTE3, HI1BYTE4, radstr);
      eb[j + 5] = set(i, 3, n, HI5BYTE4,        0, radstr);
      eb[j + 6] = set(i, 3, n, LO2BYTE4, HI3BYTE5, radstr);
      eb[j + 7] = set(i, 4, n, LO5BYTE5,        0, radstr);
    }

    fwrite(eb, 1, j, ofile);
  }

  fflush(ofile);
  return;
}

static void
rfc4648_b32dec(ifile, ofile, radstr)
  FILE *ifile;
  FILE *ofile;
  const char *radstr;
{
  init_lut(32, radstr);

#define BYTE1LO5 (eb[j] << 3)
#define BYTE2HI3 (eb[j + 1] >> 2)
#define BYTE2LO2 (eb[j + 1] << 6)
#define BYTE3LO5 (eb[j + 2] << 1)
#define BYTE4HI1 (eb[j + 3] >> 4)
#define BYTE4LO4 (eb[j + 3] << 4)
#define BYTE5HI4 (eb[j + 4] >> 1)
#define BYTE5LO1 (eb[j + 4] << 7)
#define BYTE6LO5 (eb[j + 5] << 2)
#define BYTE7HI2 (eb[j + 6] >> 3)
#define BYTE7LO3 (eb[j + 6] << 5)
#define BYTE8LO5 (eb[j + 7])

  while ((n = fread(eb, 1, 32768, ifile)) > 0) {
    for (i = 0; (i < n) && (eb[i] != '='); i++)
      eb[i] = lut[eb[i]];

    n = i;

    for (i = 0, j = 0; j < n; j += 8, i += 5) {
      rb[i] = BYTE1LO5 | BYTE2HI3;
      rb[i + 1] = BYTE2LO2 | BYTE3LO5 | BYTE4HI1;
      rb[i + 2] = BYTE4LO4 | BYTE5HI4;
      rb[i + 3] = BYTE5LO1 | BYTE6LO5 | BYTE7HI2;
      rb[i + 4] = BYTE7LO3 | BYTE8LO5;
    }

    fwrite(rb, 1, (n * 5) / 8, ofile);
  }

  fflush(ofile);
  return;
}

static void
rfc4648_b64enc(ifile, ofile, radstr)
  FILE *ifile;
  FILE *ofile;
  const char *radstr;
{
#define HI6BYTE1 (rb[i] >> 2)
#define LO2BYTE1 ((rb[i] & 0x03) << 4)
#define HI4BYTE2 ((i + 1 < n) ? (rb[i + 1] >> 4) : 0)
#define LO4BYTE2 ((rb[i + 1] & 0x0F) << 2)
#define HI2BYTE3 ((i + 2 < n) ? (rb[i + 2] >> 6) : 0)
#define LO6BYTE3 (rb[i + 2] & 0x3F)

  while ((n = fread(rb, 1, 32766, ifile)) > 0) {
    for (i = 0, j = 0; i < n; i += 3, j += 4) {
      eb[j + 0] = set(i, 0, n, HI6BYTE1,        0, radstr);
      eb[j + 1] = set(i, 0, n, LO2BYTE1, HI4BYTE2, radstr);
      eb[j + 2] = set(i, 1, n, LO4BYTE2, HI2BYTE3, radstr);
      eb[j + 3] = set(i, 2, n, LO6BYTE3,        0, radstr);
    }

    fwrite(eb, 1, j, ofile);
  }

  fflush(ofile);
  return;
}

static void
rfc4648_b64dec(ifile, ofile, radstr)
  FILE *ifile;
  FILE *ofile;
  const char *radstr;
{
  init_lut(64, radstr);

#define BYTE1LO6 (eb[j] << 2)
#define BYTE2HI2 (eb[j + 1] >> 4)
#define BYTE2LO4 (eb[j + 1] << 4)
#define BYTE3HI4 (eb[j + 2] >> 2)
#define BYTE3LO2 (eb[j + 2] << 6)
#define BYTE4LO6 (eb[j + 3])

  while ((n = fread(eb, 1, 32768, ifile)) > 0) {
    for (i = 0; (i < n) && (eb[i] != '='); i++)
      eb[i] = lut[eb[i]];

    n = i;

    for (i = 0, j = 0; j < n; j += 4, i += 3) {
      rb[i] = BYTE1LO6 | BYTE2HI2;

      if (j + 2 < n)
        rb[i + 1] = BYTE2LO4 | BYTE3HI4;

      if (j + 3 < n)
        rb[i + 2] = BYTE3LO2 | BYTE4LO6;
    }

    fwrite(rb, 1, (n * 6) / 8, ofile);
  }

  fflush(ofile);
  return;
}

static void
usage(void)
{
  printf("\nUsage:\n\trfc4648 [mode] [base] <in_file> <out_file>\n");
  printf("\nMode:\n\tE : Encode\n\tD : Decode\n");
  printf("Base:\n\tA : Base16\n\tB : Base32\n\tC : Base64\n");
  return;
}

#define FUNC 0
#define TYPE 1

int main(int argc, char *argv[])
{
  void (*x[2][3])(FILE *, FILE *, const char*) = {
    { rfc4648_b64enc, rfc4648_b32enc, rfc4648_b16enc },
    { rfc4648_b64dec, rfc4648_b32dec, rfc4648_b16dec }
  };
  const char *a[3] = { b64az, b32az, b32x0 };
  FILE *ifile = NULL, *ofile = NULL;
  char *s;
  int d[2];

  if (argc != 5) {
    usage();
    exit(EXIT_FAILURE);
  }

  if ((s = argv[1], s[1] || strpbrk(s, "DEde") == NULL) ||
      (s = argv[2], s[1] || strpbrk(s, "ABCabc") == NULL) ||
      (s = argv[3], (ifile = fopen(s, "rb")) == NULL) ||
      (s = argv[4], (ofile = fopen(s, "wb")) == NULL)) {
    printf("??? %s\n", s);
    usage();
    exit(EXIT_FAILURE);
  }

  d[FUNC] = (int)'E' - toupper(*argv[1]);
  d[TYPE] = (int)'C' - toupper(*argv[2]);
  x[d[FUNC]][d[TYPE]](ifile, ofile, a[d[TYPE]]);
  fflush(ofile);
  fclose(ofile);
  fclose(ifile);
  exit(EXIT_SUCCESS);
}
