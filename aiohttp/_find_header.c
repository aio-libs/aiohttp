
#include "_find_header.h"

#define NEXT_CHAR() \
{ \
    count++; \
    if (count == size) { \
        /* end of search */ \
        return -1; \
    } \
    pchar++; \
    ch = *pchar; \
    last = (count == size -1); \
} while(0);

int
find_header(const char *str, int size)
{
    char *pchar = str;
    int last;
    char ch;
    int count = -1;
    pchar--;

INITIAL:
    NEXT_CHAR();
    switch (ch) {

    case 'A':
        if (last) {
            return -1;
        }
        goto A;


    case 'a':
        if (last) {
            return -1;
        }
        goto A;


    case 'C':
        if (last) {
            return -1;
        }
        goto C;


    case 'c':
        if (last) {
            return -1;
        }
        goto C;


    case 'D':
        if (last) {
            return -1;
        }
        goto D;


    case 'd':
        if (last) {
            return -1;
        }
        goto D;


    case 'E':
        if (last) {
            return -1;
        }
        goto E;


    case 'e':
        if (last) {
            return -1;
        }
        goto E;


    case 'F':
        if (last) {
            return -1;
        }
        goto F;


    case 'f':
        if (last) {
            return -1;
        }
        goto F;


    case 'H':
        if (last) {
            return -1;
        }
        goto H;


    case 'h':
        if (last) {
            return -1;
        }
        goto H;


    case 'I':
        if (last) {
            return -1;
        }
        goto I;


    case 'i':
        if (last) {
            return -1;
        }
        goto I;


    case 'K':
        if (last) {
            return -1;
        }
        goto K;


    case 'k':
        if (last) {
            return -1;
        }
        goto K;


    case 'L':
        if (last) {
            return -1;
        }
        goto L;


    case 'l':
        if (last) {
            return -1;
        }
        goto L;


    case 'M':
        if (last) {
            return -1;
        }
        goto M;


    case 'm':
        if (last) {
            return -1;
        }
        goto M;


    case 'O':
        if (last) {
            return -1;
        }
        goto O;


    case 'o':
        if (last) {
            return -1;
        }
        goto O;


    case 'P':
        if (last) {
            return -1;
        }
        goto P;


    case 'p':
        if (last) {
            return -1;
        }
        goto P;


    case 'R':
        if (last) {
            return -1;
        }
        goto R;


    case 'r':
        if (last) {
            return -1;
        }
        goto R;


    case 'S':
        if (last) {
            return -1;
        }
        goto S;


    case 's':
        if (last) {
            return -1;
        }
        goto S;


    case 'T':
        if (last) {
            return -1;
        }
        goto T;


    case 't':
        if (last) {
            return -1;
        }
        goto T;


    case 'U':
        if (last) {
            return -1;
        }
        goto U;


    case 'u':
        if (last) {
            return -1;
        }
        goto U;


    case 'V':
        if (last) {
            return -1;
        }
        goto V;


    case 'v':
        if (last) {
            return -1;
        }
        goto V;


    case 'W':
        if (last) {
            return -1;
        }
        goto W;


    case 'w':
        if (last) {
            return -1;
        }
        goto W;


    case 'X':
        if (last) {
            return -1;
        }
        goto X;


    case 'x':
        if (last) {
            return -1;
        }
        goto X;

    default:
        return -1;
    }

A:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto AC;


    case 'g':
        if (last) {
            return -1;
        }
        goto AG;


    case 'l':
        if (last) {
            return -1;
        }
        goto AL;


    case 'u':
        if (last) {
            return -1;
        }
        goto AU;

    default:
        return -1;
    }

AC:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto ACC;

    default:
        return -1;
    }

ACC:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCE;

    default:
        return -1;
    }

ACCE:
    NEXT_CHAR();
    switch (ch) {

    case 'p':
        if (last) {
            return -1;
        }
        goto ACCEP;


    case 's':
        if (last) {
            return -1;
        }
        goto ACCES;

    default:
        return -1;
    }

ACCEP:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 0;
        }
        goto ACCEPT;

    default:
        return -1;
    }

ACCEPT:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto ACCEPT_;

    default:
        return -1;
    }

ACCEPT_:
    NEXT_CHAR();
    switch (ch) {

    case 'C':
        if (last) {
            return -1;
        }
        goto ACCEPT_C;


    case 'c':
        if (last) {
            return -1;
        }
        goto ACCEPT_C;


    case 'E':
        if (last) {
            return -1;
        }
        goto ACCEPT_E;


    case 'e':
        if (last) {
            return -1;
        }
        goto ACCEPT_E;


    case 'L':
        if (last) {
            return -1;
        }
        goto ACCEPT_L;


    case 'l':
        if (last) {
            return -1;
        }
        goto ACCEPT_L;


    case 'R':
        if (last) {
            return -1;
        }
        goto ACCEPT_R;


    case 'r':
        if (last) {
            return -1;
        }
        goto ACCEPT_R;

    default:
        return -1;
    }

ACCEPT_C:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return -1;
        }
        goto ACCEPT_CH;

    default:
        return -1;
    }

ACCEPT_CH:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ACCEPT_CHA;

    default:
        return -1;
    }

ACCEPT_CHA:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto ACCEPT_CHAR;

    default:
        return -1;
    }

ACCEPT_CHAR:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto ACCEPT_CHARS;

    default:
        return -1;
    }

ACCEPT_CHARS:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCEPT_CHARSE;

    default:
        return -1;
    }

ACCEPT_CHARSE:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 1;
        }
        goto ACCEPT_CHARSET;

    default:
        return -1;
    }

ACCEPT_CHARSET:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCEPT_E:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto ACCEPT_EN;

    default:
        return -1;
    }

ACCEPT_EN:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto ACCEPT_ENC;

    default:
        return -1;
    }

ACCEPT_ENC:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto ACCEPT_ENCO;

    default:
        return -1;
    }

ACCEPT_ENCO:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto ACCEPT_ENCOD;

    default:
        return -1;
    }

ACCEPT_ENCOD:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto ACCEPT_ENCODI;

    default:
        return -1;
    }

ACCEPT_ENCODI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto ACCEPT_ENCODIN;

    default:
        return -1;
    }

ACCEPT_ENCODIN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return 2;
        }
        goto ACCEPT_ENCODING;

    default:
        return -1;
    }

ACCEPT_ENCODING:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCEPT_L:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ACCEPT_LA;

    default:
        return -1;
    }

ACCEPT_LA:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto ACCEPT_LAN;

    default:
        return -1;
    }

ACCEPT_LAN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto ACCEPT_LANG;

    default:
        return -1;
    }

ACCEPT_LANG:
    NEXT_CHAR();
    switch (ch) {

    case 'u':
        if (last) {
            return -1;
        }
        goto ACCEPT_LANGU;

    default:
        return -1;
    }

ACCEPT_LANGU:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ACCEPT_LANGUA;

    default:
        return -1;
    }

ACCEPT_LANGUA:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto ACCEPT_LANGUAG;

    default:
        return -1;
    }

ACCEPT_LANGUAG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 3;
        }
        goto ACCEPT_LANGUAGE;

    default:
        return -1;
    }

ACCEPT_LANGUAGE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCEPT_R:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ACCEPT_RA;

    default:
        return -1;
    }

ACCEPT_RA:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto ACCEPT_RAN;

    default:
        return -1;
    }

ACCEPT_RAN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto ACCEPT_RANG;

    default:
        return -1;
    }

ACCEPT_RANG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCEPT_RANGE;

    default:
        return -1;
    }

ACCEPT_RANGE:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return 4;
        }
        goto ACCEPT_RANGES;

    default:
        return -1;
    }

ACCEPT_RANGES:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCES:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto ACCESS;

    default:
        return -1;
    }

ACCESS:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto ACCESS_;

    default:
        return -1;
    }

ACCESS_:
    NEXT_CHAR();
    switch (ch) {

    case 'C':
        if (last) {
            return -1;
        }
        goto ACCESS_C;


    case 'c':
        if (last) {
            return -1;
        }
        goto ACCESS_C;

    default:
        return -1;
    }

ACCESS_C:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto ACCESS_CO;

    default:
        return -1;
    }

ACCESS_CO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto ACCESS_CON;

    default:
        return -1;
    }

ACCESS_CON:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto ACCESS_CONT;

    default:
        return -1;
    }

ACCESS_CONT:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTR;

    default:
        return -1;
    }

ACCESS_CONTR:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTRO;

    default:
        return -1;
    }

ACCESS_CONTRO:
    NEXT_CHAR();
    switch (ch) {

    case 'l':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL;

    default:
        return -1;
    }

ACCESS_CONTROL:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_;

    default:
        return -1;
    }

ACCESS_CONTROL_:
    NEXT_CHAR();
    switch (ch) {

    case 'A':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_A;


    case 'a':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_A;


    case 'E':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_E;


    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_E;


    case 'M':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_M;


    case 'm':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_M;


    case 'R':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_R;


    case 'r':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_R;

    default:
        return -1;
    }

ACCESS_CONTROL_A:
    NEXT_CHAR();
    switch (ch) {

    case 'l':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_AL;

    default:
        return -1;
    }

ACCESS_CONTROL_AL:
    NEXT_CHAR();
    switch (ch) {

    case 'l':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALL;

    default:
        return -1;
    }

ACCESS_CONTROL_ALL:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLO;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLO:
    NEXT_CHAR();
    switch (ch) {

    case 'w':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_:
    NEXT_CHAR();
    switch (ch) {

    case 'C':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_C;


    case 'c':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_C;


    case 'H':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_H;


    case 'h':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_H;


    case 'M':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_M;


    case 'm':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_M;


    case 'O':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_O;


    case 'o':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_O;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_C:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_CR;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CR:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_CRE;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CRE:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_CRED;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CRED:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_CREDE;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CREDE:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_CREDEN;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CREDEN:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_CREDENT;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CREDENT:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_CREDENTI;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CREDENTI:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_CREDENTIA;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CREDENTIA:
    NEXT_CHAR();
    switch (ch) {

    case 'l':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_CREDENTIAL;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CREDENTIAL:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return 5;
        }
        goto ACCESS_CONTROL_ALLOW_CREDENTIALS;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_CREDENTIALS:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_H:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_HE;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_HE:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_HEA;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_HEA:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_HEAD;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_HEAD:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_HEADE;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_HEADE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_HEADER;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_HEADER:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return 6;
        }
        goto ACCESS_CONTROL_ALLOW_HEADERS;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_HEADERS:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_M:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_ME;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_ME:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_MET;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_MET:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_METH;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_METH:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_METHO;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_METHO:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_METHOD;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_METHOD:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return 7;
        }
        goto ACCESS_CONTROL_ALLOW_METHODS;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_METHODS:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_O:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_OR;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_OR:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_ORI;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_ORI:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_ORIG;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_ORIG:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_ALLOW_ORIGI;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_ORIGI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return 8;
        }
        goto ACCESS_CONTROL_ALLOW_ORIGIN;

    default:
        return -1;
    }

ACCESS_CONTROL_ALLOW_ORIGIN:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCESS_CONTROL_E:
    NEXT_CHAR();
    switch (ch) {

    case 'x':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EX;

    default:
        return -1;
    }

ACCESS_CONTROL_EX:
    NEXT_CHAR();
    switch (ch) {

    case 'p':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXP;

    default:
        return -1;
    }

ACCESS_CONTROL_EXP:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPO;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPO:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOS;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOS:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOSE;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOSE:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOSE_;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOSE_:
    NEXT_CHAR();
    switch (ch) {

    case 'H':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOSE_H;


    case 'h':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOSE_H;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOSE_H:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOSE_HE;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOSE_HE:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOSE_HEA;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOSE_HEA:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOSE_HEAD;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOSE_HEAD:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOSE_HEADE;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOSE_HEADE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_EXPOSE_HEADER;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOSE_HEADER:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return 9;
        }
        goto ACCESS_CONTROL_EXPOSE_HEADERS;

    default:
        return -1;
    }

ACCESS_CONTROL_EXPOSE_HEADERS:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCESS_CONTROL_M:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_MA;

    default:
        return -1;
    }

ACCESS_CONTROL_MA:
    NEXT_CHAR();
    switch (ch) {

    case 'x':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_MAX;

    default:
        return -1;
    }

ACCESS_CONTROL_MAX:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_MAX_;

    default:
        return -1;
    }

ACCESS_CONTROL_MAX_:
    NEXT_CHAR();
    switch (ch) {

    case 'A':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_MAX_A;


    case 'a':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_MAX_A;

    default:
        return -1;
    }

ACCESS_CONTROL_MAX_A:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_MAX_AG;

    default:
        return -1;
    }

ACCESS_CONTROL_MAX_AG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 10;
        }
        goto ACCESS_CONTROL_MAX_AGE;

    default:
        return -1;
    }

ACCESS_CONTROL_MAX_AGE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCESS_CONTROL_R:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_RE;

    default:
        return -1;
    }

ACCESS_CONTROL_RE:
    NEXT_CHAR();
    switch (ch) {

    case 'q':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQ;

    default:
        return -1;
    }

ACCESS_CONTROL_REQ:
    NEXT_CHAR();
    switch (ch) {

    case 'u':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQU;

    default:
        return -1;
    }

ACCESS_CONTROL_REQU:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUE;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUE:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUES;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUES:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_:
    NEXT_CHAR();
    switch (ch) {

    case 'H':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_H;


    case 'h':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_H;


    case 'M':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_M;


    case 'm':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_M;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_H:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_HE;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_HE:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_HEA;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_HEA:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_HEAD;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_HEAD:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_HEADE;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_HEADE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_HEADER;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_HEADER:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return 11;
        }
        goto ACCESS_CONTROL_REQUEST_HEADERS;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_HEADERS:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_M:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_ME;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_ME:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_MET;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_MET:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_METH;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_METH:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto ACCESS_CONTROL_REQUEST_METHO;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_METHO:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return 12;
        }
        goto ACCESS_CONTROL_REQUEST_METHOD;

    default:
        return -1;
    }

ACCESS_CONTROL_REQUEST_METHOD:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

AG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 13;
        }
        goto AGE;

    default:
        return -1;
    }

AGE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

AL:
    NEXT_CHAR();
    switch (ch) {

    case 'l':
        if (last) {
            return -1;
        }
        goto ALL;

    default:
        return -1;
    }

ALL:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto ALLO;

    default:
        return -1;
    }

ALLO:
    NEXT_CHAR();
    switch (ch) {

    case 'w':
        if (last) {
            return 14;
        }
        goto ALLOW;

    default:
        return -1;
    }

ALLOW:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

AU:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto AUT;

    default:
        return -1;
    }

AUT:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return -1;
        }
        goto AUTH;

    default:
        return -1;
    }

AUTH:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto AUTHO;

    default:
        return -1;
    }

AUTHO:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto AUTHOR;

    default:
        return -1;
    }

AUTHOR:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto AUTHORI;

    default:
        return -1;
    }

AUTHORI:
    NEXT_CHAR();
    switch (ch) {

    case 'z':
        if (last) {
            return -1;
        }
        goto AUTHORIZ;

    default:
        return -1;
    }

AUTHORIZ:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto AUTHORIZA;

    default:
        return -1;
    }

AUTHORIZA:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto AUTHORIZAT;

    default:
        return -1;
    }

AUTHORIZAT:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto AUTHORIZATI;

    default:
        return -1;
    }

AUTHORIZATI:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto AUTHORIZATIO;

    default:
        return -1;
    }

AUTHORIZATIO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return 15;
        }
        goto AUTHORIZATION;

    default:
        return -1;
    }

AUTHORIZATION:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

C:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto CA;


    case 'o':
        if (last) {
            return -1;
        }
        goto CO;

    default:
        return -1;
    }

CA:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto CAC;

    default:
        return -1;
    }

CAC:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return -1;
        }
        goto CACH;

    default:
        return -1;
    }

CACH:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto CACHE;

    default:
        return -1;
    }

CACHE:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto CACHE_;

    default:
        return -1;
    }

CACHE_:
    NEXT_CHAR();
    switch (ch) {

    case 'C':
        if (last) {
            return -1;
        }
        goto CACHE_C;


    case 'c':
        if (last) {
            return -1;
        }
        goto CACHE_C;

    default:
        return -1;
    }

CACHE_C:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto CACHE_CO;

    default:
        return -1;
    }

CACHE_CO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CACHE_CON;

    default:
        return -1;
    }

CACHE_CON:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto CACHE_CONT;

    default:
        return -1;
    }

CACHE_CONT:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto CACHE_CONTR;

    default:
        return -1;
    }

CACHE_CONTR:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto CACHE_CONTRO;

    default:
        return -1;
    }

CACHE_CONTRO:
    NEXT_CHAR();
    switch (ch) {

    case 'l':
        if (last) {
            return 16;
        }
        goto CACHE_CONTROL;

    default:
        return -1;
    }

CACHE_CONTROL:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CON;


    case 'o':
        if (last) {
            return -1;
        }
        goto COO;

    default:
        return -1;
    }

CON:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONN;


    case 't':
        if (last) {
            return -1;
        }
        goto CONT;

    default:
        return -1;
    }

CONN:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto CONNE;

    default:
        return -1;
    }

CONNE:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto CONNEC;

    default:
        return -1;
    }

CONNEC:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto CONNECT;

    default:
        return -1;
    }

CONNECT:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto CONNECTI;

    default:
        return -1;
    }

CONNECTI:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto CONNECTIO;

    default:
        return -1;
    }

CONNECTIO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return 17;
        }
        goto CONNECTION;

    default:
        return -1;
    }

CONNECTION:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CONT:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto CONTE;

    default:
        return -1;
    }

CONTE:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONTEN;

    default:
        return -1;
    }

CONTEN:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto CONTENT;

    default:
        return -1;
    }

CONTENT:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto CONTENT_;

    default:
        return -1;
    }

CONTENT_:
    NEXT_CHAR();
    switch (ch) {

    case 'D':
        if (last) {
            return -1;
        }
        goto CONTENT_D;


    case 'd':
        if (last) {
            return -1;
        }
        goto CONTENT_D;


    case 'E':
        if (last) {
            return -1;
        }
        goto CONTENT_E;


    case 'e':
        if (last) {
            return -1;
        }
        goto CONTENT_E;


    case 'L':
        if (last) {
            return -1;
        }
        goto CONTENT_L;


    case 'l':
        if (last) {
            return -1;
        }
        goto CONTENT_L;


    case 'M':
        if (last) {
            return -1;
        }
        goto CONTENT_M;


    case 'm':
        if (last) {
            return -1;
        }
        goto CONTENT_M;


    case 'R':
        if (last) {
            return -1;
        }
        goto CONTENT_R;


    case 'r':
        if (last) {
            return -1;
        }
        goto CONTENT_R;


    case 'T':
        if (last) {
            return -1;
        }
        goto CONTENT_T;


    case 't':
        if (last) {
            return -1;
        }
        goto CONTENT_T;

    default:
        return -1;
    }

CONTENT_D:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto CONTENT_DI;

    default:
        return -1;
    }

CONTENT_DI:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto CONTENT_DIS;

    default:
        return -1;
    }

CONTENT_DIS:
    NEXT_CHAR();
    switch (ch) {

    case 'p':
        if (last) {
            return -1;
        }
        goto CONTENT_DISP;

    default:
        return -1;
    }

CONTENT_DISP:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto CONTENT_DISPO;

    default:
        return -1;
    }

CONTENT_DISPO:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto CONTENT_DISPOS;

    default:
        return -1;
    }

CONTENT_DISPOS:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto CONTENT_DISPOSI;

    default:
        return -1;
    }

CONTENT_DISPOSI:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto CONTENT_DISPOSIT;

    default:
        return -1;
    }

CONTENT_DISPOSIT:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto CONTENT_DISPOSITI;

    default:
        return -1;
    }

CONTENT_DISPOSITI:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto CONTENT_DISPOSITIO;

    default:
        return -1;
    }

CONTENT_DISPOSITIO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return 18;
        }
        goto CONTENT_DISPOSITION;

    default:
        return -1;
    }

CONTENT_DISPOSITION:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CONTENT_E:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONTENT_EN;

    default:
        return -1;
    }

CONTENT_EN:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto CONTENT_ENC;

    default:
        return -1;
    }

CONTENT_ENC:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto CONTENT_ENCO;

    default:
        return -1;
    }

CONTENT_ENCO:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto CONTENT_ENCOD;

    default:
        return -1;
    }

CONTENT_ENCOD:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto CONTENT_ENCODI;

    default:
        return -1;
    }

CONTENT_ENCODI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONTENT_ENCODIN;

    default:
        return -1;
    }

CONTENT_ENCODIN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return 19;
        }
        goto CONTENT_ENCODING;

    default:
        return -1;
    }

CONTENT_ENCODING:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CONTENT_L:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto CONTENT_LA;


    case 'e':
        if (last) {
            return -1;
        }
        goto CONTENT_LE;


    case 'o':
        if (last) {
            return -1;
        }
        goto CONTENT_LO;

    default:
        return -1;
    }

CONTENT_LA:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONTENT_LAN;

    default:
        return -1;
    }

CONTENT_LAN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto CONTENT_LANG;

    default:
        return -1;
    }

CONTENT_LANG:
    NEXT_CHAR();
    switch (ch) {

    case 'u':
        if (last) {
            return -1;
        }
        goto CONTENT_LANGU;

    default:
        return -1;
    }

CONTENT_LANGU:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto CONTENT_LANGUA;

    default:
        return -1;
    }

CONTENT_LANGUA:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto CONTENT_LANGUAG;

    default:
        return -1;
    }

CONTENT_LANGUAG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 20;
        }
        goto CONTENT_LANGUAGE;

    default:
        return -1;
    }

CONTENT_LANGUAGE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CONTENT_LE:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONTENT_LEN;

    default:
        return -1;
    }

CONTENT_LEN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto CONTENT_LENG;

    default:
        return -1;
    }

CONTENT_LENG:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto CONTENT_LENGT;

    default:
        return -1;
    }

CONTENT_LENGT:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return 21;
        }
        goto CONTENT_LENGTH;

    default:
        return -1;
    }

CONTENT_LENGTH:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CONTENT_LO:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto CONTENT_LOC;

    default:
        return -1;
    }

CONTENT_LOC:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto CONTENT_LOCA;

    default:
        return -1;
    }

CONTENT_LOCA:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto CONTENT_LOCAT;

    default:
        return -1;
    }

CONTENT_LOCAT:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto CONTENT_LOCATI;

    default:
        return -1;
    }

CONTENT_LOCATI:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto CONTENT_LOCATIO;

    default:
        return -1;
    }

CONTENT_LOCATIO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return 22;
        }
        goto CONTENT_LOCATION;

    default:
        return -1;
    }

CONTENT_LOCATION:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CONTENT_M:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto CONTENT_MD;

    default:
        return -1;
    }

CONTENT_MD:
    NEXT_CHAR();
    switch (ch) {

    case '5':
        if (last) {
            return 23;
        }
        goto CONTENT_MD5;

    default:
        return -1;
    }

CONTENT_MD5:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CONTENT_R:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto CONTENT_RA;

    default:
        return -1;
    }

CONTENT_RA:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONTENT_RAN;

    default:
        return -1;
    }

CONTENT_RAN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto CONTENT_RANG;

    default:
        return -1;
    }

CONTENT_RANG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 24;
        }
        goto CONTENT_RANGE;

    default:
        return -1;
    }

CONTENT_RANGE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CONTENT_T:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto CONTENT_TR;


    case 'y':
        if (last) {
            return -1;
        }
        goto CONTENT_TY;

    default:
        return -1;
    }

CONTENT_TR:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto CONTENT_TRA;

    default:
        return -1;
    }

CONTENT_TRA:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONTENT_TRAN;

    default:
        return -1;
    }

CONTENT_TRAN:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANS;

    default:
        return -1;
    }

CONTENT_TRANS:
    NEXT_CHAR();
    switch (ch) {

    case 'f':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSF;

    default:
        return -1;
    }

CONTENT_TRANSF:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFE;

    default:
        return -1;
    }

CONTENT_TRANSFE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER;

    default:
        return -1;
    }

CONTENT_TRANSFER:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER_;

    default:
        return -1;
    }

CONTENT_TRANSFER_:
    NEXT_CHAR();
    switch (ch) {

    case 'E':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER_E;


    case 'e':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER_E;

    default:
        return -1;
    }

CONTENT_TRANSFER_E:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER_EN;

    default:
        return -1;
    }

CONTENT_TRANSFER_EN:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER_ENC;

    default:
        return -1;
    }

CONTENT_TRANSFER_ENC:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER_ENCO;

    default:
        return -1;
    }

CONTENT_TRANSFER_ENCO:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER_ENCOD;

    default:
        return -1;
    }

CONTENT_TRANSFER_ENCOD:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER_ENCODI;

    default:
        return -1;
    }

CONTENT_TRANSFER_ENCODI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto CONTENT_TRANSFER_ENCODIN;

    default:
        return -1;
    }

CONTENT_TRANSFER_ENCODIN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return 25;
        }
        goto CONTENT_TRANSFER_ENCODING;

    default:
        return -1;
    }

CONTENT_TRANSFER_ENCODING:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

CONTENT_TY:
    NEXT_CHAR();
    switch (ch) {

    case 'p':
        if (last) {
            return -1;
        }
        goto CONTENT_TYP;

    default:
        return -1;
    }

CONTENT_TYP:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 26;
        }
        goto CONTENT_TYPE;

    default:
        return -1;
    }

CONTENT_TYPE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

COO:
    NEXT_CHAR();
    switch (ch) {

    case 'k':
        if (last) {
            return -1;
        }
        goto COOK;

    default:
        return -1;
    }

COOK:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto COOKI;

    default:
        return -1;
    }

COOKI:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 27;
        }
        goto COOKIE;

    default:
        return -1;
    }

COOKIE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

D:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto DA;


    case 'e':
        if (last) {
            return -1;
        }
        goto DE;


    case 'i':
        if (last) {
            return -1;
        }
        goto DI;

    default:
        return -1;
    }

DA:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto DAT;

    default:
        return -1;
    }

DAT:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 28;
        }
        goto DATE;

    default:
        return -1;
    }

DATE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

DE:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto DES;

    default:
        return -1;
    }

DES:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto DEST;

    default:
        return -1;
    }

DEST:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto DESTI;

    default:
        return -1;
    }

DESTI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto DESTIN;

    default:
        return -1;
    }

DESTIN:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto DESTINA;

    default:
        return -1;
    }

DESTINA:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto DESTINAT;

    default:
        return -1;
    }

DESTINAT:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto DESTINATI;

    default:
        return -1;
    }

DESTINATI:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto DESTINATIO;

    default:
        return -1;
    }

DESTINATIO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return 29;
        }
        goto DESTINATION;

    default:
        return -1;
    }

DESTINATION:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

DI:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto DIG;

    default:
        return -1;
    }

DIG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto DIGE;

    default:
        return -1;
    }

DIGE:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto DIGES;

    default:
        return -1;
    }

DIGES:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 30;
        }
        goto DIGEST;

    default:
        return -1;
    }

DIGEST:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

E:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto ET;


    case 'x':
        if (last) {
            return -1;
        }
        goto EX;

    default:
        return -1;
    }

ET:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto ETA;

    default:
        return -1;
    }

ETA:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return 31;
        }
        goto ETAG;

    default:
        return -1;
    }

ETAG:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

EX:
    NEXT_CHAR();
    switch (ch) {

    case 'p':
        if (last) {
            return -1;
        }
        goto EXP;

    default:
        return -1;
    }

EXP:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto EXPE;


    case 'i':
        if (last) {
            return -1;
        }
        goto EXPI;

    default:
        return -1;
    }

EXPE:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto EXPEC;

    default:
        return -1;
    }

EXPEC:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 32;
        }
        goto EXPECT;

    default:
        return -1;
    }

EXPECT:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

EXPI:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto EXPIR;

    default:
        return -1;
    }

EXPIR:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto EXPIRE;

    default:
        return -1;
    }

EXPIRE:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return 33;
        }
        goto EXPIRES;

    default:
        return -1;
    }

EXPIRES:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

F:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto FO;


    case 'r':
        if (last) {
            return -1;
        }
        goto FR;

    default:
        return -1;
    }

FO:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto FOR;

    default:
        return -1;
    }

FOR:
    NEXT_CHAR();
    switch (ch) {

    case 'w':
        if (last) {
            return -1;
        }
        goto FORW;

    default:
        return -1;
    }

FORW:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto FORWA;

    default:
        return -1;
    }

FORWA:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto FORWAR;

    default:
        return -1;
    }

FORWAR:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto FORWARD;

    default:
        return -1;
    }

FORWARD:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto FORWARDE;

    default:
        return -1;
    }

FORWARDE:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return 34;
        }
        goto FORWARDED;

    default:
        return -1;
    }

FORWARDED:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

FR:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto FRO;

    default:
        return -1;
    }

FRO:
    NEXT_CHAR();
    switch (ch) {

    case 'm':
        if (last) {
            return 35;
        }
        goto FROM;

    default:
        return -1;
    }

FROM:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

H:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto HO;

    default:
        return -1;
    }

HO:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto HOS;

    default:
        return -1;
    }

HOS:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 36;
        }
        goto HOST;

    default:
        return -1;
    }

HOST:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

I:
    NEXT_CHAR();
    switch (ch) {

    case 'f':
        if (last) {
            return -1;
        }
        goto IF;

    default:
        return -1;
    }

IF:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto IF_;

    default:
        return -1;
    }

IF_:
    NEXT_CHAR();
    switch (ch) {

    case 'M':
        if (last) {
            return -1;
        }
        goto IF_M;


    case 'm':
        if (last) {
            return -1;
        }
        goto IF_M;


    case 'N':
        if (last) {
            return -1;
        }
        goto IF_N;


    case 'n':
        if (last) {
            return -1;
        }
        goto IF_N;


    case 'R':
        if (last) {
            return -1;
        }
        goto IF_R;


    case 'r':
        if (last) {
            return -1;
        }
        goto IF_R;


    case 'U':
        if (last) {
            return -1;
        }
        goto IF_U;


    case 'u':
        if (last) {
            return -1;
        }
        goto IF_U;

    default:
        return -1;
    }

IF_M:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto IF_MA;


    case 'o':
        if (last) {
            return -1;
        }
        goto IF_MO;

    default:
        return -1;
    }

IF_MA:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto IF_MAT;

    default:
        return -1;
    }

IF_MAT:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto IF_MATC;

    default:
        return -1;
    }

IF_MATC:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return 37;
        }
        goto IF_MATCH;

    default:
        return -1;
    }

IF_MATCH:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

IF_MO:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto IF_MOD;

    default:
        return -1;
    }

IF_MOD:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto IF_MODI;

    default:
        return -1;
    }

IF_MODI:
    NEXT_CHAR();
    switch (ch) {

    case 'f':
        if (last) {
            return -1;
        }
        goto IF_MODIF;

    default:
        return -1;
    }

IF_MODIF:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto IF_MODIFI;

    default:
        return -1;
    }

IF_MODIFI:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto IF_MODIFIE;

    default:
        return -1;
    }

IF_MODIFIE:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto IF_MODIFIED;

    default:
        return -1;
    }

IF_MODIFIED:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto IF_MODIFIED_;

    default:
        return -1;
    }

IF_MODIFIED_:
    NEXT_CHAR();
    switch (ch) {

    case 'S':
        if (last) {
            return -1;
        }
        goto IF_MODIFIED_S;


    case 's':
        if (last) {
            return -1;
        }
        goto IF_MODIFIED_S;

    default:
        return -1;
    }

IF_MODIFIED_S:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto IF_MODIFIED_SI;

    default:
        return -1;
    }

IF_MODIFIED_SI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto IF_MODIFIED_SIN;

    default:
        return -1;
    }

IF_MODIFIED_SIN:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto IF_MODIFIED_SINC;

    default:
        return -1;
    }

IF_MODIFIED_SINC:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 38;
        }
        goto IF_MODIFIED_SINCE;

    default:
        return -1;
    }

IF_MODIFIED_SINCE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

IF_N:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto IF_NO;

    default:
        return -1;
    }

IF_NO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto IF_NON;

    default:
        return -1;
    }

IF_NON:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto IF_NONE;

    default:
        return -1;
    }

IF_NONE:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto IF_NONE_;

    default:
        return -1;
    }

IF_NONE_:
    NEXT_CHAR();
    switch (ch) {

    case 'M':
        if (last) {
            return -1;
        }
        goto IF_NONE_M;


    case 'm':
        if (last) {
            return -1;
        }
        goto IF_NONE_M;

    default:
        return -1;
    }

IF_NONE_M:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto IF_NONE_MA;

    default:
        return -1;
    }

IF_NONE_MA:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto IF_NONE_MAT;

    default:
        return -1;
    }

IF_NONE_MAT:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto IF_NONE_MATC;

    default:
        return -1;
    }

IF_NONE_MATC:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return 39;
        }
        goto IF_NONE_MATCH;

    default:
        return -1;
    }

IF_NONE_MATCH:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

IF_R:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto IF_RA;

    default:
        return -1;
    }

IF_RA:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto IF_RAN;

    default:
        return -1;
    }

IF_RAN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto IF_RANG;

    default:
        return -1;
    }

IF_RANG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 40;
        }
        goto IF_RANGE;

    default:
        return -1;
    }

IF_RANGE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

IF_U:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto IF_UN;

    default:
        return -1;
    }

IF_UN:
    NEXT_CHAR();
    switch (ch) {

    case 'm':
        if (last) {
            return -1;
        }
        goto IF_UNM;

    default:
        return -1;
    }

IF_UNM:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto IF_UNMO;

    default:
        return -1;
    }

IF_UNMO:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto IF_UNMOD;

    default:
        return -1;
    }

IF_UNMOD:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto IF_UNMODI;

    default:
        return -1;
    }

IF_UNMODI:
    NEXT_CHAR();
    switch (ch) {

    case 'f':
        if (last) {
            return -1;
        }
        goto IF_UNMODIF;

    default:
        return -1;
    }

IF_UNMODIF:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto IF_UNMODIFI;

    default:
        return -1;
    }

IF_UNMODIFI:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto IF_UNMODIFIE;

    default:
        return -1;
    }

IF_UNMODIFIE:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto IF_UNMODIFIED;

    default:
        return -1;
    }

IF_UNMODIFIED:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto IF_UNMODIFIED_;

    default:
        return -1;
    }

IF_UNMODIFIED_:
    NEXT_CHAR();
    switch (ch) {

    case 'S':
        if (last) {
            return -1;
        }
        goto IF_UNMODIFIED_S;


    case 's':
        if (last) {
            return -1;
        }
        goto IF_UNMODIFIED_S;

    default:
        return -1;
    }

IF_UNMODIFIED_S:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto IF_UNMODIFIED_SI;

    default:
        return -1;
    }

IF_UNMODIFIED_SI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto IF_UNMODIFIED_SIN;

    default:
        return -1;
    }

IF_UNMODIFIED_SIN:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto IF_UNMODIFIED_SINC;

    default:
        return -1;
    }

IF_UNMODIFIED_SINC:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 41;
        }
        goto IF_UNMODIFIED_SINCE;

    default:
        return -1;
    }

IF_UNMODIFIED_SINCE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

K:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto KE;

    default:
        return -1;
    }

KE:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto KEE;

    default:
        return -1;
    }

KEE:
    NEXT_CHAR();
    switch (ch) {

    case 'p':
        if (last) {
            return -1;
        }
        goto KEEP;

    default:
        return -1;
    }

KEEP:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto KEEP_;

    default:
        return -1;
    }

KEEP_:
    NEXT_CHAR();
    switch (ch) {

    case 'A':
        if (last) {
            return -1;
        }
        goto KEEP_A;


    case 'a':
        if (last) {
            return -1;
        }
        goto KEEP_A;

    default:
        return -1;
    }

KEEP_A:
    NEXT_CHAR();
    switch (ch) {

    case 'l':
        if (last) {
            return -1;
        }
        goto KEEP_AL;

    default:
        return -1;
    }

KEEP_AL:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto KEEP_ALI;

    default:
        return -1;
    }

KEEP_ALI:
    NEXT_CHAR();
    switch (ch) {

    case 'v':
        if (last) {
            return -1;
        }
        goto KEEP_ALIV;

    default:
        return -1;
    }

KEEP_ALIV:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 42;
        }
        goto KEEP_ALIVE;

    default:
        return -1;
    }

KEEP_ALIVE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

L:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto LA;


    case 'i':
        if (last) {
            return -1;
        }
        goto LI;


    case 'o':
        if (last) {
            return -1;
        }
        goto LO;

    default:
        return -1;
    }

LA:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto LAS;

    default:
        return -1;
    }

LAS:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto LAST;

    default:
        return -1;
    }

LAST:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto LAST_;

    default:
        return -1;
    }

LAST_:
    NEXT_CHAR();
    switch (ch) {

    case 'E':
        if (last) {
            return -1;
        }
        goto LAST_E;


    case 'e':
        if (last) {
            return -1;
        }
        goto LAST_E;


    case 'M':
        if (last) {
            return -1;
        }
        goto LAST_M;


    case 'm':
        if (last) {
            return -1;
        }
        goto LAST_M;

    default:
        return -1;
    }

LAST_E:
    NEXT_CHAR();
    switch (ch) {

    case 'v':
        if (last) {
            return -1;
        }
        goto LAST_EV;

    default:
        return -1;
    }

LAST_EV:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto LAST_EVE;

    default:
        return -1;
    }

LAST_EVE:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto LAST_EVEN;

    default:
        return -1;
    }

LAST_EVEN:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto LAST_EVENT;

    default:
        return -1;
    }

LAST_EVENT:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto LAST_EVENT_;

    default:
        return -1;
    }

LAST_EVENT_:
    NEXT_CHAR();
    switch (ch) {

    case 'I':
        if (last) {
            return -1;
        }
        goto LAST_EVENT_I;


    case 'i':
        if (last) {
            return -1;
        }
        goto LAST_EVENT_I;

    default:
        return -1;
    }

LAST_EVENT_I:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return 43;
        }
        goto LAST_EVENT_ID;

    default:
        return -1;
    }

LAST_EVENT_ID:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

LAST_M:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto LAST_MO;

    default:
        return -1;
    }

LAST_MO:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto LAST_MOD;

    default:
        return -1;
    }

LAST_MOD:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto LAST_MODI;

    default:
        return -1;
    }

LAST_MODI:
    NEXT_CHAR();
    switch (ch) {

    case 'f':
        if (last) {
            return -1;
        }
        goto LAST_MODIF;

    default:
        return -1;
    }

LAST_MODIF:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto LAST_MODIFI;

    default:
        return -1;
    }

LAST_MODIFI:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto LAST_MODIFIE;

    default:
        return -1;
    }

LAST_MODIFIE:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return 44;
        }
        goto LAST_MODIFIED;

    default:
        return -1;
    }

LAST_MODIFIED:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

LI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto LIN;

    default:
        return -1;
    }

LIN:
    NEXT_CHAR();
    switch (ch) {

    case 'k':
        if (last) {
            return 45;
        }
        goto LINK;

    default:
        return -1;
    }

LINK:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

LO:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto LOC;

    default:
        return -1;
    }

LOC:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto LOCA;

    default:
        return -1;
    }

LOCA:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto LOCAT;

    default:
        return -1;
    }

LOCAT:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto LOCATI;

    default:
        return -1;
    }

LOCATI:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto LOCATIO;

    default:
        return -1;
    }

LOCATIO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return 46;
        }
        goto LOCATION;

    default:
        return -1;
    }

LOCATION:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

M:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto MA;

    default:
        return -1;
    }

MA:
    NEXT_CHAR();
    switch (ch) {

    case 'x':
        if (last) {
            return -1;
        }
        goto MAX;

    default:
        return -1;
    }

MAX:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto MAX_;

    default:
        return -1;
    }

MAX_:
    NEXT_CHAR();
    switch (ch) {

    case 'F':
        if (last) {
            return -1;
        }
        goto MAX_F;


    case 'f':
        if (last) {
            return -1;
        }
        goto MAX_F;

    default:
        return -1;
    }

MAX_F:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto MAX_FO;

    default:
        return -1;
    }

MAX_FO:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto MAX_FOR;

    default:
        return -1;
    }

MAX_FOR:
    NEXT_CHAR();
    switch (ch) {

    case 'w':
        if (last) {
            return -1;
        }
        goto MAX_FORW;

    default:
        return -1;
    }

MAX_FORW:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto MAX_FORWA;

    default:
        return -1;
    }

MAX_FORWA:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto MAX_FORWAR;

    default:
        return -1;
    }

MAX_FORWAR:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto MAX_FORWARD;

    default:
        return -1;
    }

MAX_FORWARD:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return 47;
        }
        goto MAX_FORWARDS;

    default:
        return -1;
    }

MAX_FORWARDS:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

O:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto OR;

    default:
        return -1;
    }

OR:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto ORI;

    default:
        return -1;
    }

ORI:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto ORIG;

    default:
        return -1;
    }

ORIG:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto ORIGI;

    default:
        return -1;
    }

ORIGI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return 48;
        }
        goto ORIGIN;

    default:
        return -1;
    }

ORIGIN:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

P:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto PR;

    default:
        return -1;
    }

PR:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto PRA;


    case 'o':
        if (last) {
            return -1;
        }
        goto PRO;

    default:
        return -1;
    }

PRA:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto PRAG;

    default:
        return -1;
    }

PRAG:
    NEXT_CHAR();
    switch (ch) {

    case 'm':
        if (last) {
            return -1;
        }
        goto PRAGM;

    default:
        return -1;
    }

PRAGM:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return 49;
        }
        goto PRAGMA;

    default:
        return -1;
    }

PRAGMA:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

PRO:
    NEXT_CHAR();
    switch (ch) {

    case 'x':
        if (last) {
            return -1;
        }
        goto PROX;

    default:
        return -1;
    }

PROX:
    NEXT_CHAR();
    switch (ch) {

    case 'y':
        if (last) {
            return -1;
        }
        goto PROXY;

    default:
        return -1;
    }

PROXY:
    NEXT_CHAR();
    switch (ch) {

    case '_':
        if (last) {
            return -1;
        }
        goto PROXY_;


    case '-':
        if (last) {
            return -1;
        }
        goto PROXY_;

    default:
        return -1;
    }

PROXY_:
    NEXT_CHAR();
    switch (ch) {

    case 'A':
        if (last) {
            return -1;
        }
        goto PROXY_A;


    case 'a':
        if (last) {
            return -1;
        }
        goto PROXY_A;

    default:
        return -1;
    }

PROXY_A:
    NEXT_CHAR();
    switch (ch) {

    case 'u':
        if (last) {
            return -1;
        }
        goto PROXY_AU;

    default:
        return -1;
    }

PROXY_AU:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto PROXY_AUT;

    default:
        return -1;
    }

PROXY_AUT:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return -1;
        }
        goto PROXY_AUTH;

    default:
        return -1;
    }

PROXY_AUTH:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto PROXY_AUTHE;

    default:
        return -1;
    }

PROXY_AUTHE:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto PROXY_AUTHEN;

    default:
        return -1;
    }

PROXY_AUTHEN:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto PROXY_AUTHENT;

    default:
        return -1;
    }

PROXY_AUTHENT:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto PROXY_AUTHENTI;

    default:
        return -1;
    }

PROXY_AUTHENTI:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto PROXY_AUTHENTIC;

    default:
        return -1;
    }

PROXY_AUTHENTIC:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto PROXY_AUTHENTICA;

    default:
        return -1;
    }

PROXY_AUTHENTICA:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto PROXY_AUTHENTICAT;

    default:
        return -1;
    }

PROXY_AUTHENTICAT:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 50;
        }
        goto PROXY_AUTHENTICATE;

    default:
        return -1;
    }

PROXY_AUTHENTICATE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

R:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto RA;


    case 'e':
        if (last) {
            return -1;
        }
        goto RE;

    default:
        return -1;
    }

RA:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto RAN;

    default:
        return -1;
    }

RAN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto RANG;

    default:
        return -1;
    }

RANG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 52;
        }
        goto RANGE;

    default:
        return -1;
    }

RANGE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

RE:
    NEXT_CHAR();
    switch (ch) {

    case 'f':
        if (last) {
            return -1;
        }
        goto REF;


    case 't':
        if (last) {
            return -1;
        }
        goto RET;

    default:
        return -1;
    }

REF:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto REFE;

    default:
        return -1;
    }

REFE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto REFER;

    default:
        return -1;
    }

REFER:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto REFERE;

    default:
        return -1;
    }

REFERE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return 53;
        }
        goto REFERER;

    default:
        return -1;
    }

REFERER:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

RET:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto RETR;

    default:
        return -1;
    }

RETR:
    NEXT_CHAR();
    switch (ch) {

    case 'y':
        if (last) {
            return -1;
        }
        goto RETRY;

    default:
        return -1;
    }

RETRY:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto RETRY_;

    default:
        return -1;
    }

RETRY_:
    NEXT_CHAR();
    switch (ch) {

    case 'A':
        if (last) {
            return -1;
        }
        goto RETRY_A;


    case 'a':
        if (last) {
            return -1;
        }
        goto RETRY_A;

    default:
        return -1;
    }

RETRY_A:
    NEXT_CHAR();
    switch (ch) {

    case 'f':
        if (last) {
            return -1;
        }
        goto RETRY_AF;

    default:
        return -1;
    }

RETRY_AF:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto RETRY_AFT;

    default:
        return -1;
    }

RETRY_AFT:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto RETRY_AFTE;

    default:
        return -1;
    }

RETRY_AFTE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return 54;
        }
        goto RETRY_AFTER;

    default:
        return -1;
    }

RETRY_AFTER:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

S:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto SE;

    default:
        return -1;
    }

SE:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto SEC;


    case 'r':
        if (last) {
            return -1;
        }
        goto SER;


    case 't':
        if (last) {
            return -1;
        }
        goto SET;

    default:
        return -1;
    }

SEC:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto SEC_;

    default:
        return -1;
    }

SEC_:
    NEXT_CHAR();
    switch (ch) {

    case 'W':
        if (last) {
            return -1;
        }
        goto SEC_W;


    case 'w':
        if (last) {
            return -1;
        }
        goto SEC_W;

    default:
        return -1;
    }

SEC_W:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto SEC_WE;

    default:
        return -1;
    }

SEC_WE:
    NEXT_CHAR();
    switch (ch) {

    case 'b':
        if (last) {
            return -1;
        }
        goto SEC_WEB;

    default:
        return -1;
    }

SEC_WEB:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto SEC_WEBS;

    default:
        return -1;
    }

SEC_WEBS:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto SEC_WEBSO;

    default:
        return -1;
    }

SEC_WEBSO:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOC;

    default:
        return -1;
    }

SEC_WEBSOC:
    NEXT_CHAR();
    switch (ch) {

    case 'k':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCK;

    default:
        return -1;
    }

SEC_WEBSOCK:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKE;

    default:
        return -1;
    }

SEC_WEBSOCKE:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET;

    default:
        return -1;
    }

SEC_WEBSOCKET:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_;

    default:
        return -1;
    }

SEC_WEBSOCKET_:
    NEXT_CHAR();
    switch (ch) {

    case 'A':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_A;


    case 'a':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_A;


    case 'E':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_E;


    case 'e':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_E;


    case 'K':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_K;


    case 'k':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_K;


    case 'P':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_P;


    case 'p':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_P;


    case 'V':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_V;


    case 'v':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_V;

    default:
        return -1;
    }

SEC_WEBSOCKET_A:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_AC;

    default:
        return -1;
    }

SEC_WEBSOCKET_AC:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_ACC;

    default:
        return -1;
    }

SEC_WEBSOCKET_ACC:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_ACCE;

    default:
        return -1;
    }

SEC_WEBSOCKET_ACCE:
    NEXT_CHAR();
    switch (ch) {

    case 'p':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_ACCEP;

    default:
        return -1;
    }

SEC_WEBSOCKET_ACCEP:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 55;
        }
        goto SEC_WEBSOCKET_ACCEPT;

    default:
        return -1;
    }

SEC_WEBSOCKET_ACCEPT:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

SEC_WEBSOCKET_E:
    NEXT_CHAR();
    switch (ch) {

    case 'x':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_EX;

    default:
        return -1;
    }

SEC_WEBSOCKET_EX:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_EXT;

    default:
        return -1;
    }

SEC_WEBSOCKET_EXT:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_EXTE;

    default:
        return -1;
    }

SEC_WEBSOCKET_EXTE:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_EXTEN;

    default:
        return -1;
    }

SEC_WEBSOCKET_EXTEN:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_EXTENS;

    default:
        return -1;
    }

SEC_WEBSOCKET_EXTENS:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_EXTENSI;

    default:
        return -1;
    }

SEC_WEBSOCKET_EXTENSI:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_EXTENSIO;

    default:
        return -1;
    }

SEC_WEBSOCKET_EXTENSIO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_EXTENSION;

    default:
        return -1;
    }

SEC_WEBSOCKET_EXTENSION:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return 56;
        }
        goto SEC_WEBSOCKET_EXTENSIONS;

    default:
        return -1;
    }

SEC_WEBSOCKET_EXTENSIONS:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

SEC_WEBSOCKET_K:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_KE;

    default:
        return -1;
    }

SEC_WEBSOCKET_KE:
    NEXT_CHAR();
    switch (ch) {

    case 'y':
        if (last) {
            return 57;
        }
        goto SEC_WEBSOCKET_KEY;

    default:
        return -1;
    }

SEC_WEBSOCKET_KEY:
    NEXT_CHAR();
    switch (ch) {

    case '1':
        if (last) {
            return 58;
        }
        goto SEC_WEBSOCKET_KEY1;

    default:
        return -1;
    }

SEC_WEBSOCKET_KEY1:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

SEC_WEBSOCKET_P:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_PR;

    default:
        return -1;
    }

SEC_WEBSOCKET_PR:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_PRO;

    default:
        return -1;
    }

SEC_WEBSOCKET_PRO:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_PROT;

    default:
        return -1;
    }

SEC_WEBSOCKET_PROT:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_PROTO;

    default:
        return -1;
    }

SEC_WEBSOCKET_PROTO:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_PROTOC;

    default:
        return -1;
    }

SEC_WEBSOCKET_PROTOC:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_PROTOCO;

    default:
        return -1;
    }

SEC_WEBSOCKET_PROTOCO:
    NEXT_CHAR();
    switch (ch) {

    case 'l':
        if (last) {
            return 59;
        }
        goto SEC_WEBSOCKET_PROTOCOL;

    default:
        return -1;
    }

SEC_WEBSOCKET_PROTOCOL:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

SEC_WEBSOCKET_V:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_VE;

    default:
        return -1;
    }

SEC_WEBSOCKET_VE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_VER;

    default:
        return -1;
    }

SEC_WEBSOCKET_VER:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_VERS;

    default:
        return -1;
    }

SEC_WEBSOCKET_VERS:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_VERSI;

    default:
        return -1;
    }

SEC_WEBSOCKET_VERSI:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto SEC_WEBSOCKET_VERSIO;

    default:
        return -1;
    }

SEC_WEBSOCKET_VERSIO:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return 60;
        }
        goto SEC_WEBSOCKET_VERSION;

    default:
        return -1;
    }

SEC_WEBSOCKET_VERSION:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

SER:
    NEXT_CHAR();
    switch (ch) {

    case 'v':
        if (last) {
            return -1;
        }
        goto SERV;

    default:
        return -1;
    }

SERV:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto SERVE;

    default:
        return -1;
    }

SERVE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return 61;
        }
        goto SERVER;

    default:
        return -1;
    }

SERVER:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

SET:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto SET_;

    default:
        return -1;
    }

SET_:
    NEXT_CHAR();
    switch (ch) {

    case 'C':
        if (last) {
            return -1;
        }
        goto SET_C;


    case 'c':
        if (last) {
            return -1;
        }
        goto SET_C;

    default:
        return -1;
    }

SET_C:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto SET_CO;

    default:
        return -1;
    }

SET_CO:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto SET_COO;

    default:
        return -1;
    }

SET_COO:
    NEXT_CHAR();
    switch (ch) {

    case 'k':
        if (last) {
            return -1;
        }
        goto SET_COOK;

    default:
        return -1;
    }

SET_COOK:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto SET_COOKI;

    default:
        return -1;
    }

SET_COOKI:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 62;
        }
        goto SET_COOKIE;

    default:
        return -1;
    }

SET_COOKIE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

T:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 63;
        }
        goto TE;


    case 'r':
        if (last) {
            return -1;
        }
        goto TR;

    default:
        return -1;
    }

TE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

TR:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto TRA;

    default:
        return -1;
    }

TRA:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto TRAI;


    case 'n':
        if (last) {
            return -1;
        }
        goto TRAN;

    default:
        return -1;
    }

TRAI:
    NEXT_CHAR();
    switch (ch) {

    case 'l':
        if (last) {
            return -1;
        }
        goto TRAIL;

    default:
        return -1;
    }

TRAIL:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto TRAILE;

    default:
        return -1;
    }

TRAILE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return 64;
        }
        goto TRAILER;

    default:
        return -1;
    }

TRAILER:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

TRAN:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto TRANS;

    default:
        return -1;
    }

TRANS:
    NEXT_CHAR();
    switch (ch) {

    case 'f':
        if (last) {
            return -1;
        }
        goto TRANSF;

    default:
        return -1;
    }

TRANSF:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto TRANSFE;

    default:
        return -1;
    }

TRANSFE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto TRANSFER;

    default:
        return -1;
    }

TRANSFER:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto TRANSFER_;

    default:
        return -1;
    }

TRANSFER_:
    NEXT_CHAR();
    switch (ch) {

    case 'E':
        if (last) {
            return -1;
        }
        goto TRANSFER_E;


    case 'e':
        if (last) {
            return -1;
        }
        goto TRANSFER_E;

    default:
        return -1;
    }

TRANSFER_E:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto TRANSFER_EN;

    default:
        return -1;
    }

TRANSFER_EN:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto TRANSFER_ENC;

    default:
        return -1;
    }

TRANSFER_ENC:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto TRANSFER_ENCO;

    default:
        return -1;
    }

TRANSFER_ENCO:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto TRANSFER_ENCOD;

    default:
        return -1;
    }

TRANSFER_ENCOD:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto TRANSFER_ENCODI;

    default:
        return -1;
    }

TRANSFER_ENCODI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto TRANSFER_ENCODIN;

    default:
        return -1;
    }

TRANSFER_ENCODIN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return 65;
        }
        goto TRANSFER_ENCODING;

    default:
        return -1;
    }

TRANSFER_ENCODING:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

U:
    NEXT_CHAR();
    switch (ch) {

    case 'p':
        if (last) {
            return -1;
        }
        goto UP;


    case 'r':
        if (last) {
            return -1;
        }
        goto UR;


    case 's':
        if (last) {
            return -1;
        }
        goto US;

    default:
        return -1;
    }

UP:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto UPG;

    default:
        return -1;
    }

UPG:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto UPGR;

    default:
        return -1;
    }

UPGR:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto UPGRA;

    default:
        return -1;
    }

UPGRA:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto UPGRAD;

    default:
        return -1;
    }

UPGRAD:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 66;
        }
        goto UPGRADE;

    default:
        return -1;
    }

UPGRADE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

UR:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return 67;
        }
        goto URI;

    default:
        return -1;
    }

URI:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

US:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto USE;

    default:
        return -1;
    }

USE:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto USER;

    default:
        return -1;
    }

USER:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto USER_;

    default:
        return -1;
    }

USER_:
    NEXT_CHAR();
    switch (ch) {

    case 'A':
        if (last) {
            return -1;
        }
        goto USER_A;


    case 'a':
        if (last) {
            return -1;
        }
        goto USER_A;

    default:
        return -1;
    }

USER_A:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto USER_AG;

    default:
        return -1;
    }

USER_AG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto USER_AGE;

    default:
        return -1;
    }

USER_AGE:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto USER_AGEN;

    default:
        return -1;
    }

USER_AGEN:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 68;
        }
        goto USER_AGENT;

    default:
        return -1;
    }

USER_AGENT:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

V:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto VA;


    case 'i':
        if (last) {
            return -1;
        }
        goto VI;

    default:
        return -1;
    }

VA:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto VAR;

    default:
        return -1;
    }

VAR:
    NEXT_CHAR();
    switch (ch) {

    case 'y':
        if (last) {
            return 69;
        }
        goto VARY;

    default:
        return -1;
    }

VARY:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

VI:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return 70;
        }
        goto VIA;

    default:
        return -1;
    }

VIA:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

W:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto WA;


    case 'e':
        if (last) {
            return -1;
        }
        goto WE;


    case 'w':
        if (last) {
            return -1;
        }
        goto WW;

    default:
        return -1;
    }

WA:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto WAN;


    case 'r':
        if (last) {
            return -1;
        }
        goto WAR;

    default:
        return -1;
    }

WAN:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto WANT;

    default:
        return -1;
    }

WANT:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto WANT_;

    default:
        return -1;
    }

WANT_:
    NEXT_CHAR();
    switch (ch) {

    case 'D':
        if (last) {
            return -1;
        }
        goto WANT_D;


    case 'd':
        if (last) {
            return -1;
        }
        goto WANT_D;

    default:
        return -1;
    }

WANT_D:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto WANT_DI;

    default:
        return -1;
    }

WANT_DI:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return -1;
        }
        goto WANT_DIG;

    default:
        return -1;
    }

WANT_DIG:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto WANT_DIGE;

    default:
        return -1;
    }

WANT_DIGE:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto WANT_DIGES;

    default:
        return -1;
    }

WANT_DIGES:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 71;
        }
        goto WANT_DIGEST;

    default:
        return -1;
    }

WANT_DIGEST:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

WAR:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto WARN;

    default:
        return -1;
    }

WARN:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto WARNI;

    default:
        return -1;
    }

WARNI:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto WARNIN;

    default:
        return -1;
    }

WARNIN:
    NEXT_CHAR();
    switch (ch) {

    case 'g':
        if (last) {
            return 72;
        }
        goto WARNING;

    default:
        return -1;
    }

WARNING:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

WE:
    NEXT_CHAR();
    switch (ch) {

    case 'b':
        if (last) {
            return -1;
        }
        goto WEB;

    default:
        return -1;
    }

WEB:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto WEBS;

    default:
        return -1;
    }

WEBS:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto WEBSO;

    default:
        return -1;
    }

WEBSO:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto WEBSOC;

    default:
        return -1;
    }

WEBSOC:
    NEXT_CHAR();
    switch (ch) {

    case 'k':
        if (last) {
            return -1;
        }
        goto WEBSOCK;

    default:
        return -1;
    }

WEBSOCK:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto WEBSOCKE;

    default:
        return -1;
    }

WEBSOCKE:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 73;
        }
        goto WEBSOCKET;

    default:
        return -1;
    }

WEBSOCKET:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

WW:
    NEXT_CHAR();
    switch (ch) {

    case 'w':
        if (last) {
            return -1;
        }
        goto WWW;

    default:
        return -1;
    }

WWW:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto WWW_;

    default:
        return -1;
    }

WWW_:
    NEXT_CHAR();
    switch (ch) {

    case 'A':
        if (last) {
            return -1;
        }
        goto WWW_A;


    case 'a':
        if (last) {
            return -1;
        }
        goto WWW_A;

    default:
        return -1;
    }

WWW_A:
    NEXT_CHAR();
    switch (ch) {

    case 'u':
        if (last) {
            return -1;
        }
        goto WWW_AU;

    default:
        return -1;
    }

WWW_AU:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto WWW_AUT;

    default:
        return -1;
    }

WWW_AUT:
    NEXT_CHAR();
    switch (ch) {

    case 'h':
        if (last) {
            return -1;
        }
        goto WWW_AUTH;

    default:
        return -1;
    }

WWW_AUTH:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto WWW_AUTHE;

    default:
        return -1;
    }

WWW_AUTHE:
    NEXT_CHAR();
    switch (ch) {

    case 'n':
        if (last) {
            return -1;
        }
        goto WWW_AUTHEN;

    default:
        return -1;
    }

WWW_AUTHEN:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto WWW_AUTHENT;

    default:
        return -1;
    }

WWW_AUTHENT:
    NEXT_CHAR();
    switch (ch) {

    case 'i':
        if (last) {
            return -1;
        }
        goto WWW_AUTHENTI;

    default:
        return -1;
    }

WWW_AUTHENTI:
    NEXT_CHAR();
    switch (ch) {

    case 'c':
        if (last) {
            return -1;
        }
        goto WWW_AUTHENTIC;

    default:
        return -1;
    }

WWW_AUTHENTIC:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto WWW_AUTHENTICA;

    default:
        return -1;
    }

WWW_AUTHENTICA:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto WWW_AUTHENTICAT;

    default:
        return -1;
    }

WWW_AUTHENTICAT:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return 74;
        }
        goto WWW_AUTHENTICATE;

    default:
        return -1;
    }

WWW_AUTHENTICATE:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

X:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto X_;

    default:
        return -1;
    }

X_:
    NEXT_CHAR();
    switch (ch) {

    case 'F':
        if (last) {
            return -1;
        }
        goto X_F;


    case 'f':
        if (last) {
            return -1;
        }
        goto X_F;

    default:
        return -1;
    }

X_F:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto X_FO;

    default:
        return -1;
    }

X_FO:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto X_FOR;

    default:
        return -1;
    }

X_FOR:
    NEXT_CHAR();
    switch (ch) {

    case 'w':
        if (last) {
            return -1;
        }
        goto X_FORW;

    default:
        return -1;
    }

X_FORW:
    NEXT_CHAR();
    switch (ch) {

    case 'a':
        if (last) {
            return -1;
        }
        goto X_FORWA;

    default:
        return -1;
    }

X_FORWA:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto X_FORWAR;

    default:
        return -1;
    }

X_FORWAR:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto X_FORWARD;

    default:
        return -1;
    }

X_FORWARD:
    NEXT_CHAR();
    switch (ch) {

    case 'e':
        if (last) {
            return -1;
        }
        goto X_FORWARDE;

    default:
        return -1;
    }

X_FORWARDE:
    NEXT_CHAR();
    switch (ch) {

    case 'd':
        if (last) {
            return -1;
        }
        goto X_FORWARDED;

    default:
        return -1;
    }

X_FORWARDED:
    NEXT_CHAR();
    switch (ch) {

    case '-':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_;

    default:
        return -1;
    }

X_FORWARDED_:
    NEXT_CHAR();
    switch (ch) {

    case 'F':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_F;


    case 'f':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_F;


    case 'H':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_H;


    case 'h':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_H;


    case 'P':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_P;


    case 'p':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_P;

    default:
        return -1;
    }

X_FORWARDED_F:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_FO;

    default:
        return -1;
    }

X_FORWARDED_FO:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return 75;
        }
        goto X_FORWARDED_FOR;

    default:
        return -1;
    }

X_FORWARDED_FOR:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

X_FORWARDED_H:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_HO;

    default:
        return -1;
    }

X_FORWARDED_HO:
    NEXT_CHAR();
    switch (ch) {

    case 's':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_HOS;

    default:
        return -1;
    }

X_FORWARDED_HOS:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return 76;
        }
        goto X_FORWARDED_HOST;

    default:
        return -1;
    }

X_FORWARDED_HOST:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

X_FORWARDED_P:
    NEXT_CHAR();
    switch (ch) {

    case 'r':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_PR;

    default:
        return -1;
    }

X_FORWARDED_PR:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_PRO;

    default:
        return -1;
    }

X_FORWARDED_PRO:
    NEXT_CHAR();
    switch (ch) {

    case 't':
        if (last) {
            return -1;
        }
        goto X_FORWARDED_PROT;

    default:
        return -1;
    }

X_FORWARDED_PROT:
    NEXT_CHAR();
    switch (ch) {

    case 'o':
        if (last) {
            return 77;
        }
        goto X_FORWARDED_PROTO;

    default:
        return -1;
    }

X_FORWARDED_PROTO:
    NEXT_CHAR();
    switch (ch) {

    default:
        return -1;
    }

missing:
    return -1;
}
