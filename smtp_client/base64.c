//
// Created by L.Laddie on 2017/5/14.
//

#include "base64.h"

char ConvertToBase64(unsigned int uc) {
    if (uc < 26) {
        return (char) ('A' + uc);
    }
    if (uc < 52) {
        return (char) ('a' + (uc - 26));
    }
    if (uc < 62) {
        return (char) ('0' + (uc - 52));
    }
    if (uc == 62) {
        return '+';
    }
    return '/';
}

// base64的实现
void EncodeBase64(char *dbuf, const char *buf128, int len) {
    struct Base64Date6 *ddd = NULL;
    int i = 0;
    char buf[256] = {0};
    char *tmp = NULL;
    char cc = '\0';

    memset(buf, 0, 256);
    strncpy(buf, buf128, 256);
    for (i = 1; i <= len / 3; i++) {
        tmp = buf + (i - 1) * 3;
        cc = tmp[2];
        tmp[2] = tmp[0];
        tmp[0] = cc;
        ddd = (struct Base64Date6 *) tmp;
        dbuf[(i - 1) * 4 + 0] = ConvertToBase64((unsigned int) ddd->d1);
        dbuf[(i - 1) * 4 + 1] = ConvertToBase64((unsigned int) ddd->d2);
        dbuf[(i - 1) * 4 + 2] = ConvertToBase64((unsigned int) ddd->d3);
        dbuf[(i - 1) * 4 + 3] = ConvertToBase64((unsigned int) ddd->d4);
    }
    if (len % 3 == 1) {
        tmp = buf + (i - 1) * 3;
        cc = tmp[2];
        tmp[2] = tmp[0];
        tmp[0] = cc;
        ddd = (struct Base64Date6 *) tmp;
        dbuf[(i - 1) * 4 + 0] = ConvertToBase64((unsigned int) ddd->d1);
        dbuf[(i - 1) * 4 + 1] = ConvertToBase64((unsigned int) ddd->d2);
        dbuf[(i - 1) * 4 + 2] = '=';
        dbuf[(i - 1) * 4 + 3] = '=';
    }
    if (len % 3 == 2) {
        tmp = buf + (i - 1) * 3;
        cc = tmp[2];
        tmp[2] = tmp[0];
        tmp[0] = cc;
        ddd = (struct Base64Date6 *) tmp;
        dbuf[(i - 1) * 4 + 0] = ConvertToBase64((unsigned int) ddd->d1);
        dbuf[(i - 1) * 4 + 1] = ConvertToBase64((unsigned int) ddd->d2);
        dbuf[(i - 1) * 4 + 2] = ConvertToBase64((unsigned int) ddd->d3);
        dbuf[(i - 1) * 4 + 3] = '=';
    }
    return;
}