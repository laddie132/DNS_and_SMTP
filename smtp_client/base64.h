//
// Created by L.Laddie on 2017/5/14.
//

#ifndef SMTP_CLIENT_BASE64_H
#define SMTP_CLIENT_BASE64_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

struct Base64Date6
{
    unsigned int d4:6;
    unsigned int d3:6;
    unsigned int d2:6;
    unsigned int d1:6;
};

void EncodeBase64(char *dbuf, const char *buf128, int len);

#endif //SMTP_CLIENT_BASE64_H
