#include "mastermind_simple.h"

#pragma hls_top // this NEEDS to be on the line before the declaration or nothing will work :/
short mastermind_simple(short secret, short challenger) {
    // 0123 aka big endian

    short result = 00;
    // secret decomposed
    short secret_0 = secret >> 9; // we suppose no garbage in last 3 bits
    short secret_1 = (secret >> 6) & 00007;
    short secret_2 = (secret >> 3) & 00007;
    short secret_3 = secret & 00007;

    // challenger decomposed
    short challenger_0 = challenger >> 9; // we suppose no garbage in last 3 bits
    short challenger_1 = (challenger >> 6) & 00007;
    short challenger_2 = (challenger >> 3) & 00007;
    short challenger_3 = challenger & 00007;

    // check reds aka exact position
    // this is not binary anymore, will need to be fixed
    result += (secret_0 == challenger_0);
    result += (secret_1 == challenger_1);
    result += (secret_2 == challenger_2);
    result += (secret_3 == challenger_3);
    result = result << 3;

    // check whites aka except exact position
    // this is not binary anymore, will need to be fixed
    result += (secret_0 == challenger_1);
    result += (secret_0 == challenger_2);
    result += (secret_0 == challenger_3);

    result += (secret_1 == challenger_0);
    result += (secret_1 == challenger_2);
    result += (secret_1 == challenger_3);

    result += (secret_2 == challenger_0);
    result += (secret_2 == challenger_1);
    result += (secret_2 == challenger_3);

    result += (secret_3 == challenger_0);
    result += (secret_3 == challenger_1);
    result += (secret_3 == challenger_2);


    return result;
}
