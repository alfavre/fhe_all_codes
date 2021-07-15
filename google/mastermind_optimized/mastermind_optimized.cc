#include "mastermind_optimized.h"

#pragma hls_top // this NEEDS to be on the line before the declaration or nothing will work :/
short mastermind_optimized(short secret, short challenger) {
    // 3210 aka lil endian

    short result = 00;
    short mask_3 = 07000;
    short mask_2 = 00700;
    short mask_1 = 00070;
    short mask_0 = 00007;

    short secret_0 = secret & mask_0;
    short secret_1 = secret & mask_1;
    short secret_2 = secret & mask_2;
    short secret_3 = secret & mask_3;

    short challenger_0 = challenger & mask_0;
    short challenger_1 = challenger & mask_1;
    short challenger_2 = challenger & mask_2;
    short challenger_3 = challenger & mask_3;



    // reds
    result += (secret_0 == challenger_0);
    result += (secret_1 == challenger_1);
    result += (secret_2 == challenger_2);
    result += (secret_3 == challenger_3);
    result = result << 3;


    //whites
    challenger_0<<=3;
    result += (secret_1 == challenger_0);
    challenger_0<<=3;
    result += (secret_2 == challenger_0);
    challenger_0<<=3;
    result += (secret_3 == challenger_0);


    secret_0<<=3;
    result += (secret_0 == challenger_1);
    secret_0<<=3;
    result += (secret_0 == challenger_2);
    secret_0<<=3;
    result += (secret_0 == challenger_3);


    challenger_1<<=3;
    result += (secret_2 == challenger_1);
    challenger_1<<=3;
    result += (secret_3 == challenger_1);

    result += (secret_1<<3 == challenger_2);
    result += (secret_3 == challenger_2 << 3);

    challenger_3 >>=3;
    result += (secret_2 == challenger_3);
    challenger_3 >>=3;
    result += (secret_1 == challenger_3);


    return result;
}
