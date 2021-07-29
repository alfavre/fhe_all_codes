#include "mastermind_simple.h"

#pragma hls_top // this NEEDS to be on the line before the declaration or nothing will work :/
short mastermind_simple(short secret, short challenger) {
    short result = 00;

    // check reds aka exact position
    #pragma hls_unroll yes
    for (int i = 0; i < 4; i++) {
        result += (((secret >> 3 * i) & 00007) == ((challenger >> 3 * i) & 00007));
    }
    result = result << 3;

    // check whites aka except exact position
    #pragma hls_unroll yes
    for (int i = 0; i < 4; i++) {
        #pragma hls_unroll yes
        for (int j = 0; j < 4; j++) {
            if (j != i)
                result += (((secret >> 3 * i) & 00007) == ((challenger >> 3 * j) & 00007));
        }
    }
    return result;
}

