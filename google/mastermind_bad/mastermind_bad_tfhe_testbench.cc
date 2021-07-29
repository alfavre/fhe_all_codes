#include <stdint.h>
#include <bitset>
#include <iostream>
#include <chrono>

#include "tfhe/tfhe.h"
#include "transpiler/data/fhe_data.h"
#include "xls/common/logging/logging.h"


#include "transpiler/examples/mastermind_bad/mastermind_bad_tfhe.h"

// to run:"bazel run //transpiler/examples/mastermind_bad:mastermind_bad_tfhe_testbench"

using namespace std;

const int main_minimum_lambda = 120;
const int MAX_ATTEMPTS = 6;

// this is basically stolen from bad sum
int main(int argc, char** argv) {
    // generate a keyset
    TFheGateBootstrappingParameterSet* params =
            new_default_gate_bootstrapping_parameters(main_minimum_lambda);

    // generate a random key
    // Note: In real applications, a cryptographically secure seed needs to be
    // used.
    uint32_t seed[] = {314, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet* key =
            new_random_gate_bootstrapping_secret_keyset(params);
    const TFheGateBootstrappingCloudKeySet* cloud_key = &key->cloud;

    // create secret code
    short code = 05461;

    // Encrypt code
    auto ciphertext_code = FheShort::Encrypt(code, key);
    cout << "Encryption code done." << endl;

    int attempts_made = 0;
    bool game_is_won=false;
    while (attempts_made < MAX_ATTEMPTS &&
           !game_is_won){
        short challenge = 00;
        cout << "Type your code, four digits between 0 and 7.\nThe numbers represent the colors.\nPlease be nice, there is no input control\nYour number: " << endl;
        scanf("%o", &challenge);
        cout << "Your code is: " << oct << challenge << "\t" << bitset<12>(challenge) << endl;

        auto ciphertext_challenge = FheShort::Encrypt(challenge, key);
        cout << "Encryption of your code done" << endl;


        cout << "\tThe mastermind will now rate your code.\n\tThey will take their time to do so.\n\tPlease be patient." << endl;

        FheShort cipher_result(params);

        auto t_start = std::chrono::high_resolution_clock::now();

        XLS_CHECK_OK(mastermind_bad(cipher_result.get(), ciphertext_code.get(),
                           ciphertext_challenge.get(), cloud_key));

        auto t_end = std::chrono::high_resolution_clock::now();

        double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end-t_start).count();

        cout << "\tThe mastermind is done!" << endl;
        cout << "\tIt took them: " << elapsed_time_ms << " miliseconds" << endl;

        short result = cipher_result.Decrypt(key);
        cout << "You got " << oct << (result >> 3) << " correct color(s) in the exact spot" << endl;
        cout << "You got " << oct << (result & 07) << " color(s) correctly but not in the exact spot" << endl;

        if((result >> 3)==04){
            game_is_won=true;
            cout << "A winner is you!" << endl;
        }
        attempts_made++;
    }


}
