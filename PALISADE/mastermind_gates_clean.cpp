//
// Created by alban on 10.06.21.
//

#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;

const int MAX_ATTEMPTS = 6;

vector<shared_ptr<LWECiphertextImpl>> adder_round_2_to_4(
    BinFHEContext crypto_context, shared_ptr<LWECiphertextImpl> initial_bit_0,
    shared_ptr<LWECiphertextImpl> initial_bit_1,
    shared_ptr<LWECiphertextImpl> initial_bit_2,
    shared_ptr<LWECiphertextImpl> added_bit) {
  vector<shared_ptr<LWECiphertextImpl>> result;

  shared_ptr<LWECiphertextImpl> carry_1 =
      crypto_context.EvalBinGate(AND, initial_bit_0, added_bit);
  shared_ptr<LWECiphertextImpl> result_ct_0 =
      crypto_context.EvalBinGate(XOR, initial_bit_0, added_bit);
  shared_ptr<LWECiphertextImpl> carry_2 =
      crypto_context.EvalBinGate(AND, initial_bit_1, carry_1);
  shared_ptr<LWECiphertextImpl> result_ct_1 = crypto_context.EvalBinGate(
      XOR, carry_1, initial_bit_1);  // they can be both 1
  shared_ptr<LWECiphertextImpl> result_ct_2 = crypto_context.EvalBinGate(
      OR, carry_2,
      initial_bit_2);  // it is impossible that those 2 are both 1, but if
  // one is already 1, better not override it
  // we know that it is this simple as the max is 100

  result.push_back(result_ct_0);
  result.push_back(result_ct_1);
  result.push_back(result_ct_2);
  return result;
}

vector<shared_ptr<LWECiphertextImpl>> adder_round_1(
    BinFHEContext crypto_context,
    vector<shared_ptr<LWECiphertextImpl>> bits_to_add) {
  vector<shared_ptr<LWECiphertextImpl>> result;

  // full adder simplified
  // for addition of only 1 bit at the time, never multi bit numbers

  // add first bit
  // we know that the second and third result bit can't be affected as max is
  // 1
  shared_ptr<LWECiphertextImpl> result_ct_0 =
      bits_to_add[0];  // first add, 0 + first bit = first bit obv

  // add second bit
  // result_ct_0 + second bit = ???
  // we know that the third result bit can't be affected as max is 2 (10)
  shared_ptr<LWECiphertextImpl> carry_1 =
      crypto_context.EvalBinGate(AND, result_ct_0, bits_to_add[1]);
  result_ct_0 = crypto_context.EvalBinGate(XOR, result_ct_0, bits_to_add[1]);
  shared_ptr<LWECiphertextImpl> result_ct_1 = carry_1;

  // add third bit
  // (result_ct_0 || result_ct_1) + third bit = ???
  // we know that the third result bit can't be affected as max is 3 (11)
  carry_1 = crypto_context.EvalBinGate(AND, result_ct_0, bits_to_add[2]);
  result_ct_0 = crypto_context.EvalBinGate(XOR, result_ct_0, bits_to_add[2]);
  result_ct_1 = crypto_context.EvalBinGate(
      OR, carry_1,
      result_ct_1);  // it is impossible that those 2 are both 1

  // add fourth bit
  // (result_ct_0 || result_ct_1) + forth bit = ???
  // this is the most complex as it can affect 3 result bits, max is 4 (100)
  carry_1 = crypto_context.EvalBinGate(AND, result_ct_0, bits_to_add[3]);
  result_ct_0 = crypto_context.EvalBinGate(XOR, result_ct_0, bits_to_add[3]);
  shared_ptr<LWECiphertextImpl> carry_2 =
      crypto_context.EvalBinGate(AND, result_ct_1, carry_1);
  result_ct_1 = crypto_context.EvalBinGate(XOR, carry_1,
                                           result_ct_1);  // they can be both 1
  shared_ptr<LWECiphertextImpl> result_ct_2 =
      carry_2;  // we know that it is this simple as the max is 100

  result.push_back(result_ct_0);
  result.push_back(result_ct_1);
  result.push_back(result_ct_2);
  return result;
}

int main() {
  // Sample Program: Step 1: Set CryptoContext

  BinFHEContext cc = BinFHEContext();

  // STD128 is the security level of 128 bits of security based on LWE Estimator
  // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
  // MEDIUM corresponds to the level of more than 100 bits for both quantum and
  // classical computer attacks.
  cc.GenerateBinFHEContext(STD128);

  // Sample Program: Step 2: Key Generation

  // Generate the secret key
  auto sk = cc.KeyGen();

  std::cout << "Generating the bootstrapping keys..." << std::endl;

  // Generate the bootstrapping keys (refresh and switching keys)
  cc.BTKeyGen(sk);

  std::cout << "Completed the key generation." << std::endl;

  // Encrypt two ciphertexts representing Boolean True (1).
  // By default, freshly encrypted ciphertexts are bootstrapped.
  // If you wish to get a fresh encryption without bootstrapping, write
  // auto   ct1 = cc.Encrypt(sk, 1, FRESH);

  auto code_bits = bitset<12>(05461);

  // this vector is little endian
  vector<shared_ptr<LWECiphertextImpl>> secret_code;
  for (int i = 0; i < 12; i++) {
    secret_code.push_back(cc.Encrypt(sk, code_bits[i]));
  }

  cout << "Secret code encrypted." << endl;

  int attempts_made = 0;
  bool game_is_won = false;
  while (attempts_made < MAX_ATTEMPTS && !game_is_won) {
    int challenge = 00;
    cout << "Type your code, four digits between 0 and 7.\nThe numbers "
            "represent the colors.\nPlease be nice, there is no input "
            "control\nYour number: "
         << endl;
    scanf("%o", &challenge);
    auto challenge_bits = bitset<12>(challenge);
    cout << "Your code is: " << oct << challenge << dec << "\t"
         << challenge_bits << endl;

    // this vector is little endian
    vector<shared_ptr<LWECiphertextImpl>> challenger;
    for (int i = 0; i < 12; i++) {
      challenger.push_back(cc.Encrypt(sk, challenge_bits[i]));
    }
    cout << "Encryption of your code done" << endl;

    cout << "\tThe mastermind will now rate your code.\n\tThey will take their "
            "time to do so.\n\tPlease be patient."
         << endl;

    auto t_start = std::chrono::high_resolution_clock::now();

    // do compare here
    //---------------------------------------------------------------------------

    // reds first
    vector<shared_ptr<LWECiphertextImpl>> xnor_red_results;

    for (int i = 0; i < 12; i++) {
      // the endianese of the next vectors can be ignored as position won't
      // matter at the end
      xnor_red_results.push_back(
          cc.EvalBinGate(XNOR, secret_code[i], challenger[i]));
    }

    // group 3 bits into one
    vector<shared_ptr<LWECiphertextImpl>> and_red_results;

    for (int i = 0; i < 4; i++) {
      auto tmp = cc.EvalBinGate(AND, xnor_red_results[3 * i],
                                xnor_red_results[3 * i + 1]);
      and_red_results.push_back(
          cc.EvalBinGate(AND, tmp, xnor_red_results[3 * i + 2]));
    }

    vector<shared_ptr<LWECiphertextImpl>> round_1_result =
        adder_round_1(cc, and_red_results);

    // the result is the octal number: (red_result_ct_2 || red_result_ct_1 ||
    // red_result_ct_0)
    LWEPlaintext red_result_pt_0;
    LWEPlaintext red_result_pt_1;
    LWEPlaintext red_result_pt_2;

    cc.Decrypt(sk, round_1_result[0], &red_result_pt_0);
    cc.Decrypt(sk, round_1_result[1], &red_result_pt_1);
    cc.Decrypt(sk, round_1_result[2], &red_result_pt_2);
    //---------------------------------------------------------------------------

    // whites
    vector<shared_ptr<LWECiphertextImpl>> xnor_white_results;
    for (int j = 1; j < 4; j++) {
      for (int i = 0; i < 12; i++) {
        // the endianese of the next vectors can be ignored as position won't
        // matter at the end
        xnor_white_results.push_back(
            cc.EvalBinGate(XNOR, secret_code[(i + 3 * j) % 12], challenger[i]));
      }
    }

    // group 3 bits into one
    vector<shared_ptr<LWECiphertextImpl>> and_white_results;
    for (int i = 0; i < (12);
         i++) {  // 4 groups of 3 bits, for 3 offsets: 3*4=12
      auto tmp = cc.EvalBinGate(AND, xnor_white_results[(3 * i)],
                                xnor_white_results[(3 * i + 1)]);
      and_white_results.push_back(
          cc.EvalBinGate(AND, tmp, xnor_white_results[3 * i + 2]));
    }

    // round 1 out of 3, aka the addition of bits 0 to 3
    auto intermediary_white_result = adder_round_1(
        cc, {and_white_results.begin(), and_white_results.begin() + 4});

    // round 2 and 3 out of 3, aka the addition of bits 4 to 11

    for (int i = 4; i < 12; i++) {
      intermediary_white_result = adder_round_2_to_4(
          cc, intermediary_white_result[0], intermediary_white_result[1],
          intermediary_white_result[2], and_white_results[i]);
    }

    // that is it

    // the result is the octal number: (white_result_ct_2 || white_result_ct_1
    // || white_result_ct_0)
    LWEPlaintext white_result_pt_0;
    LWEPlaintext white_result_pt_1;
    LWEPlaintext white_result_pt_2;

    cc.Decrypt(sk, intermediary_white_result[0], &white_result_pt_0);
    cc.Decrypt(sk, intermediary_white_result[1], &white_result_pt_1);
    cc.Decrypt(sk, intermediary_white_result[2], &white_result_pt_2);

    //---------------------------------------------------------------------------

    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed_time_ms =
        std::chrono::duration<double, std::milli>(t_end - t_start).count();

    cout << "\tThe mastermind is done!" << endl;
    cout << "\tIt took them: " << elapsed_time_ms << " miliseconds" << endl;

    cout << "You got "
         << red_result_pt_2 * 4 + red_result_pt_1 * 2 + red_result_pt_0
         << " correct color(s) in the exact spot" << endl;
    cout << "You got "
         << white_result_pt_2 * 4 + white_result_pt_1 * 2 + white_result_pt_0
         << " color(s) correctly but not in the exact spot" << endl;

    if (red_result_pt_2 == 1) {
      game_is_won = true;
      cout << "A winner is you!" << endl;
    }

    attempts_made++;
  }

  return 0;
}

