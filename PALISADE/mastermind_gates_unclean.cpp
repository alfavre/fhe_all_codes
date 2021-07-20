//
// Created by alban on 10.06.21.
//

#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;

int main() {
  // Sample Program: Step 1: Set CryptoContext

  auto cc = BinFHEContext();

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

  // Sample Program: Step 3: Encryption

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
  const int MAX_ATTEMPTS = 6;
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
    vector<shared_ptr<LWECiphertextImpl>> big_results;

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

    shared_ptr<LWECiphertextImpl> red_result_ct_0;
    shared_ptr<LWECiphertextImpl> red_result_ct_1;
    shared_ptr<LWECiphertextImpl> red_result_ct_2;
    shared_ptr<LWECiphertextImpl> carry_red_1;
    shared_ptr<LWECiphertextImpl> carry_red_2;

    // full adder simplified
    // for addition of only 1 bit at the time, never multi bit numbers

    // add first bit
    // we know that the second and third result bit can't be affected as max is
    // 1
    red_result_ct_0 =
        and_red_results[0];  // first add, 0 + first bit = first bit obv

    // add second bit
    // red_result_ct_0 + second bit = ???
    // we know that the third result bit can't be affected as max is 2 (10)
    carry_red_1 = cc.EvalBinGate(AND, red_result_ct_0, and_red_results[1]);
    red_result_ct_0 = cc.EvalBinGate(XOR, red_result_ct_0, and_red_results[1]);
    red_result_ct_1 = carry_red_1;

    // add third bit
    // (red_result_ct_0 || red_result_ct_1) + third bit = ???
    // we know that the third result bit can't be affected as max is 3 (11)
    carry_red_1 = cc.EvalBinGate(AND, red_result_ct_0, and_red_results[2]);
    red_result_ct_0 = cc.EvalBinGate(XOR, red_result_ct_0, and_red_results[2]);
    red_result_ct_1 = cc.EvalBinGate(
        OR, carry_red_1,
        red_result_ct_1);  // it is impossible that those 2 are both 1

    // add fourth bit
    // (red_result_ct_0 || red_result_ct_1) + forth bit = ???
    // this is the most complex as it can affect 3 result bits, max is 4 (100)
    carry_red_1 = cc.EvalBinGate(AND, red_result_ct_0, and_red_results[3]);
    red_result_ct_0 = cc.EvalBinGate(XOR, red_result_ct_0, and_red_results[3]);
    carry_red_2 = cc.EvalBinGate(AND, red_result_ct_1, carry_red_1);
    red_result_ct_1 = cc.EvalBinGate(XOR, carry_red_1,
                                     red_result_ct_1);  // they can be both 1
    red_result_ct_2 =
        carry_red_2;  // we know that it is this simple as the max is 100

    // the result is the octal number: (red_result_ct_2 || red_result_ct_1 ||
    // red_result_ct_0)
    LWEPlaintext red_result_pt_0;
    LWEPlaintext red_result_pt_1;
    LWEPlaintext red_result_pt_2;

    cc.Decrypt(sk, red_result_ct_0, &red_result_pt_0);
    cc.Decrypt(sk, red_result_ct_1, &red_result_pt_1);
    cc.Decrypt(sk, red_result_ct_2, &red_result_pt_2);

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

    shared_ptr<LWECiphertextImpl> white_result_ct_0;
    shared_ptr<LWECiphertextImpl> white_result_ct_1;
    shared_ptr<LWECiphertextImpl> white_result_ct_2;
    shared_ptr<LWECiphertextImpl> carry_white_1;
    shared_ptr<LWECiphertextImpl> carry_white_2;

    // full adder simplified
    // for addition of only 1 bit at the time, never multi bit numbers

    // add first bit
    // we know that the second and third result bit can't be affected as max is
    // 1
    white_result_ct_0 =
        and_white_results[0];  // first add, 0 + first bit = first bit obv

    // add second bit
    // white_result_ct_0 + second bit = ???
    // we know that the third result bit can't be affected as max is 2 (10)
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[1]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[1]);
    white_result_ct_1 = carry_white_1;

    // add third bit
    // (white_result_ct_0 || white_result_ct_1) + third bit = ???
    // we know that the third result bit can't be affected as max is 3 (11)
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[2]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[2]);
    white_result_ct_1 = cc.EvalBinGate(
        OR, carry_white_1,
        white_result_ct_1);  // it is impossible that those 2 are both 1

    // add fourth bit
    // (white_result_ct_0 || white_result_ct_1) + forth bit = ???
    // this is the most complex as it can affect 3 result bits, max is 4 (100)
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[3]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[3]);
    carry_white_2 = cc.EvalBinGate(AND, white_result_ct_1, carry_white_1);
    white_result_ct_1 = cc.EvalBinGate(
        XOR, carry_white_1, white_result_ct_1);  // they can be both 1
    white_result_ct_2 =
        carry_white_2;  // we know that it is this simple as the max is 100

    // round 2/3 for offset 2,

    // add fifth bit
    // (white_result_ct_0 || white_result_ct_1 || white_result_ct_2) + fifth bit
    // = ??? this is the most complex as it can affect 3 result bits, max is 4
    // (100) even if we might believe we can go to 101 here, we can't, as the
    // non repeated color rule of the mastermind prevents it
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[4]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[4]);
    carry_white_2 = cc.EvalBinGate(AND, white_result_ct_1, carry_white_1);
    white_result_ct_1 = cc.EvalBinGate(
        XOR, carry_white_1, white_result_ct_1);  // they can be both 1
    white_result_ct_2 = cc.EvalBinGate(
        OR, carry_white_2,
        white_result_ct_2);  // it is impossible that those 2 are both 1, but if
                             // one is already 1, better not overide it
                             // we know that it is this simple as the max is 100

    // add sixth bit
    // (white_result_ct_0 || white_result_ct_1 || white_result_ct_2) + sixth bit
    // = ??? this is the most complex as it can affect 3 result bits, max is 4
    // (100) even if we might believe we can go to 101 here, we can't, as the
    // non repeated color rule of the mastermind prevents it
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[5]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[5]);
    carry_white_2 = cc.EvalBinGate(AND, white_result_ct_1, carry_white_1);
    white_result_ct_1 = cc.EvalBinGate(
        XOR, carry_white_1, white_result_ct_1);  // they can be both 1
    white_result_ct_2 = cc.EvalBinGate(
        OR, carry_white_2,
        white_result_ct_2);  // it is impossible that those 2 are both 1, but if
                             // one is already 1, better not override it
    // we know that it is this simple as the max is 100

    // add seventh bit
    // (white_result_ct_0 || white_result_ct_1 || white_result_ct_2) + seventh
    // bit = ??? this is the most complex as it can affect 3 result bits, max is
    // 4 (100) even if we might believe we can go to 101 here, we can't, as the
    // non repeated color rule of the mastermind prevents it
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[6]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[6]);
    carry_white_2 = cc.EvalBinGate(AND, white_result_ct_1, carry_white_1);
    white_result_ct_1 = cc.EvalBinGate(
        XOR, carry_white_1, white_result_ct_1);  // they can be both 1
    white_result_ct_2 = cc.EvalBinGate(
        OR, carry_white_2,
        white_result_ct_2);  // it is impossible that those 2 are both 1, but if
                             // one is already 1, better not override it
    // we know that it is this simple as the max is 100

    // add eighth bit
    // (white_result_ct_0 || white_result_ct_1 || white_result_ct_2) + eighth
    // bit = ??? this is the most complex as it can affect 3 result bits, max is
    // 4 (100) even if we might believe we can go to 101 here, we can't, as the
    // non repeated color rule of the mastermind prevents it
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[7]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[7]);
    carry_white_2 = cc.EvalBinGate(AND, white_result_ct_1, carry_white_1);
    white_result_ct_1 = cc.EvalBinGate(
        XOR, carry_white_1, white_result_ct_1);  // they can be both 1
    white_result_ct_2 = cc.EvalBinGate(
        OR, carry_white_2,
        white_result_ct_2);  // it is impossible that those 2 are both 1, but if
                             // one is already 1, better not override it
    // we know that it is this simple as the max is 100

    // round 3/3 for offset 3,

    // add ninth bit
    // (white_result_ct_0 || white_result_ct_1 || white_result_ct_2) + ninth bit
    // = ??? this is the most complex as it can affect 3 result bits, max is 4
    // (100) even if we might believe we can go to 101 here, we can't, as the
    // non repeated color rule of the mastermind prevents it
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[8]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[8]);
    carry_white_2 = cc.EvalBinGate(AND, white_result_ct_1, carry_white_1);
    white_result_ct_1 = cc.EvalBinGate(
        XOR, carry_white_1, white_result_ct_1);  // they can be both 1
    white_result_ct_2 = cc.EvalBinGate(
        OR, carry_white_2,
        white_result_ct_2);  // it is impossible that those 2 are both 1, but if
                             // one is already 1, better not override it
    // we know that it is this simple as the max is 100

    // add tenth bit
    // (white_result_ct_0 || white_result_ct_1 || white_result_ct_2) + tenth bit
    // = ??? this is the most complex as it can affect 3 result bits, max is 4
    // (100) even if we might believe we can go to 101 here, we can't, as the
    // non repeated color rule of the mastermind prevents it
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[9]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[9]);
    carry_white_2 = cc.EvalBinGate(AND, white_result_ct_1, carry_white_1);
    white_result_ct_1 = cc.EvalBinGate(
        XOR, carry_white_1, white_result_ct_1);  // they can be both 1
    white_result_ct_2 = cc.EvalBinGate(
        OR, carry_white_2,
        white_result_ct_2);  // it is impossible that those 2 are both 1, but if
                             // one is already 1, better not override it
    // we know that it is this simple as the max is 100

    // add eleventh bit
    // (white_result_ct_0 || white_result_ct_1 || white_result_ct_2) + eleventh
    // bit = ??? this is the most complex as it can affect 3 result bits, max is
    // 4 (100) even if we might believe we can go to 101 here, we can't, as the
    // non repeated color rule of the mastermind prevents it
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[10]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[10]);
    carry_white_2 = cc.EvalBinGate(AND, white_result_ct_1, carry_white_1);
    white_result_ct_1 = cc.EvalBinGate(
        XOR, carry_white_1, white_result_ct_1);  // they can be both 1
    white_result_ct_2 = cc.EvalBinGate(
        OR, carry_white_2,
        white_result_ct_2);  // it is impossible that those 2 are both 1, but if
                             // one is already 1, better not override it
    // we know that it is this simple as the max is 100

    // add twelfth bit
    // (white_result_ct_0 || white_result_ct_1 || white_result_ct_2) + twelfth
    // bit = ??? this is the most complex as it can affect 3 result bits, max is
    // 4 (100) even if we might believe we can go to 101 here, we can't, as the
    // non repeated color rule of the mastermind prevents it
    carry_white_1 =
        cc.EvalBinGate(AND, white_result_ct_0, and_white_results[11]);
    white_result_ct_0 =
        cc.EvalBinGate(XOR, white_result_ct_0, and_white_results[11]);
    carry_white_2 = cc.EvalBinGate(AND, white_result_ct_1, carry_white_1);
    white_result_ct_1 = cc.EvalBinGate(
        XOR, carry_white_1, white_result_ct_1);  // they can be both 1
    white_result_ct_2 = cc.EvalBinGate(
        OR, carry_white_2,
        white_result_ct_2);  // it is impossible that those 2 are both 1, but if
                             // one is already 1, better not override it
    // we know that it is this simple as the max is 100

    // that is it

    // the result is the octal number: (white_result_ct_2 || white_result_ct_1
    // || white_result_ct_0)
    LWEPlaintext white_result_pt_0;
    LWEPlaintext white_result_pt_1;
    LWEPlaintext white_result_pt_2;

    cc.Decrypt(sk, white_result_ct_0, &white_result_pt_0);
    cc.Decrypt(sk, white_result_ct_1, &white_result_pt_1);
    cc.Decrypt(sk, white_result_ct_2, &white_result_pt_2);

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

