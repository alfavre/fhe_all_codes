from eva import *
from eva.ckks import *
from eva.seal import *
from eva.metric import valuation_mse
import time

number_bits = 12


# x cant be 0
# take an expr and a int/float
def divide(n, x):
    value = 1 / x
    return n * value


mastermind_process = EvaProgram('Control_Peg', vec_size=8192)
with mastermind_process:
    challenger_0 = Input('encoded_vec')
    result = 0
    color_verification = 1
    for j in range(4): # 0-1-2-3
        for i in range(number_bits):
            # this is a not xor
            tmp = (challenger_0 << i) - (challenger_0 << i + number_bits + 3*j)
            tmp = tmp * tmp
            tmp = tmp - 1
            color_verification *= tmp * tmp  # this might be too much for ckks imprecision
            if (i % 3 == 2):
                result += color_verification
                color_verification = 1
        if j==0:
            result*=8 # this absolutely destroys precision to an irrecoverable state

    Output('result', result)

mastermind_process.set_output_ranges(30)
mastermind_process.set_input_scales(30)



def make_inputs(propostion, code, size):
    fact = 4
    number = size - (len(propostion) + len(code) * fact)
    arr_num = propostion + code * fact + [0] * number  # proposition and solution and solution and solution and ...
    # print(arr_num)
    return arr_num


def result_analysis(proposition, result):
    print(result)
    reds = result // 8
    whites = result % 8
    print('{} has {} color(s) at exact position and {} correct color(s) at inexact position'
          .format(proposition, reds, whites))
    return reds == 4


if __name__ == "__main__":

    code = [5, 4, 6, 1]
    code_b = [1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1]  # 101 100 110 001
    MAX_ATTEMPTS = 6  # hard mode
    game_is_won = False
    attempts_made = 0
    print("WARNING, there is no input control, so please be nice")
    while attempts_made < MAX_ATTEMPTS and not game_is_won:

        array_b = [bin(int(8 + int(a)))[3:] for a in input("Please enter a 4 digits [0-7] code: ")]
        string_b = ''
        for str_bin in array_b:
            string_b += str_bin
        propostion_b = [0 if a == '0' else 1 for a in string_b]

        compiler = CKKSCompiler()
        compiled, params, signature = compiler.compile(mastermind_process)
        # print(compiled.to_DOT())
        public_ctx, secret_ctx = generate_keys(params)
        inputs_arr = make_inputs(propostion_b, code_b, compiled.vec_size)

        inputs = {'encoded_vec': inputs_arr}  # is it possible to compile multiple arrays and the fuse them?

        t0 = time.time()
        encInputs = public_ctx.encrypt(inputs, signature)
        encOutputs = public_ctx.execute(compiled, encInputs)
        outputs = secret_ctx.decrypt(encOutputs, signature)
        print(time.time() - t0, "seconds wall time")


        print(outputs["result"][1])

        my_result=round(outputs["result"][1])


        reference = evaluate(compiled, inputs)
        # print('MSE', valuation_mse(outputs, reference))
        game_is_won = result_analysis(propostion_b, my_result)
        attempts_made += 1
        if game_is_won:
            print("A winner is you!")
    print("Game Over")
