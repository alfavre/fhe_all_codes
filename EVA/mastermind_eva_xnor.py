from eva import *
from eva.ckks import *
from eva.seal import *
from eva.metric import valuation_mse
import time

number_bits = 12

exact_postion_counter = EvaProgram('Red_Control_Peg', vec_size=8192)
with exact_postion_counter:
    player_0 = Input('encoded_vec')
    result = 0
    color_verification = 1
    for i in range(number_bits):
        # this is a not xor
        tmp = (player_0 << i) - (player_0 << i + number_bits)
        tmp = tmp * tmp
        tmp = tmp - 1
        color_verification *= tmp * tmp  # this might be too much for ckks imprecision
        if (i % 3 == 2):
            result += color_verification
            color_verification = 1

    Output('result', result)

exact_postion_counter.set_output_ranges(30)
exact_postion_counter.set_input_scales(30)

inexact_postion_counter = EvaProgram('White_Control_Peg_0', vec_size=8192)
with inexact_postion_counter:
    player_0 = Input('encoded_vec')
    result = 0
    color_verification = 1
    for j in range(1,4): # 1-2-3
        for i in range(number_bits):
            # this is a not xor
            tmp = (player_0 << i) - (player_0 << i + number_bits + 3 * j)
            tmp = tmp * tmp
            tmp = tmp - 1
            color_verification *= tmp * tmp  # this might be too much for ckks imprecision
            if (i % 3 == 2):
                result += color_verification
                color_verification = 1
    Output('result', result)

inexact_postion_counter.set_output_ranges(30)
inexact_postion_counter.set_input_scales(30)



def make_inputs(player_propostion, code, size):
    fact = 4
    number = size - (len(player_propostion) + len(code) * fact)
    arr_num = player_propostion + code * fact + [0] * number  # proposition and solution and solution and solution and ...
    return arr_num


def result_analysis(player_proposition, result):
    reds = result[0]
    whites = result[1]
    print('{} has {} color(s) at exact position and {} correct color(s) at inexact position'
          .format(player_proposition, reds, whites))
    return reds == 4


if __name__ == "__main__":

    code = [5, 4, 6, 1]
    code_b = [1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1]  # 101 100 110 001
    MAX_ATTEMPTS = 6  # hard mode
    game_is_won = False
    attempts_made = 0
    print("WARNING, there is no input control, so please be nice")
    count = 0
    total_time = 0

    while attempts_made < MAX_ATTEMPTS and not game_is_won:

        array_b = [bin(int(8 + int(a)))[3:] for a in input("Please enter a 4 digits [0-7] code: ")]
        string_b = ''
        for str_bin in array_b:
            string_b += str_bin
        player_propostion_b = [0 if a == '0' else 1 for a in string_b]
        big_result = []

        for prog in [exact_postion_counter, inexact_postion_counter]:
            compiler = CKKSCompiler()
            compiled, params, signature = compiler.compile(prog)


            name="mstrmnd_xnor_" + str(count) + ".dot"
            f = open(name, "w")
            count+=1
            f.write(compiled.to_DOT())
            f.close()


            public_ctx, secret_ctx = generate_keys(params)
            inputs_arr = make_inputs(player_propostion_b, code_b, compiled.vec_size)

            inputs = {'encoded_vec': inputs_arr}  # is it possible to compile multiple arrays and the fuse them?

            t0 = time.time()
            encInputs = public_ctx.encrypt(inputs, signature)
            encOutputs = public_ctx.execute(compiled, encInputs)
            outputs = secret_ctx.decrypt(encOutputs, signature)
            tmp_time = time.time() - t0
            total_time += tmp_time
            print(tmp_time, "seconds wall time for program "+str(count))

            my_result = []
            for result in outputs["result"][:1]:
                my_result.append(round(result))
            big_result += my_result

            reference = evaluate(compiled, inputs)
            # print('MSE', valuation_mse(outputs, reference))

        print(total_time, "total seconds wall time")
        game_is_won = result_analysis(player_propostion_b, big_result)
        attempts_made += 1
        if game_is_won:
            print("A winner is you!")
    print("Game Over")
