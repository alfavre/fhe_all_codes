from eva import *
from eva.ckks import *
from eva.seal import *
from eva.metric import valuation_mse
import time

# x cant be 0
# take an expr and a int/float
def divide(n, x):
    value = 1 / x
    return n * value


exact_postion_counter = EvaProgram('Red_Control_Peg', vec_size=4096)
with exact_postion_counter:
    challenger = Input('encoded_vec')
    secret = challenger << 4
    Output('result', challenger - secret)

exact_postion_counter.set_output_ranges(30)
exact_postion_counter.set_input_scales(30)

inexact_postion_counter_0 = EvaProgram('White_Control_Peg_0', vec_size=4096)
with inexact_postion_counter_0:
    challenger = Input('encoded_vec')
    secret = challenger << 5
    Output('result', challenger - secret)

inexact_postion_counter_0.set_output_ranges(30)
inexact_postion_counter_0.set_input_scales(30)

inexact_postion_counter_1 = EvaProgram('White_Control_Peg_1', vec_size=4096)
with inexact_postion_counter_1:
    challenger = Input('encoded_vec')
    secret = challenger << 6
    Output('result', challenger - secret)

inexact_postion_counter_1.set_output_ranges(30)
inexact_postion_counter_1.set_input_scales(30)

inexact_postion_counter_2 = EvaProgram('White_Control_Peg_2', vec_size=4096)
with inexact_postion_counter_2:
    challenger = Input('encoded_vec')
    secret = challenger << 7
    Output('result', challenger - secret)

inexact_postion_counter_2.set_output_ranges(30)
inexact_postion_counter_2.set_input_scales(30)


def make_inputs(propostion, code, size):
    number = (size // 4) - 1
    arr_num = propostion + code * number  # proposition and solution and solution and solution and ...
    return arr_num


def result_analysis(proposition, result):
    reds = result[:4].count(0)
    whites = result[4:].count(0)
    print('{} has {} color(s) at exact position and {} correct color(s) at inexact position'
          .format(proposition, reds, whites))
    return reds==4


if __name__ == "__main__":

    code = [5, 4, 6, 1]
    MAX_ATTEMPTS = 6 # hard mode
    game_is_won = False
    attempts_made=0
    print("WARNING, there is no input control, so please be nice")
    while attempts_made < MAX_ATTEMPTS and not game_is_won:
        propostion = [
            int(input("Please enter your first color [0-7]: ")),
            int(input("Please enter your second color [0-7]: ")),
            int(input("Please enter your third color [0-7]: ")),
            int(input("Please enter your fourth color [0-7]: ")),
        ]

        # offset=0

        big_result = []

        for prog in [exact_postion_counter, inexact_postion_counter_0, inexact_postion_counter_1,
                     inexact_postion_counter_2]:
            compiler = CKKSCompiler()
            compiled, params, signature = compiler.compile(prog)
            # print(compiled.to_DOT())
            public_ctx, secret_ctx = generate_keys(params)
            inputs_arr = make_inputs(propostion, code, compiled.vec_size)

            inputs = {'encoded_vec': inputs_arr}  # is it possible to compile multiple arrays and the fuse them?

            t0 = time.time()
            encInputs = public_ctx.encrypt(inputs, signature)
            encOutputs = public_ctx.execute(compiled, encInputs)
            outputs = secret_ctx.decrypt(encOutputs, signature)
            print(time.time() - t0, "seconds wall time")

            my_result = []
            for result in outputs["result"][:4]:
                my_result.append(round(result))
            big_result += my_result
            print(outputs["result"][:4])
            reference = evaluate(compiled, inputs)
            # print('MSE', valuation_mse(outputs, reference))

        game_is_won=result_analysis(propostion, big_result)
        attempts_made+=1
        if game_is_won:
            print("A winner is you!")
    print("Game Over")
