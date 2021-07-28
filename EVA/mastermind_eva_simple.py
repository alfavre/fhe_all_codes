from eva import *
from eva.ckks import *
from eva.seal import *
from eva.metric import valuation_mse
import time



exact_postion_counter = EvaProgram('Red_Control_Peg', vec_size=1024)
with exact_postion_counter:
    player = Input('encoded_vec')
    secret = player << 4
    Output('result', player - secret)

exact_postion_counter.set_output_ranges(30)
exact_postion_counter.set_input_scales(30)

inexact_postion_counter_0 = EvaProgram('White_Control_Peg_0', vec_size=4096)
with inexact_postion_counter_0:
    player = Input('encoded_vec')
    secret = player << 5
    Output('result', player - secret)

inexact_postion_counter_0.set_output_ranges(30)
inexact_postion_counter_0.set_input_scales(30)

inexact_postion_counter_1 = EvaProgram('White_Control_Peg_1', vec_size=4096)
with inexact_postion_counter_1:
    player = Input('encoded_vec')
    secret = player << 6
    Output('result', player - secret)

inexact_postion_counter_1.set_output_ranges(30)
inexact_postion_counter_1.set_input_scales(30)

inexact_postion_counter_2 = EvaProgram('White_Control_Peg_2', vec_size=4096)
with inexact_postion_counter_2:
    player = Input('encoded_vec')
    secret = player << 7
    Output('result', player - secret)

inexact_postion_counter_2.set_output_ranges(30)
inexact_postion_counter_2.set_input_scales(30)


def make_inputs(player_propostion, code, size):
    number = (size // 4) - 1
    arr_num = player_propostion + code * number  # proposition and solution and solution and solution and ...
    return arr_num


def result_analysis(player_proposition, result):
    reds = result[:4].count(0)
    whites = result[4:].count(0)
    print('{} has {} color(s) at exact position and {} correct color(s) at inexact position'
          .format(player_proposition, reds, whites))
    return reds==4


if __name__ == "__main__":

    code = [5, 4, 6, 1]
    MAX_ATTEMPTS = 6 # hard mode
    game_is_won = False
    attempts_made=0
    print("WARNING, there is no input control, so please be nice")
    while attempts_made < MAX_ATTEMPTS and not game_is_won:
        player_propostion = [
            int(input("Please enter your first color [0-7]: ")),
            int(input("Please enter your second color [0-7]: ")),
            int(input("Please enter your third color [0-7]: ")),
            int(input("Please enter your fourth color [0-7]: ")),
        ]


        big_result = []
        count = 0
        total_time = 0

        for prog in [exact_postion_counter, inexact_postion_counter_0, inexact_postion_counter_1,
                     inexact_postion_counter_2]:
            compiler = CKKSCompiler()
            compiled, params, signature = compiler.compile(prog)


            name="mstrmnd_simple_" + str(count) + ".dot"
            f = open(name, "w")
            count+=1
            f.write(compiled.to_DOT())
            f.close()


            public_ctx, secret_ctx = generate_keys(params)
            inputs_arr = make_inputs(player_propostion, code, compiled.vec_size)

            inputs = {'encoded_vec': inputs_arr}  # is it possible to compile multiple arrays and the fuse them?

            t0 = time.time()
            encInputs = public_ctx.encrypt(inputs, signature)
            encOutputs = public_ctx.execute(compiled, encInputs)
            outputs = secret_ctx.decrypt(encOutputs, signature)
            tmp_time = time.time() - t0
            total_time += tmp_time
            print(tmp_time, "seconds wall time for program "+str(count))

            my_result = []
            for result in outputs["result"][:4]:
                my_result.append(round(result))
            big_result += my_result
            # print(outputs["result"][:4])
            reference = evaluate(compiled, inputs)
            # print('MSE', valuation_mse(outputs, reference))
        print(total_time, "total seconds wall time")
        game_is_won=result_analysis(player_propostion, big_result)
        attempts_made+=1
        if game_is_won:
            print("A winner is you!")
    print("Game Over")
