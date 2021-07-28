def mastermind_process(my_array):
    result = 0
    color_verification = 1
    for j in range(4): # 0-1-2-3
        for i in range(12):
            # this is a not xor
            tmp = (my_array[i]) - (my_array[i + 12 + 3*j])
            tmp = tmp * tmp
            tmp = tmp - 1
            color_verification *= tmp * tmp
            if (i % 3 == 2):
                result += color_verification
                color_verification = 1
        if j==0:
            result*=8

    return result

print('hello')
array=[1,0,1,1,0,0,1,1,0,0,1,0,1,0,1,1,0,0,1,1,0,0,0,1,1,0,1,1,0,0,1,1,0,0,0,1,1,0,1,1,0,0,1,1,0,0,0,1]
result=mastermind_process(array)
print(result)
reds = result // 8
whites = result % 8
print('{} has {} color(s) at exact position and {} correct color(s) at inexact position'
          .format('5462', reds, whites))
