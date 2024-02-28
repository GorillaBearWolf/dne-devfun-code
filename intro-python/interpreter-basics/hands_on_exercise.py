"""Python Interpreter and Basics Exercise.

Copyright (c) 2018-2021 Cisco and/or its affiliates.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import math
import random


# TODO: Write a print statement that displays both the type and value of `pi`
pi = math.pi
print(f"{pi} {type(pi)}")


# TODO: Write a conditional to print out if `i` is less than or greater than 50
i = random.randint(0, 100)
if i == 50:
    print(f"{i} is equal to 50")
if i < 50:
    print(f"{i} is less than 50")
if i > 50:
    print(f"{i} is greater than 50")



# TODO: Write a conditional that prints the color of the selected sportsball
picked_sportsball = random.choice(['tennis', 'basketball', 'golf'])
if picked_sportsball == 'tennis':
    print("A tennis ball is green.")
if picked_sportsball == 'basketball':
    print("A basketball is orange.")
if picked_sportsball == 'golf':
    print("A golf ball is white.")


# TODO: Write a function that multiplies two numbers and returns the result
# Define the function here.
def multiply(a, b):
    return a * b

# TODO: Now call the function a few times to calculate the following answers

print("12 x 96 =", multiply(12, 96))

print("48 x 17 =", multiply(48, 17))

print("196523 x 87323 =",multiply(196523, 87323))
