import os

user_input = input("Enter command: ")
os.system(user_input)   # ❌ Command Injection vulnerability
#new here 