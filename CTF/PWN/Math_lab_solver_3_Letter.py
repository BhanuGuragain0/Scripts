from pwn import *

r = remote("172.100.100.23", 1603)

# Initial lines to skip
print(r.recvline().decode().strip())  # "Free Flag: Easy Math"
print(r.recvline().decode().strip())  # "You have 5 seconds to answer each question"
print(r.recvline().decode().strip())  # "You have to solve arount 77-111 questions"
print(r.recvline().decode().strip())  # "Good luck"

while True:
    try:
        # Receive the question
        question = r.recvline().decode().strip()
        print(f"Received: {question}")

        # Check if the question follows the pattern
        if "Solve" in question and ":" in question:
            # Extract the arithmetic expression
            expression = question.split("Solve")[1].split(":")[0].strip()
            print(f"Solving: {expression}")

            # Evaluate the expression
            answer = eval(expression)
            print(f"Answer: {answer}")

            # Send the answer
            r.sendline(str(answer).encode())
        else:
            # Skip unexpected lines
            print(f"Skipping: {question}")
    except EOFError:
        print("Connection closed by server.")
        break
    except Exception as e:
        print(f"Error: {e}")
        break
