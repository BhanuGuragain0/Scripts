from pwn import *

def connect():
    """Establish a connection to the remote CTF server."""
    return remote("172.100.100.3", 4444)  # Change IP/Port as needed

def solve_math_challenge(r):
    """Receive and solve math challenges dynamically."""
    try:
        # Skip initial messages if any
        for _ in range(4):  
            msg = r.recvline().decode().strip()
            print(f"[INFO] {msg}")  # Debugging purposes

        while True:
            question = r.recvline().decode().strip()
            print(f"[CHALLENGE] {question}")

            if "Solve" in question and ":" in question:
                expression = question.split("Solve")[1].split(":")[0].strip()
            else:
                expression = question.replace("What is ", "").replace("?", "").strip()

            print(f"[SOLVING] {expression}")
            answer = eval(expression)  # Safe for controlled CTF environments
            print(f"[ANSWER] {answer}")

            r.sendlineafter("Your answer:", str(answer).encode())

    except EOFError:
        print("[ERROR] Connection closed by server.")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    r = connect()
    solve_math_challenge(r)
    print("[SUCCESS] All challenges completed!")
