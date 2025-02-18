from pwn import *
import sympy as sp  # For solving equations with variables

def connect():
    """Establish a connection to the remote CTF server."""
    return remote("172.100.100.3", 4444)  # Change IP/Port as needed

def solve_math_challenge(r):
    """Receive and solve complex math challenges dynamically."""
    try:
        # Skip initial messages if any
        for _ in range(4):  
            msg = r.recvline().decode().strip()
            print(f"[INFO] {msg}")  # Debugging purposes

        while True:
            question = r.recvline().decode().strip()
            print(f"[CHALLENGE] {question}")

            # Handle problem formats dynamically
            if "Solve" in question and ":" in question:
                expression = question.split("Solve")[1].split(":")[0].strip()
                print(f"[SOLVING] {expression}")
                answer = eval_expression(expression)
            elif "=" in question:  # Handling equations (e.g., x + 5 = 10)
                answer = solve_equation(question)
            else:
                print(f"[INFO] Skipping: {question}")
                continue

            print(f"[ANSWER] {answer}")
            r.sendlineafter("Your answer:", str(answer).encode())

    except EOFError:
        print("[ERROR] Connection closed by server.")
    except Exception as e:
        print(f"[ERROR] {e}")

def eval_expression(expression):
    """Evaluate a general math expression with support for complex operations."""
    try:
        # Evaluate using Python's eval (which can handle most mathematical operations)
        return eval(expression)  # This can handle operations like +, -, *, /, **, %, etc.
    except Exception as e:
        print(f"[ERROR] Failed to evaluate: {e}")
        return "ERROR"

def solve_equation(equation):
    """Solve equations with a single variable."""
    try:
        # Replace any common "Solve" keyword and whitespace issues
        equation = equation.replace("Solve", "").replace("=", " - ").strip()
        
        # Extract the variable (assuming a single variable exists in the equation)
        variable = sp.symbols('x')

        # Parse and solve the equation using SymPy
        expr = sp.sympify(equation)
        solution = sp.solve(expr, variable)
        return solution[0]  # Assuming a single solution
    except Exception as e:
        print(f"[ERROR] Failed to solve equation: {e}")
        return "ERROR"

if __name__ == "__main__":
    r = connect()
    solve_math_challenge(r)
    print("[SUCCESS] All challenges completed!")
