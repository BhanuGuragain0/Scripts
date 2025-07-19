#!/usr/bin/env python3
"""
Advanced CTF Math Challenge Solver
Production-ready script for automated math problem solving in CTF challenges
Supports: Arithmetic, Algebraic equations, Complex expressions, Modular arithmetic
"""

from pwn import *
import sympy as sp
import re
import time
import sys
from typing import Union, Optional

class CTFMathSolver:
    def __init__(self, host: str, port: int, timeout: int = 10):
        """Initialize the CTF Math Solver with connection parameters."""
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connection = None
        self.solved_count = 0
        
    def connect(self, retries: int = 3) -> bool:
        """Establish connection with retry mechanism."""
        for attempt in range(retries):
            try:
                log.info(f"Connecting to {self.host}:{self.port} (Attempt {attempt + 1})")
                self.connection = remote(self.host, self.port, timeout=self.timeout)
                log.success("Connection established successfully")
                return True
            except Exception as e:
                log.warning(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(2)
        return False
    
    def safe_eval(self, expression: str) -> Union[int, float]:
        """Safely evaluate mathematical expressions with security considerations."""
        # Remove potential dangerous functions and limit to safe operations
        safe_dict = {
            '__builtins__': {},
            'abs': abs, 'round': round, 'pow': pow,
            'min': min, 'max': max, 'sum': sum,
            'int': int, 'float': float,
            'divmod': divmod
        }
        
        # Add mathematical constants and functions
        import math
        safe_dict.update({
            'pi': math.pi, 'e': math.e,
            'sin': math.sin, 'cos': math.cos, 'tan': math.tan,
            'sqrt': math.sqrt, 'log': math.log, 'exp': math.exp,
            'floor': math.floor, 'ceil': math.ceil
        })
        
        try:
            # Clean the expression
            expression = self.clean_expression(expression)
            result = eval(expression, safe_dict, {})
            return int(result) if isinstance(result, float) and result.is_integer() else result
        except Exception as e:
            log.error(f"Failed to evaluate '{expression}': {e}")
            raise
    
    def clean_expression(self, expression: str) -> str:
        """Clean and normalize mathematical expressions."""
        # Remove common prefixes and suffixes
        cleaners = [
            r'^(What is |Solve |Calculate |Find )',
            r'(\?|:|\.)$',
            r'\s+'
        ]
        
        for pattern in cleaners:
            expression = re.sub(pattern, ' ' if pattern == r'\s+' else '', expression, flags=re.IGNORECASE)
        
        expression = expression.strip()
        
        # Handle special cases
        expression = expression.replace('^', '**')  # Convert ^ to **
        expression = expression.replace('mod', '%')   # Convert mod to %
        
        return expression
    
    def solve_equation(self, equation: str) -> Union[int, float]:
        """Solve algebraic equations using SymPy."""
        try:
            # Clean the equation
            equation = self.clean_expression(equation)
            
            # Handle different equation formats
            if '=' in equation:
                left, right = equation.split('=', 1)
                expr = sp.sympify(f"({left}) - ({right})")
            else:
                expr = sp.sympify(equation)
            
            # Find variables in the expression
            variables = list(expr.free_symbols)
            
            if not variables:
                # No variables, just evaluate
                return float(expr)
            elif len(variables) == 1:
                # Single variable equation
                solutions = sp.solve(expr, variables[0])
                if solutions:
                    solution = solutions[0]
                    return int(solution) if solution.is_integer else float(solution)
            
            raise ValueError("Cannot solve equation with multiple variables or no solution")
            
        except Exception as e:
            log.error(f"Failed to solve equation '{equation}': {e}")
            raise
    
    def parse_and_solve(self, question: str) -> Union[int, float]:
        """Parse question and determine solving method."""
        question = question.strip()
        
        # Skip empty or info lines
        if not question or any(skip in question.lower() for skip in 
                              ['good luck', 'you have', 'seconds to answer', 'questions']):
            return None
        
        log.info(f"Processing: {question}")
        
        # Try different solving approaches
        try:
            # Method 1: Direct evaluation for arithmetic
            if not re.search(r'[a-zA-Z]', question) or question.lower().startswith(('what is', 'solve', 'calculate')):
                return self.safe_eval(question)
            
            # Method 2: Equation solving
            elif '=' in question:
                return self.solve_equation(question)
            
            # Method 3: Try as expression anyway
            else:
                return self.safe_eval(question)
                
        except Exception as e:
            log.error(f"All solving methods failed for '{question}': {e}")
            return None
    
    def run_solver(self, max_questions: int = 200):
        """Main solver loop with enhanced error handling."""
        if not self.connect():
            log.error("Failed to establish connection")
            return False
        
        try:
            # Skip initial banner/info lines (adaptive)
            for _ in range(5):
                try:
                    line = self.connection.recvline(timeout=2).decode().strip()
                    log.info(f"Banner: {line}")
                except:
                    break
            
            # Main solving loop
            while self.solved_count < max_questions:
                try:
                    # Receive question with timeout
                    question = self.connection.recvline(timeout=self.timeout).decode().strip()
                    
                    # Parse and solve
                    answer = self.parse_and_solve(question)
                    
                    if answer is not None:
                        log.success(f"Solved #{self.solved_count + 1}: {question} = {answer}")
                        
                        # Send answer with multiple possible prompts
                        try:
                            self.connection.sendlineafter(":", str(answer).encode(), timeout=5)
                        except:
                            try:
                                self.connection.sendlineafter("answer", str(answer).encode(), timeout=5)
                            except:
                                self.connection.sendline(str(answer).encode())
                        
                        self.solved_count += 1
                    else:
                        log.warning(f"Skipped: {question}")
                        
                except EOFError:
                    log.info("Server closed connection - challenge completed!")
                    break
                except Exception as e:
                    log.error(f"Error in solving loop: {e}")
                    break
            
            # Try to get flag/final message
            try:
                final_msg = self.connection.recvall(timeout=3).decode()
                log.success(f"Final message: {final_msg}")
            except:
                pass
                
            return True
            
        finally:
            if self.connection:
                self.connection.close()
    
    def __del__(self):
        """Cleanup connection on object destruction."""
        if self.connection:
            self.connection.close()

def main():
    """Main execution function with command line argument support."""
    if len(sys.argv) != 3:
        print("Usage: python3 solver.py <host> <port>")
        print("Example: python3 solver.py 172.100.100.3 4444")
        return
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    # Initialize and run solver
    solver = CTFMathSolver(host, port, timeout=15)
    
    log.info(f"Starting CTF Math Solver for {host}:{port}")
    log.info("Supported operations: +, -, *, /, %, **, equations with single variables")
    
    success = solver.run_solver(max_questions=300)
    
    if success:
        log.success(f"Challenge completed! Solved {solver.solved_count} questions")
    else:
        log.error("Challenge failed or interrupted")

if __name__ == "__main__":
    # Set pwntools context
    context.log_level = 'info'
    context.timeout = 30
    
    main()
