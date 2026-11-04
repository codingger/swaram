"""Calculator Module."""

from typing import Union

Number = Union[int, float]


class Calculator:
    """A robust, type-annotated calculator supporting basic arithmetic operations."""

    @staticmethod
    def add(a: Number, b: Number) -> Number:
        """Return the sum of a and b."""
        Calculator._validate_number(a, b)
        return a + b

    @staticmethod
    def subtract(a: Number, b: Number) -> Number:
        """Return the difference of a and b (a - b)."""
        Calculator._validate_number(a, b)
        return a - b

    @staticmethod
    def multiply(a: Number, b: Number) -> Number:
        """Return the product of a and b."""
        Calculator._validate_number(a, b)
        return a * b

    @staticmethod
    def divide(a: Number, b: Number) -> float:
        """Return the quotient of a and b (a / b)."""
        Calculator._validate_number(a, b)
        if b == 0:
            raise ZeroDivisionError("Division by zero is not allowed.")
        return float(a / b)

    @staticmethod
    def _validate_number(*args: Number) -> None:
        """Internal helper to validate input types."""
        for arg in args:
            if not isinstance(arg, (int, float)) or isinstance(arg, bool):
                raise TypeError(f"Invalid input type '{type(arg).__name__}'. Expected int or float.")
