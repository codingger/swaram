"""Unit tests for Calculator Module."""

import unittest
from calculator import Calculator


class TestCalculator(unittest.TestCase):
    """Unit test suite for Calculator class."""

    def test_add(self) -> None:
        self.assertEqual(Calculator.add(5, 3), 8)
        self.assertEqual(Calculator.add(-1, 1), 0)
        self.assertEqual(Calculator.add(-5, -5), -10)
        self.assertAlmostEqual(Calculator.add(2.5, 3.1), 5.6)

    def test_subtract(self) -> None:
        self.assertEqual(Calculator.subtract(10, 4), 6)
        self.assertEqual(Calculator.subtract(0, 5), -5)
        self.assertAlmostEqual(Calculator.subtract(5.5, 2.3), 3.2)

    def test_multiply(self) -> None:
        self.assertEqual(Calculator.multiply(3, 4), 12)
        self.assertEqual(Calculator.multiply(-2, 3), -6)
        self.assertEqual(Calculator.multiply(0, 100), 0)
        self.assertAlmostEqual(Calculator.multiply(2.5, 2.0), 5.0)

    def test_divide(self) -> None:
        self.assertEqual(Calculator.divide(10, 2), 5.0)
        self.assertEqual(Calculator.divide(-6, 3), -2.0)
        self.assertAlmostEqual(Calculator.divide(7, 2), 3.5)

    def test_divide_by_zero(self) -> None:
        with self.assertRaises(ZeroDivisionError):
            Calculator.divide(10, 0)

    def test_invalid_types(self) -> None:
        with self.assertRaises(TypeError):
            Calculator.add("5", 3)  # type: ignore
        with self.assertRaises(TypeError):
            Calculator.subtract(10, None)  # type: ignore


if __name__ == "__main__":
    unittest.main()
