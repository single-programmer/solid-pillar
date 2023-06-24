#! /usr/bin/env python3

import random

def randomlist():
    return ','.join(str(random.randint(0, 2**8 - 1)) for _ in range(32))

print("#[test]")
print(f"fn test_random_mul_{random.randint(1, 9999)}() {{")
print(f"let lhs = Scalar::from_bytes(&[{randomlist()}]);")
print(f"let rhs = Scalar::from_bytes(&[{randomlist()}]);")
print(f"let rust_result = (&lhs * &rhs).write_polynomial().unwrap();")
print("""assert_eq!(run_python(rust_result), run_python(format!("({}) * ({})", lhs.write_polynomial().unwrap(), rhs.write_polynomial().unwrap())));""")
print("}")
