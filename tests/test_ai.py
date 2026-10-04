from processor import run_ai_analysis

test_patch = '''
password = "SuperSecretPassword123"

user_input = input("Enter code: ")
eval(user_input)
'''

result = run_ai_analysis(
    test_patch,
    "security_test.py"
)

print("\n===== AI RESULT =====\n")
print(result)