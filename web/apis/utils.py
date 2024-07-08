def calculate_percentage(percentage, number):
    """
    Calculate the percentage of a given number with input validation.
    
    :param percentage: The percentage to calculate (e.g., 0.7 for 0.7%)
    :param number: The number to calculate the percentage of
    :return: The result of the percentage calculation
    """
    # Validate that percentage is a number
    if not isinstance(percentage, (int, float)):
        raise ValueError("Percentage must be a number.")
    
    # Validate that number is a number
    if not isinstance(number, (int, float)):
        raise ValueError("Number must be a number.")
    
    # Validate that percentage is between 0 and 100
    if percentage < 0 or percentage > 100:
        raise ValueError("Percentage must be between 0 and 100.")
    
    # Calculate the percentage
    return (percentage / 100) * number

""" # Example usage:
try:
    result = calculate_percentage(0.7, 10)
    print(result)  # Output: 0.07
except ValueError as e:
    print(e)
 """
 
import math
def round_up(amount):
    # Scale the number by 100, use ceil to round up, then scale back down
    return math.ceil(amount * 100) / 100

# Example usage
result = round_up(0.38499999999999995)
print(result)  # Output: 0.39


# Assuming 'user_plan_percentages' dictionary maps user plans to their corresponding percentages
user_plan_percentages = {
    'normal': 0.7,
    'vip': 0.9,
    'vvip': 1.5,
    'vvvip': 2.0
}
