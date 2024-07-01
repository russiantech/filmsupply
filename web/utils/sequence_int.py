class SequentialGenerator:
    def __init__(self, start=1):
        self.counter = start

    def next(self):
        current_value = self.counter
        self.counter += 1
        return current_value

# Create an instance of the SequentialGenerator
generator = SequentialGenerator(start=10)


# Generate sequential numbers
""" print(generator.next())  # Output: 1
print(generator.next())  # Output: 2
print(generator.next())  # Output: 3 """
