#!/usr/bin/env python3
import os
import logging
import subprocess
import bcrypt
import json
import re
import tkinter as tk
from tkinter import messagebox, simpledialog

# Define the directory path
directory = '/var/library_management/'
directory2 = '/var/library_management/books/'
books_list = '/var/library_management/books.txt'

# check if the directory exists, and create it if it doesn't
if not os.path.exists(directory):
    os.makedirs(directory)
    os.makedirs(directory2)

# Check if books.txt exists, and create it if it doesn't
if not os.path.exists(books_list):
    # Create the file
    with open(books_list, 'w') as file:
        pass # Just create an empty file and move on

# Configuring logging early in the startup of the script (ensure logging is available before all other operations).
logging.basicConfig(
    filename='/var/library_management/library.log', # Log file path
    level=logging.INFO, # Set the logging level
    format='%(asctime)s - %(levelname)s - %(message)s', # Log format
    datefmt='%Y-%m-%d %H:%M:%S'
)

logging.info("Library Management script started.") # Log script startup.

# Hard-coded password (against best practices - hashed for 'security', lol)
password_plaintext = "SecurePass123"
hashed_password = bcrypt.hashpw(password_plaintext.encode(), bcrypt.gensalt())

# Employee data storage (simulated database)
employee_data = {}

def save_data():
    """ Save employee data to a JSON file """
    try:
        with open("/var/library_management/employees.json", "w") as file:
            json.dump(employee_data, file)
        logging.info("Employee data successfully updated.")
    except Exception as e:
        print(f"\nAn error has occurred: {e}")
        logging.error(f"Error during saving operation: {e}")

def load_data():
    """ Load employee data from a JSON file """
    global employee_data
    try:
        with open("/var/library_management/employees.json", "r") as file:
            employee_data = json.load(file)
        logging.info("Employee data loaded from JSON file.")
    except FileNotFoundError:
        employee_data = {}
    except Exception as e:
        print(f"\nAn error has occurred: {e}")
        logging.error(f"Error during saving operation: {e}")

def check_password():
    """ Ask user for password and validate it """
    attempts = 3 # Only allow 3 attempts for password entry
    while attempts > 0:
        user_password = input("\nEnter the password: ").encode()

        if bcrypt.checkpw(user_password, hashed_password):
            logging.info("Password authenticated successfully.")
            return True
        else:
            print(f"\nIncorrect password! {attempts-1} attempts remaining")
            attempts -= 1
    print("\nYou have exceeded the number of password attempts.")
    return False

def sanitize_input(user_input, is_phone=False):
    """ Sanitize user input (and only document proper names. If it's a phone number, allow only digits """
    if is_phone:
        return re.sub(r'[^0-9]', '', user_input) # Remove anything that is not a digit.
    else:
        return re.sub(r'[^a-zA-Z ]', '', user_input) # Only letters and spaces allowed.

def validate_phone_number(phone_number):
    """ Validate phone number to ensure it's exactly 10 digits """
    if len(phone_number) == 10 and phone_number.isdigit():
        return True
    return False

def add_employee():
    """ Add a new employee """
    print("\nThis functionality is reserved for authorized and privileged users.")

    if check_password():
        name = input("\nEnter employee name: ")

        # Sanitize and validate employee name (only alphanumeric characters and spaces)
        sanitized_name = sanitize_input(name)
        if not sanitized_name:
            print("\nInvalid name. Name should only contain alphabetic characters and spaces.")
            return

        # Allow for 3 attempts for phone number input
        attempts = 3
        while attempts > 0:
            phone = input("\nEnter 10-digit employee phone number: ")

            # Sanitize phone number input
            sanitized_phone = sanitize_input(phone, is_phone=True)

            # Validate phone number
            if validate_phone_number(sanitized_phone):
                # Add sanitized and validated data to the employee_data
                employee_data[sanitized_name] = sanitized_phone
                save_data()

                print("\nEmployee added successfully!")
                logging.info(f"Employee {sanitized_name} and with number {sanitized_phone} was added.")
                return
            else:
                attempts -= 1
                print(f"\nInvalid phone number. It must be exactly 10-digits. You have {attempts} attempts remaining.")
        # If all attempts are exhausted, exit the function
        print("\nYou have exceeded the number of attempts to enter a valid phone number.")

def view_employees():
    """ View all employee data (requires password) """
    if not employee_data: # Checks first if there are any employees
        print("\nNo employee records found.")
        logging.info("Attempted to view employees but no records exist.")
        return # Exit early

    if check_password():
        # This will print out the employees in alphabetical order
        for name, phone in sorted(employee_data.items()):
            print(f"\n{name}: {phone}")
        logging.info("Employee records viewed successfully.")
    else:
        print("\nAccess denied.")
        logging.warning("Failed attempt to view employees (incorrect password).")

def create_group():
    group_name = 'librarians'
    try:
        # Check if the group exists
        subprocess.run(['getent', 'group', group_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print(f"Group '{group_name}' doesn't exist, creating it now...")
        subprocess.run(['sudo', 'groupadd', group_name])

def add_user_to_group(user_name):
    group_name = 'librarians'
    try:
        # Add the user to the 'librarians' group
        subprocess.run(['sudo', 'usermod', '-aG', group_name, user_name], check=True)
        print(f"User '{user_name} added to group '{group_name}'.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add user '{user_name} to group '{group_name}': {e}")

def set_log_permissions():
    log_file = '/var/library_managemenet/library.log'
    employee_data = '/var/library_management/employees.json'
    books_list = '/var/library_management/books.txt'

    try:
        # Change the group ownership of the files to 'librarians'
        subprocess.run(['sudo', 'chown', ':librarians', log_file], check=True)
        subprocess.run(['sudo', 'chown', ':librarians', employee_data], check=True)
        subprocess.run(['sudo', 'chown', ':librarians', books_list], check=True)

        # Set permissions so only the owner and group can read/write (660), others have no access
        subprocess.run(['sudo', 'chmod', '660', log_file], check=True)
        subprocess.run(['sudo', 'chmod', '660', employee_data], check=True)
        subprocess.run(['sudo', 'chmod', '660', books_list], check=True)

        print(f"Permissions for '{log_file}' set to 660 (owner and group read/write).")
    except subprocess.CalledProcessError as e:
        print(f"Failed to set permissions for '{log_file}': {e}")

def setup_logging():
    create_group() # Ensure 'librarians' group exists
    current_user = os.getlogin() # Get the current logged-in user
    add_user_to_group(current_user) # Add the current user to the 'librarians' group
    set_log_permissions() # Set the correct permissions for the log file

def clear_screen():
    os.system('clear')  # On Linux/MacOS

def view_books():
    try:
        with open("/var/library_management/books.txt", "r") as file:
            books = file.readlines()

            if not books:  # If the file is empty
                print("\nNo books available!")
                logging.info("No books available to view.")
                return

            # Remove duplicates using set, then sort the books
            books = list(set(books))
            books.sort()

            print("\nHere are the available books: ")
            for i, book in enumerate(books, 1):  # Enumerating for numbering
                print(f"{i}. {book.strip()}")  # Clean up newlines
            logging.info("Books listed successfully.")
    except FileNotFoundError:
        print("\nThe library is empty! Add some books first.")
        logging.error("books.txt file not found. Library is empty.")

def sanitize_book_title(title):
    # Replace non-alphanumeric characters with underscores
    sanitized_title = re.sub(r'[^a-zA-Z0-9_]', '_', title)
    
    # Replace consecutive underscores with a single underscore
    sanitized_title = re.sub(r'_+', '_', sanitized_title)
    
    # Remove leading and trailing underscores (if any)
    sanitized_title = sanitized_title.strip('_')
    
    return sanitized_title

def add_book():
    new_book = input("Enter the title of the book to add: ")

    # Sanitize the book title to remove special characters
    sanitized_book = sanitize_book_title(new_book)

    try:
        # Read the existing books from the file to check for duplicates
        with open("/var/library_management/books.txt", "r") as file:
            books = file.readlines()

        # Check if the sanitized book already exists in the list
        if sanitized_book + "\n" in books:
            print(f"\n'{sanitized_book}' is already in the library.")
            logging.info(f"Attempted to add '{sanitized_book}', but it already exists.")
            return

        # Open the books.txt file in append mode to add the new sanitized book
        with open("/var/library_management/books.txt", "a") as file:
            file.write(sanitized_book + "\n")

        # Create a new file for the sanitized book title
        filename = f"/var/library_management/books/{sanitized_book}.txt"
        with open(filename, "w") as book_file:
            book_file.write(f"This is the content of the book: {sanitized_book}\n")  # You can customize this

        # Confirm the new book was added
        print(f"\n'{sanitized_book}' has been added to the library.")
        logging.info(f"Book '{sanitized_book}' added successfully to books.txt and created a new file.")
    except Exception as e:
        print(f"\nAn error has occurred while adding the book: {e}")
        logging.error(f"Error adding book '{sanitized_book}': {e}")

def delete_book():
    try:
        # Reading the file and displaying books to the user
        with open("/var/library_management/books.txt", "r") as file:
            books = file.readlines()

        if not books:  # If the file is empty
            print("\nNo books available to delete!")
            logging.info("No books available to delete.")
            return

        # Remove the duplicates using set, then sort the books
        books = list(set(books))
        books.sort()

        # Show the list of books to the user
        print("\nHere are the available books:")
        for i, book in enumerate(books, 1):
            print(f"{i}. {book.strip()}")

        # Ask the user to select the book to delete
        book_to_delete = int(input("\nEnter the number of the book to delete: ")) - 1

        # Check if the input is valid
        if book_to_delete < 0 or book_to_delete >= len(books):
            print("\nInvalid book number!")
            logging.warning("Invalid book number entered during delete operation.")
            return

        # Remove the selected book from the list
        del books[book_to_delete]

        # Rewrite the books back to the file without the deleted book
        with open("/var/library_management/books.txt", "w") as file:
            file.writelines(books)

        print("\nThe book has been deleted successfully.")
        logging.info("Book deleted successfully from books.txt.")
    except FileNotFoundError:
        print("\nThe library is empty! Add some books first.")
        logging.error("books.txt file not found during delete operation.")
    except Exception as e:
        print(f"\nAn error occurred while deleting the book: {e}")
        logging.error(f"Error during book deletion: {e}")

def open_book():
    try:
        with open("/var/library_management/books.txt", "r") as file:
            books = file.readlines()

        if not books:
            print("\nNo books available to open!")
            logging.info("No books available to open.")
            return

        # Show the list of available books
        print("\nHere are the available books: ")
        for i, book in enumerate(books, 1):
            print(f"{i}. {book.strip()}")

        # Ask the user to select a book to open
        book_to_open = int(input("\nEnter the number of the book to open: "))

        # Check if the input is valid
        if book_to_open < 1 or book_to_open > len(books):
            print("\nInvalid book number!")
            logging.warning("Invalid book number entered during open operation.")
            return

        # Get the book title and create a filename (assuming each book has its own file)
        book_title = books[book_to_open - 1].strip()  # Convert to a 0-based index
        filename = f"/var/library_management/books/{book_title}.txt"

        # Attempt to open and read the book
        try:
            with open(filename, "r") as book_file:
                print(f"\nReading '{book_title}':\n")
                print(book_file.read())  # Display the contents of the book
            logging.info(f"Book '{book_title}' opened successfully.")
        except FileNotFoundError:
            print(f"\nThe book '{book_title}' does not exist. Please make sure it was added properly.")
            logging.error(f"File for book '{book_title}' not found.")
        except Exception as e:
            print(f"\nAn error occurred while opening the book: {e}")
            logging.error(f"Error during book open operation for '{book_title}': {e}")
    except FileNotFoundError:
        print("\nThe library is empty! Add some books first.")
        logging.error("books.txt file not found during open operation.")
    except Exception as e:
        print(f"\nAn error has occurred: {e}")
        logging.error(f"Error during open operation: {e}")

def menu():
    
    load_data()    # Load employee data from JSON file.
    clear_screen()  # Clear screen before the menu displays.

    while True:
        print("="*40)
        print("\nLibrary Management System")
        print("="*40)
        print("1. View Books")
        print("2. Add a Book")
        print("3. Delete a Book")
        print("4. Open a Book")
        print("5. Add an employee")
        print("6. View employees")
        print("7. Exit")
        print("="*40)

        try:
            choice = int(input("Enter your choice: "))
        except ValueError:
            print("\nInvalid Input! Please enter a number.")
            logging.warning("Invalid input entered during menu selection.")
            continue

        match choice:
            case 1:
                view_books()
            case 2:
                add_book()
            case 3:
                delete_book()
            case 4:
                open_book()
            case 5:
                add_employee()
            case 6:
                view_employees()
            case 7:
                print("\nGoodbye! ")
                logging.info("User exited the program.")
                return  # Exit the program gracefully.
            # Error handling
            case _:
                print("\nInvalid option! Please try again.")
                logging.warning("Invalid option selected in menu.")

# Call the setup function to configure the permissions before logging
setup_logging() 

# Present the menu to the user
if __name__ == "__main__":
    menu()
